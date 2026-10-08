package relayfence

// This file contains the offline synthetic laboratory only. It exposes no
// production flag that disables address validation or certificate verification.
import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const labIdentity = "urn:relayfence:workload:demo"

type labPKI struct {
	ca             *x509.Certificate
	key            *ecdsa.PrivateKey
	pool           *x509.CertPool
	server, client tls.Certificate
}

func newLabPKI() (*labPKI, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "RelayFence ephemeral laboratory CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	p := &labPKI{ca: ca, key: key, pool: x509.NewCertPool()}
	p.pool.AddCert(ca)
	p.server, err = p.leaf(false, nil)
	if err != nil {
		return nil, err
	}
	p.client, err = p.leaf(true, []string{labIdentity})
	return p, err
}
func (p *labPKI) leaf(client bool, identities []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{SerialNumber: serial, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	if client {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		for _, value := range identities {
			u, err := url.Parse(value)
			if err != nil {
				return tls.Certificate{}, err
			}
			tpl.URIs = append(tpl.URIs, u)
		}
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.DNSNames = []string{"proxy.test"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, p.ca, &key.PublicKey, p.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}
func labPolicy(destination string) Policy {
	return Policy{SchemaVersion: 1, Revision: 1, GlobalMaxActive: 8, Rules: []Rule{{Identity: labIdentity, Destinations: []string{destination}, MaxActive: 4, MaxBytes: 1 << 20, MaxDurationMS: 5000, IdleTimeoutMS: 2000}}}
}

type labServer struct {
	address  string
	server   *http.Server
	listener net.Listener
	store    *Store
	done     chan error
}

func startLabGateway(g *Gateway, p *labPKI) (*labServer, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := HTTPServer(g, TLSConfig(p.server, p.pool))
	out := &labServer{listener.Addr().String(), server, listener, g.Store, make(chan error, 1)}
	go func() { out.done <- server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	return out, nil
}
func (l *labServer) close() {
	l.store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := l.server.Shutdown(ctx); err != nil {
		_ = l.server.Close()
	}
	<-l.done
}
func labConnect(address, destination string, p *labPKI, cert *tls.Certificate) (*tls.Conn, *bufio.Reader, int, error) {
	config := &tls.Config{RootCAs: p.pool, ServerName: "proxy.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	if cert != nil {
		config.Certificates = []tls.Certificate{*cert}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	connection, err := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: config}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, 0, err
	}
	client := connection.(*tls.Conn)
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", destination, destination); err != nil {
		client.Close()
		return nil, nil, 0, err
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		client.Close()
		return nil, nil, 0, err
	}
	// The CONNECT body is the raw tunnel; the reader must be retained.
	return client, reader, response.StatusCode, nil
}

// Demo performs real local TLS and TCP I/O. DNS is a labelled deterministic fixture.
func Demo(out string) (err error) {
	if err = os.MkdirAll(out, 0700); err != nil {
		return err
	}
	auditPath := filepath.Join(out, "audit.jsonl")
	if _, statErr := os.Stat(auditPath); !os.IsNotExist(statErr) {
		return errors.New("demo output must be fresh; audit.jsonl already exists")
	}
	audit, err := OpenAudit(auditPath)
	if err != nil {
		return err
	}
	defer audit.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	var connections sync.WaitGroup
	defer connections.Wait()
	stop := make(chan struct{})
	go func() {
		defer close(stop)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	defer func() { listener.Close(); <-stop }()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	destination := "echo.test:" + port
	policy := labPolicy(destination)
	store, err := NewStore(policy, "")
	if err != nil {
		return err
	}
	gateway, _ := NewGateway(store, audit)
	gateway.labLoopback = true
	gateway.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	pki, err := newLabPKI()
	if err != nil {
		return err
	}
	server, err := startLabGateway(gateway, pki)
	if err != nil {
		return err
	}
	defer server.close()
	client, reader, status, err := labConnect(server.address, destination, pki, &pki.client)
	if err != nil {
		return err
	}
	defer client.Close()
	if status != 200 {
		return fmt.Errorf("allowed CONNECT returned %d", status)
	}
	payload := []byte("relayfence-real-tls-echo\n")
	if _, err = client.Write(payload); err != nil {
		return err
	}
	actual := make([]byte, len(payload))
	if _, err = io.ReadFull(reader, actual); err != nil {
		return err
	}
	if string(actual) != string(payload) {
		return errors.New("echo payload mismatch")
	}
	denied, _, status, err := labConnect(server.address, "denied.test:443", pki, &pki.client)
	if err != nil {
		return err
	}
	denied.Close()
	if status != 403 {
		return fmt.Errorf("denied CONNECT returned %d", status)
	}
	policy.Revision = 2
	policy.Rules = nil
	start := time.Now()
	if err = store.Replace(1, policy); err != nil {
		return err
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, err = reader.ReadByte()
	if err == nil {
		return errors.New("revoked tunnel remained readable")
	}
	elapsed := time.Since(start)
	if e, ok := err.(net.Error); ok && e.Timeout() {
		return errors.New("revoked tunnel did not close before timeout")
	}
	deadline := time.Now().Add(time.Second)
	for store.Status().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if store.Status().Active != 0 {
		return errors.New("session leak after revocation")
	}
	if err = audit.Close(); err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(out, "inspection.html"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = InspectAudit(auditPath, file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	report := map[string]any{"status": "PASS", "kind": "synthetic loopback laboratory", "transport": "real TLS1.3 mTLS plus TCP", "dns": "deterministic loopback fixture; not production DNS or containment evidence", "allowed_echo": true, "denied_authority": true, "revoked_tunnel": true, "revocation_observed_ns": elapsed.Nanoseconds(), "real_users": 0}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "report.json"), append(data, '\n'), 0600)
}
