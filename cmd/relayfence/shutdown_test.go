package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rf "github.com/C-X1an/relayfence/internal/relayfence"
)

const shutdownIdentity = "urn:relayfence:workload:shutdown"

type shutdownResolver struct{ calls atomic.Int32 }

func (r *shutdownResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" || host != "owned.test" {
		return nil, fmt.Errorf("unexpected resolution %s %s", network, host)
	}
	r.calls.Add(1)
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

// This labelled transport fixture maps the validated public literal to an
// owned loopback TCP listener. It exercises real mTLS/relay/shutdown, not public
// routing, external DNS, or an unsafe daemon configuration flag.
type shutdownDialer struct {
	target string
	calls  atomic.Int32
}

func (d *shutdownDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != "8.8.8.8:443" {
		return nil, fmt.Errorf("nonliteral or unexpected dial %s %s", network, address)
	}
	d.calls.Add(1)
	return (&net.Dialer{}).DialContext(ctx, "tcp", d.target)
}

type shutdownAudit struct {
	file    *rf.FileAudit
	kind    string
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	failure error
}

func (a *shutdownAudit) Record(event rf.Event) error {
	if event.Kind == a.kind {
		a.once.Do(func() { close(a.entered) })
		<-a.release
		if a.failure != nil {
			return a.failure
		}
	}
	return a.file.Record(event)
}

func shutdownPKI(t *testing.T) (tls.Certificate, *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral shutdown fixture CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	leaf := func(client bool) tls.Certificate {
		leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		if client {
			tpl.SerialNumber = big.NewInt(3)
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			identity, e := url.Parse(shutdownIdentity)
			if e != nil {
				t.Fatal(e)
			}
			tpl.URIs = []*url.URL{identity}
		} else {
			tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tpl.DNSNames = []string{"proxy.test"}
		}
		certDER, e := x509.CreateCertificate(rand.Reader, tpl, ca, &leafKey.PublicKey, key)
		if e != nil {
			t.Fatal(e)
		}
		return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: leafKey}
	}
	return leaf(false), &tls.Config{RootCAs: pool, ClientCAs: pool, Certificates: []tls.Certificate{leaf(true)}, ServerName: "proxy.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
}

type shutdownFixture struct {
	store        *rf.Store
	audit        *shutdownAudit
	path         string
	listener     net.Listener
	clientConfig *tls.Config
	resolver     *shutdownResolver
	dialer       *shutdownDialer
	cancel       context.CancelFunc
	result       chan error
	closed       atomic.Bool
	upDone       chan struct{}
}

func newShutdownFixture(t *testing.T, kind string, auditFailure, adminFailure, closeFailure error) *shutdownFixture {
	t.Helper()
	f := &shutdownFixture{result: make(chan error, 1), upDone: make(chan struct{})}
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = up.Close() })
	go func() {
		defer close(f.upDone)
		c, e := up.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c)
	}()
	f.store, err = rf.NewStore(rf.Policy{SchemaVersion: 1, Revision: 1, GlobalMaxActive: 2, Rules: []rf.Rule{{Identity: shutdownIdentity, Destinations: []string{"owned.test:443"}, MaxActive: 2, MaxBytes: 65536, MaxDurationMS: 10000, IdleTimeoutMS: 5000}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	f.path = filepath.Join(t.TempDir(), "audit.jsonl")
	file, err := rf.OpenAudit(f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.audit = &shutdownAudit{file: file, kind: kind, entered: make(chan struct{}), release: make(chan struct{}), failure: auditFailure}
	tracked := &daemonAudit{Audit: f.audit}
	gateway, err := rf.NewGateway(f.store, tracked)
	if err != nil {
		t.Fatal(err)
	}
	f.resolver = &shutdownResolver{}
	f.dialer = &shutdownDialer{target: up.Addr().String()}
	gateway.Resolver, gateway.Dialer = f.resolver, f.dialer
	cert, clientConfig := shutdownPKI(t)
	f.clientConfig = clientConfig
	f.listener, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := rf.HTTPServer(gateway, rf.TLSConfig(cert, clientConfig.RootCAs))
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	go func() {
		f.result <- serveDaemon(ctx, tls.NewListener(f.listener, server.TLSConfig), server, f.store, tracked, func() error {
			f.closed.Store(true)
			return errors.Join(file.Close(), closeFailure)
		}, func(context.Context) error { return adminFailure })
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-f.audit.release:
		default:
			close(f.audit.release)
		}
		f.store.Close()
		_ = f.listener.Close()
		_ = up.Close()
		select {
		case <-f.upDone:
		case <-time.After(time.Second):
			t.Error("upstream fixture did not join")
		}
		_ = file.Close()
	})
	return f
}

func (f *shutdownFixture) request(t *testing.T, method string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	c, err := tls.Dial("tcp", f.listener.Addr().String(), f.clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err = c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = fmt.Fprintf(c, "%s owned.test:443 HTTP/1.1\r\nHost: owned.test:443\r\n\r\n", method); err != nil {
		t.Fatal(err)
	}
	return c, bufio.NewReader(c)
}

func awaitShutdown(t *testing.T, ch <-chan struct{}, label string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("%s not observed within 1s", label)
	}
}

func assertShutdownEcho(t *testing.T, c net.Conn, reader *bufio.Reader) {
	t.Helper()
	// A 200 response precedes deadline installation and relay startup. Actual
	// round-trip bytes establish the live-pump precondition before cancellation.
	if _, err := c.Write([]byte("exact-echo")); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, len("exact-echo"))
	if _, err := io.ReadFull(reader, body); err != nil || string(body) != "exact-echo" {
		t.Fatalf("echo %q %v", body, err)
	}
}

func TestDaemonShutdownJoinsHijackedAuditAndRelease(t *testing.T) {
	for _, trigger := range []string{"context", "listener_error"} {
		t.Run(trigger, func(t *testing.T) {
			f := newShutdownFixture(t, "closed", nil, nil, nil)
			c, reader := f.request(t, "CONNECT")
			response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
			if err != nil || response.StatusCode != 200 {
				t.Fatalf("CONNECT: %v %v", response, err)
			}
			assertShutdownEcho(t, c, reader)
			start := time.Now()
			if trigger == "context" {
				f.cancel()
			} else if err = f.listener.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = reader.ReadByte(); err == nil {
				t.Fatal("peer did not terminate")
			}
			if time.Since(start) > time.Second {
				t.Fatal("peer cancellation exceeded 1s")
			}
			awaitShutdown(t, f.audit.entered, "closed audit barrier")
			if f.store.Status().Active != 1 {
				t.Fatal("session released before closed audit finalization")
			}
			select {
			case err = <-f.result:
				t.Fatalf("daemon returned before handler finalization: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			if f.closed.Load() {
				t.Fatal("audit closed before handler finalization")
			}
			close(f.audit.release)
			select {
			case err = <-f.result:
			case <-time.After(time.Second):
				t.Fatal("daemon did not join")
			}
			if trigger == "context" && err != nil {
				t.Fatal(err)
			}
			if trigger == "listener_error" && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("lost listener error: %v", err)
			}
			if time.Since(start) > time.Second || f.store.Status().Active != 0 || !f.closed.Load() {
				t.Fatalf("incomplete drain: %v %+v closed=%v", time.Since(start), f.store.Status(), f.closed.Load())
			}
			rows, err := rf.ReadAudit(f.path)
			if err != nil || len(rows) != 2 || rows[0].Event.Kind != "allowed" || rows[1].Event.Kind != "closed" || rows[1].Event.Session != rows[0].Event.Session || rows[1].Event.Bytes != 20 {
				t.Fatalf("audit accounting: %+v %v", rows, err)
			}
			if f.resolver.calls.Load() != 1 || f.dialer.calls.Load() != 1 {
				t.Fatal("unexpected resolver/dial count")
			}
		})
	}
}

func TestDaemonShutdownJoinsDeniedHandler(t *testing.T) {
	f := newShutdownFixture(t, "denied", nil, nil, nil)
	_, _ = f.request(t, "GET")
	awaitShutdown(t, f.audit.entered, "denied audit barrier")
	f.cancel()
	select {
	case err := <-f.result:
		t.Fatalf("returned before denied audit finalized: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if f.closed.Load() {
		t.Fatal("audit closed with denied handler still active")
	}
	close(f.audit.release)
	select {
	case err := <-f.result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("denied handler drain timed out")
	}
	rows, err := rf.ReadAudit(f.path)
	if err != nil || len(rows) != 1 || rows[0].Event.Kind != "denied" || f.store.Status().Active != 0 {
		t.Fatalf("denied finalization: %+v %v", rows, err)
	}
	if f.resolver.calls.Load() != 0 || f.dialer.calls.Load() != 0 {
		t.Fatal("denied method reached resolver/upstream")
	}
}

func TestDaemonShutdownPropagatesFinalizationErrors(t *testing.T) {
	auditErr, adminErr, closeErr := errors.New("closed audit fixture failure"), errors.New("admin close fixture failure"), errors.New("audit close fixture failure")
	f := newShutdownFixture(t, "closed", auditErr, adminErr, closeErr)
	c, reader := f.request(t, "CONNECT")
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", response, err)
	}
	assertShutdownEcho(t, c, reader)
	f.cancel()
	awaitShutdown(t, f.audit.entered, "closed audit")
	close(f.audit.release)
	select {
	case err = <-f.result:
	case <-time.After(time.Second):
		t.Fatal("finalization did not finish")
	}
	for _, want := range []error{auditErr, adminErr, closeErr} {
		if !errors.Is(err, want) {
			t.Fatalf("lost %v: %v", want, err)
		}
	}
	if f.store.Status().Active != 0 || !f.closed.Load() {
		t.Fatal("failed audit did not release/close")
	}
}

func TestDaemonShutdownTimeoutReportsUnfinishedHandler(t *testing.T) {
	f := newShutdownFixture(t, "closed", nil, nil, nil)
	c, reader := f.request(t, "CONNECT")
	response, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", response, err)
	}
	assertShutdownEcho(t, c, reader)
	start := time.Now()
	f.cancel()
	awaitShutdown(t, f.audit.entered, "closed audit")
	select {
	case err = <-f.result:
	case <-time.After(1500 * time.Millisecond):
		t.Fatal("shutdown was not bounded")
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "handler finalization") {
		t.Fatalf("timeout hidden: %v", err)
	}
	if time.Since(start) > 1500*time.Millisecond || f.closed.Load() || f.store.Status().Active != 1 {
		t.Fatal("timeout falsely finalized or closed audit")
	}
	close(f.audit.release)
	deadline := time.Now().Add(time.Second)
	for f.store.Status().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if f.store.Status().Active != 0 {
		t.Fatal("late handler failed to release")
	}
	rows, err := rf.ReadAudit(f.path)
	if err != nil || len(rows) != 2 {
		t.Fatalf("late finalization lost audit: %v %v", rows, err)
	}
}
