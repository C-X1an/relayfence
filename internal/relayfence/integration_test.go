package relayfence

import (
	"sync"

	"crypto/tls"
	"errors"
	"testing"

	"net"

	"bufio"
	"net/http"
	"net/netip"
	"time"

	"context"
	"io"

	"fmt"
)

type memoryAudit struct {
	mu   sync.Mutex
	rows []Event
	fail bool
}

func (a *memoryAudit) Record(e Event) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return errors.New("injected audit failure")
	}
	a.rows = append(a.rows, e)
	return nil
}

type dialerFunc func(context.Context, string, string) (net.Conn, error)

func (f dialerFunc) DialContext(c context.Context, n, a string) (net.Conn, error) { return f(c, n, a) }

type fixture struct {
	pki         *labPKI
	gateway     *Gateway
	server      *labServer
	destination string
	upstream    net.Listener
}

func newFixture(t *testing.T, handler func(net.Conn), configure func(*Policy, *Gateway)) *fixture {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				handler(c)
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	destination := "echo.test:" + port
	p := labPolicy(destination)
	placeholder := &Gateway{}
	if configure != nil {
		configure(&p, placeholder)
	}
	store := mustStore(t, p)
	gateway, e := NewGateway(store, &memoryAudit{})
	if e != nil {
		t.Fatal(e)
	}
	gateway.labLoopback = true
	gateway.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	if configure != nil {
		configure(&p, gateway)
	}
	pki, e := newLabPKI()
	if e != nil {
		t.Fatal(e)
	}
	server, e := startLabGateway(gateway, pki)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { server.close(); listener.Close(); <-acceptDone; wg.Wait() })
	return &fixture{pki, gateway, server, destination, listener}
}
func echo(c net.Conn) { _, _ = io.Copy(c, c) }
func connectOK(t *testing.T, f *fixture) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	c, r, status, e := labConnect(f.server.address, f.destination, f.pki, &f.pki.client)
	if e != nil {
		t.Fatal(e)
	}
	if status != 200 {
		c.Close()
		t.Fatalf("CONNECT: %d", status)
	}
	t.Cleanup(func() { c.Close() })
	return c, r
}
func waitEmpty(t *testing.T, s *Store) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for s.Status().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if s.Status().Active != 0 {
		t.Fatal("active session leaked")
	}
}

func rawQueuedConnect(f *fixture, payload string) (*tls.Conn, *bufio.Reader, int, error) {
	config := &tls.Config{RootCAs: f.pki.pool, ServerName: "proxy.test", Certificates: []tls.Certificate{f.pki.client}, MinVersion: tls.VersionTLS13}
	c, e := tls.Dial("tcp", f.server.address, config)
	if e != nil {
		return nil, nil, 0, e
	}
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n%s", f.destination, f.destination, payload)
	if e != nil {
		c.Close()
		return nil, nil, 0, e
	}
	r := bufio.NewReader(c)
	response, e := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
	if e != nil {
		c.Close()
		return nil, nil, 0, e
	}
	return c, r, response.StatusCode, nil
}

type shortWriteConn struct{ net.Conn }

func (c shortWriteConn) Write(b []byte) (int, error) {
	if len(b) > 3 {
		b = b[:3]
	}
	return c.Conn.Write(b)
}
func (c shortWriteConn) CloseWrite() error { return c.Conn.(*net.TCPConn).CloseWrite() }
