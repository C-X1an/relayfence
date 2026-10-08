package relayfence

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// This fixture uses authenticated TLS over owned TCP sockets. A stalled peer
// fills the kernel send queue using actual encrypted application writes.
// No fake connection, artificial blocking Write, or net.Pipe is involved.
func TestTLSCloseStalledReader(t *testing.T) {
	pki, err := newLabPKI()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan *tls.Conn, 1)
	go func() {
		conn, err := listener.AcceptTCP()
		if err != nil {
			return
		}
		_ = conn.SetWriteBuffer(1024)
		server := tls.Server(conn, TLSConfig(pki.server, pki.pool))
		if server.Handshake() != nil {
			conn.Close()
			return
		}
		accepted <- server
	}()
	conn, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	client := tls.Client(conn, &tls.Config{RootCAs: pki.pool, ServerName: "proxy.test", Certificates: []tls.Certificate{pki.client}, MinVersion: tls.VersionTLS13})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	var server *tls.Conn
	select {
	case server = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("mTLS handshake did not finish")
	}
	defer server.NetConn().Close()
	store := mustStore(t, labPolicy("echo.test:443"))
	session, err := store.Reserve(context.Background(), labIdentity, "echo.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Release()
	if err := store.Attach(session, server); err != nil {
		t.Fatal(err)
	}
	// A timed-out application Write fills the actual TCP queue. close_notify
	// still writes an alert after an application write error and extends the
	// deadline. This specifically exercises TLS's sticky-error behavior.
	if err := server.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	n, err := server.Write(make([]byte, 256<<10))
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n == 0 {
		t.Fatalf("send queue did not saturate: bytes=%d error=%v", n, err)
	}
	if err := server.NetConn().SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	closedWrite := make(chan error, 1)
	go func() { closedWrite <- server.CloseWrite() }()
	select {
	case err := <-closedWrite:
		t.Fatalf("fixture did not stall TLS close notification: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	started := time.Now()
	closed := make(chan struct{})
	go func() { session.Close(); close(closed) }()
	select {
	case <-closed:
		t.Logf("terminal close completed in %s", time.Since(started))
	case <-time.After(time.Second):
		server.NetConn().Close()
		<-closed
		t.Fatal("TLS terminal close exceeded one-second shutdown bound")
	}
	select {
	case <-closedWrite:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("half-close writer was not joined")
	}
	session.Release()
	if store.Status().Active != 0 {
		t.Fatal("reservation not released after transport finalization")
	}
}

// The gateway control uses genuine CONNECT/relay/audit/release code with owned
// TCP/mTLS sockets. A fixture application Write with a short deadline establishes
// the saturated queue before real upstream EOF enters the gateway's CloseWrite.
// It controls scheduling on the hijacked TLS socket rather than raw TCP framing.
func TestGatewayTLSCloseStalledReader(t *testing.T) {
	for _, mode := range []string{"shutdown", "revoke", "idle", "lifetime"} {
		t.Run(mode, func(t *testing.T) {
			finishUpstream := make(chan struct{})
			upstreamEOF := make(chan struct{})
			var once sync.Once
			f := newFixture(t, func(c net.Conn) {
				_, _ = c.Write([]byte("!"))
				<-finishUpstream
				_ = c.(*net.TCPConn).CloseWrite()
				close(upstreamEOF)
				_, _ = io.Copy(io.Discard, c)
			}, func(p *Policy, _ *Gateway) {
				p.Rules[0].IdleTimeoutMS = 3000
				p.Rules[0].MaxDurationMS = 4000
				if mode == "idle" {
					p.Rules[0].IdleTimeoutMS = 500
				}
				if mode == "lifetime" {
					p.Rules[0].MaxDurationMS = 500
					p.Rules[0].IdleTimeoutMS = 500
				}
			})
			t.Cleanup(func() { once.Do(func() { close(finishUpstream) }) })
			client, reader := connectOK(t, f)
			// Receipt through the pump establishes that gateway deadline setup is
			// complete before this control installs its short write deadline.
			if b, err := reader.ReadByte(); err != nil || b != '!' {
				t.Fatalf("relay readiness byte=%q error=%v", b, err)
			}
			if err := client.NetConn().(*net.TCPConn).SetReadBuffer(1024); err != nil {
				t.Fatal(err)
			}
			store := f.gateway.Store
			store.mu.Lock()
			var session *Session
			for _, candidate := range store.active {
				session = candidate
			}
			store.mu.Unlock()
			if session == nil {
				t.Fatal("CONNECT has no reservation")
			}
			session.mu.Lock()
			var secured *tls.Conn
			for _, connection := range session.connections {
				if candidate, ok := connection.(*tls.Conn); ok {
					secured = candidate
				}
			}
			session.mu.Unlock()
			if secured == nil {
				t.Fatal("hijacked TLS socket not attached")
			}
			transport := secured.NetConn().(*net.TCPConn)
			if err := transport.SetWriteBuffer(1024); err != nil {
				t.Fatal(err)
			}
			if err := transport.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			n, err := secured.Write(make([]byte, 256<<10))
			if ne, ok := err.(net.Error); !ok || !ne.Timeout() || n == 0 {
				t.Fatalf("send queue did not saturate: bytes=%d error=%v", n, err)
			}
			if err := transport.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			once.Do(func() { close(finishUpstream) })
			<-upstreamEOF
			time.Sleep(50 * time.Millisecond)
			started := time.Now()
			terminal := make(chan error, 1)
			go func() {
				if mode == "shutdown" {
					store.Close()
					terminal <- nil
				} else if mode == "revoke" {
					next := labPolicy(f.destination)
					next.Revision = 2
					next.Rules = nil
					terminal <- store.Replace(1, next)
				} else {
					<-session.Context.Done()
					terminal <- nil
				}
			}()
			bound := time.Second
			if mode == "idle" || mode == "lifetime" {
				bound = 850 * time.Millisecond
			}
			defer transport.Close()
			select {
			case err := <-terminal:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(bound):
				transport.Close()
				<-terminal
				t.Fatal("gateway TLS terminal close exceeded bound")
			}
			deadline := started.Add(bound)
			for store.Status().Active != 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if store.Status().Active != 0 {
				t.Fatal("gateway TLS handler reservation exceeded close bound")
			}
			audit := f.gateway.Audit.(*memoryAudit)
			audit.mu.Lock()
			closed := 0
			for _, event := range audit.rows {
				if event.Kind == "closed" {
					closed++
				}
			}
			audit.mu.Unlock()
			if closed != 1 {
				t.Fatalf("closed audit events=%d want1 before reservation release", closed)
			}
			t.Logf("%s transport and complete handler finalized in %s", mode, time.Since(started))
		})
	}
}

// This control sends the payload exclusively through the actual upstream socket
// and gateway pump. A deliberately short real socket write deadline makes the
// blocked application's error precede terminal cancellation deterministically.
func TestGatewayTLSCloseBlockedApplicationWrite(t *testing.T) {
	startPayload := make(chan struct{})
	var once sync.Once
	f := newFixture(t, func(c net.Conn) {
		_, _ = c.Write([]byte("!"))
		<-startPayload
		_, _ = c.Write(make([]byte, 256<<10))
		_ = c.(*net.TCPConn).CloseWrite()
		_, _ = io.Copy(io.Discard, c)
	}, nil)
	t.Cleanup(func() { once.Do(func() { close(startPayload) }) })
	client, reader := connectOK(t, f)
	if b, err := reader.ReadByte(); err != nil || b != '!' {
		t.Fatalf("relay readiness byte=%q error=%v", b, err)
	}
	if err := client.NetConn().(*net.TCPConn).SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	store := f.gateway.Store
	store.mu.Lock()
	var session *Session
	for _, candidate := range store.active {
		session = candidate
	}
	store.mu.Unlock()
	if session == nil {
		t.Fatal("CONNECT has no reservation")
	}
	session.mu.Lock()
	var secured *tls.Conn
	for _, connection := range session.connections {
		if candidate, ok := connection.(*tls.Conn); ok {
			secured = candidate
		}
	}
	session.mu.Unlock()
	if secured == nil {
		t.Fatal("hijacked TLS socket not attached")
	}
	transport := secured.NetConn().(*net.TCPConn)
	defer transport.Close()
	if err := transport.SetWriteBuffer(1024); err != nil {
		t.Fatal(err)
	}
	if err := secured.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	once.Do(func() { close(startPayload) })
	for store.Status().Active != 0 && time.Since(started) < time.Second {
		time.Sleep(time.Millisecond)
	}
	if store.Status().Active != 0 {
		t.Fatal("gateway blocked TLS application write exceeded terminal handler bound")
	}
	audit := f.gateway.Audit.(*memoryAudit)
	audit.mu.Lock()
	defer audit.mu.Unlock()
	var closed Event
	for _, event := range audit.rows {
		if event.Kind == "closed" {
			closed = event
		}
	}
	if closed.Bytes <= 1 || closed.Reason != "io_error" {
		t.Fatalf("expected actual forwarded payload followed by write error: %+v", closed)
	}
	t.Logf("upstream TCP -> TLS pump forwarded %d bytes and finalized in %s", closed.Bytes, time.Since(started))
}
