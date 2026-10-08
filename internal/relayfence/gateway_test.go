package relayfence

import (
	"bufio"
	"sync/atomic"

	"context"
	"io"

	"fmt"

	"sync"

	"bytes"
	"crypto/tls"
	"testing"

	"errors"

	"net"

	"net/http"
	"net/netip"
	"time"
)

func TestAcceptanceMTLS(t *testing.T) {
	f := newFixture(t, echo, nil)
	c, r := connectOK(t, f)
	if _, e := c.Write([]byte("hello")); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 5)
	if _, e := io.ReadFull(r, b); e != nil || string(b) != "hello" {
		t.Fatalf("real echo: %q %v", b, e)
	}
	c.Close()
	for _, kind := range []string{"missing", "wrong_ca", "ambiguous", "no_uri", "unknown_identity"} {
		t.Run(kind, func(t *testing.T) {
			var cert *tls.Certificate
			switch kind {
			case "wrong_ca":
				other, e := newLabPKI()
				if e != nil {
					t.Fatal(e)
				}
				cert = &other.client
			case "ambiguous":
				v, e := f.pki.leaf(true, []string{labIdentity, "urn:relayfence:workload:other"})
				if e != nil {
					t.Fatal(e)
				}
				cert = &v
			case "no_uri":
				v, e := f.pki.leaf(true, nil)
				if e != nil {
					t.Fatal(e)
				}
				cert = &v
			case "unknown_identity":
				v, e := f.pki.leaf(true, []string{"urn:relayfence:workload:other"})
				if e != nil {
					t.Fatal(e)
				}
				cert = &v
			}
			conn, _, status, e := labConnect(f.server.address, f.destination, f.pki, cert)
			if conn != nil {
				conn.Close()
			}
			if e == nil && status != 403 {
				t.Fatalf("unauthorized TLS accepted: status=%d err=%v", status, e)
			}
		})
	}

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.pki.pool, ServerName: "proxy.test", Certificates: []tls.Certificate{f.pki.client}, MinVersion: tls.VersionTLS13}}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	response, e := client.Get("https://" + f.server.address + "/v1/status")
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	if response.StatusCode != 405 {
		t.Fatalf("network admin/GET exposed: %d", response.StatusCode)
	}
}
func TestAuthorizeBeforeDNS(t *testing.T) {
	var calls atomic.Int64
	f := newFixture(t, echo, func(_ *Policy, g *Gateway) {
		g.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			calls.Add(1)
			return nil, errors.New("must not resolve")
		})
	})
	c, _, status, e := labConnect(f.server.address, "denied.test:443", f.pki, &f.pki.client)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if status != 403 || calls.Load() != 0 {
		t.Fatalf("status=%d DNS=%d", status, calls.Load())
	}
}
func TestDNSPinning(t *testing.T) {
	var calls atomic.Int64
	dialed := make(chan string, 1)
	f := newFixture(t, echo, func(_ *Policy, g *Gateway) {
		g.labLoopback = false
		g.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
			calls.Add(1)
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		})
		g.Dialer = dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			dialed <- address
			a, b := net.Pipe()
			go func() { defer b.Close(); <-ctx.Done() }()
			return a, nil
		})
	})
	c, _, status, e := labConnect(f.server.address, f.destination, f.pki, &f.pki.client)
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if status != 200 {
		t.Fatalf("%d", status)
	}
	_, port, _ := net.SplitHostPort(f.destination)
	if got := <-dialed; got != "8.8.8.8:"+port || calls.Load() != 1 {
		t.Fatalf("dial=%q lookups=%d", got, calls.Load())
	}
}

func TestRevokePending(t *testing.T) {
	for _, stage := range []string{"dns", "dial"} {
		t.Run(stage, func(t *testing.T) {
			entered := make(chan struct{})
			resume := make(chan struct{})
			var once sync.Once
			var received atomic.Int64
			upDone := make(chan struct{}, 1)
			f := newFixture(t, func(c net.Conn) { n, _ := io.Copy(io.Discard, c); received.Add(n); upDone <- struct{}{} }, func(_ *Policy, g *Gateway) {
				if stage == "dns" {
					g.Resolver = resolverFunc(func(ctx context.Context, _, _ string) ([]netip.Addr, error) {
						once.Do(func() { close(entered) })
						<-resume
						return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
					})
				} else {
					g.Dialer = dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
						once.Do(func() { close(entered) })
						<-resume
						return (&net.Dialer{}).DialContext(context.Background(), network, address)
					})
				}
			})
			done := make(chan int, 1)
			go func() {
				c, _, status, _ := rawQueuedConnect(f, "STALE_PAYLOAD_MUST_NOT_PASS")
				if c != nil {
					c.Close()
				}
				done <- status
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("barrier not reached")
			}
			p := labPolicy(f.destination)
			p.Revision = 2
			p.Rules = nil
			if e := f.gateway.Store.Replace(1, p); e != nil {
				t.Fatal(e)
			}
			close(resume)
			select {
			case status := <-done:
				if status == 200 {
					t.Fatal("revoked pending operation established tunnel")
				}
			case <-time.After(time.Second):
				t.Fatal("pending operation did not finish")
			}
			waitEmpty(t, f.gateway.Store)
			if stage == "dial" {
				select {
				case <-upDone:
				case <-time.After(time.Second):
					t.Fatal("dial fixture did not terminate")
				}
			}
			if received.Load() != 0 {
				t.Fatalf("stale payload forwarded: %d", received.Load())
			}
		})
	}
}
func TestRevokeActive(t *testing.T) {
	f := newFixture(t, echo, nil)
	c, r := connectOK(t, f)
	p := labPolicy(f.destination)
	p.Revision = 2
	p.Rules = nil
	if e := f.gateway.Store.Replace(1, p); e != nil {
		t.Fatal(e)
	}
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, e := r.ReadByte()
	if e == nil {
		t.Fatal("revoked stream still readable")
	}
	if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("revoked stream not terminated")
	}
	waitEmpty(t, f.gateway.Store)
	again, _, status, err := labConnect(f.server.address, f.destination, f.pki, &f.pki.client)
	if again != nil {
		again.Close()
	}
	if err != nil || status != 403 {
		t.Fatalf("revoked identity reconnected: status=%d error=%v", status, err)
	}
}
func TestTimeouts(t *testing.T) {
	for _, mode := range []string{"idle", "lifetime"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t, echo, func(p *Policy, _ *Gateway) {
				p.Rules[0].MaxDurationMS = 200
				p.Rules[0].IdleTimeoutMS = 50
				if mode == "lifetime" {
					p.Rules[0].IdleTimeoutMS = 200
				}
			})
			c, r := connectOK(t, f)
			started := time.Now()
			if mode == "lifetime" {
				for i := 0; i < 5; i++ {
					_, e := c.Write([]byte("x"))
					if e != nil {
						break
					}
					if _, e = r.ReadByte(); e != nil {
						break
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
			_ = c.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
			_, e := r.ReadByte()
			if e == nil {
				t.Fatal("expired stream alive")
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				t.Fatal("gateway did not enforce timeout")
			}
			if time.Since(started) > 800*time.Millisecond {
				t.Fatal("termination beyond tolerance")
			}
			waitEmpty(t, f.gateway.Store)
		})
	}
	t.Run("blocked_write", func(t *testing.T) {
		releasePeer := make(chan struct{})
		f := newFixture(t, func(c net.Conn) {
			if tcp, ok := c.(*net.TCPConn); ok {
				_ = tcp.SetReadBuffer(1024)
			}
			<-releasePeer
		}, func(p *Policy, _ *Gateway) {
			p.Rules[0].MaxBytes = 32 << 20
			p.Rules[0].MaxDurationMS = 200
			p.Rules[0].IdleTimeoutMS = 50
		})
		t.Cleanup(func() { close(releasePeer) })
		c, _ := connectOK(t, f)
		_ = c.SetWriteDeadline(time.Now().Add(time.Second))
		finished := make(chan error, 1)
		started := time.Now()
		go func() { _, err := c.Write(make([]byte, 16<<20)); finished <- err }()
		select {
		case err := <-finished:
			if err == nil {
				t.Fatal("slow peer did not exert expected backpressure")
			}
		case <-time.After(800 * time.Millisecond):
			t.Fatal("blocked writer outlived cancellation tolerance")
		}
		if time.Since(started) > 800*time.Millisecond {
			t.Fatal("blocked writer not cancelled")
		}
		waitEmpty(t, f.gateway.Store)
	})

}
func TestHalfClose(t *testing.T) {
	sawEOF := make(chan struct{})
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	f := newFixture(t, func(c net.Conn) {
		data, e := io.ReadAll(c)
		close(sawEOF)
		<-releaseResponse
		if e == nil {
			_, _ = c.Write(append([]byte("received:"), data...))
		}
	}, nil)
	t.Cleanup(func() { releaseOnce.Do(func() { close(releaseResponse) }) })
	c, r := connectOK(t, f)
	if _, e := c.Write([]byte("request")); e != nil {
		t.Fatal(e)
	}
	if e := c.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-sawEOF:
	case <-time.After(time.Second):
		t.Fatal("upstream did not observe half-close")
	}

	if e := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	_, e := r.ReadByte()
	var timeout net.Error
	if !errors.As(e, &timeout) || !timeout.Timeout() {
		t.Fatalf("connection closed before delayed response: %v", e)
	}
	if e := c.SetReadDeadline(time.Now().Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	releaseOnce.Do(func() { close(releaseResponse) })
	data, e := io.ReadAll(r)
	if e != nil || string(data) != "received:request" {
		t.Fatalf("half-close response %q error %v", data, e)
	}
	waitEmpty(t, f.gateway.Store)
}
func TestAuditFailure(t *testing.T) {
	var bytesSeen atomic.Int64
	f := newFixture(t, func(c net.Conn) { n, _ := io.Copy(io.Discard, c); bytesSeen.Add(n) }, func(_ *Policy, g *Gateway) { g.Audit = &memoryAudit{fail: true} })
	c, _, status, e := rawQueuedConnect(f, "AUDIT_FAILURE_MUST_NOT_FORWARD")
	if e != nil {
		t.Fatal(e)
	}
	c.Close()
	if status != 503 || !f.gateway.Store.Status().Poisoned || bytesSeen.Load() != 0 {
		t.Fatalf("audit did not fail closed: %d %v bytes=%d", status, f.gateway.Store.Status(), bytesSeen.Load())
	}
	waitEmpty(t, f.gateway.Store)
}
func TestRelayBudget(t *testing.T) {
	var received atomic.Int64
	f := newFixture(t, func(c net.Conn) { n, _ := io.Copy(io.Discard, c); received.Add(n) }, func(p *Policy, _ *Gateway) { p.Rules[0].MaxBytes = 257 })
	c, r := connectOK(t, f)
	_, _ = c.Write(bytes.Repeat([]byte("a"), 4096))
	_, _ = io.ReadAll(r)
	waitEmpty(t, f.gateway.Store)
	deadline := time.Now().Add(time.Second)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if received.Load() != 257 {
		t.Fatalf("payload budget: received=%d want257", received.Load())
	}
}
func TestBufferedPayload(t *testing.T) {
	f := newFixture(t, echo, nil)
	config := &tls.Config{RootCAs: f.pki.pool, ServerName: "proxy.test", Certificates: []tls.Certificate{f.pki.client}, MinVersion: tls.VersionTLS13}
	c, e := tls.Dial("tcp", f.server.address, config)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, e = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\ninline", f.destination, f.destination)
	if e != nil {
		t.Fatal(e)
	}
	r := bufio.NewReader(c)
	response, e := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
	if e != nil || response.StatusCode != 200 {
		t.Fatalf("%v %v", response, e)
	}
	b := make([]byte, 6)
	if _, e = io.ReadFull(r, b); e != nil || string(b) != "inline" {
		t.Fatalf("buffered payload lost: %q %v", b, e)
	}
}
func TestShutdown(t *testing.T) {
	f := newFixture(t, echo, nil)
	c, r := connectOK(t, f)
	f.gateway.Store.Close()
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, e := r.ReadByte()
	if e == nil {
		t.Fatal("shutdown did not close tunnel")
	}
	if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("shutdown timed out")
	}
	waitEmpty(t, f.gateway.Store)
}

func TestRelayShortWrites(t *testing.T) {
	f := newFixture(t, echo, func(_ *Policy, g *Gateway) {
		g.Dialer = dialerFunc(func(ctx context.Context, n, a string) (net.Conn, error) {
			c, e := (&net.Dialer{}).DialContext(ctx, n, a)
			if e != nil {
				return nil, e
			}
			return shortWriteConn{c}, nil
		})
	})
	c, r := connectOK(t, f)
	payload := []byte("a response split across short writes")
	if _, e := c.Write(payload); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, len(payload))
	if _, e := io.ReadFull(r, got); e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("short writes: %q %v", got, e)
	}
}
func TestRelayBidirectionalBudget(t *testing.T) {
	f := newFixture(t, echo, func(p *Policy, _ *Gateway) { p.Rules[0].MaxBytes = 257 })
	c, r := connectOK(t, f)
	payload := bytes.Repeat([]byte("b"), 200)
	if _, e := c.Write(payload); e != nil {
		t.Fatal(e)
	}
	got, _ := io.ReadAll(r)
	waitEmpty(t, f.gateway.Store)
	if len(got) != 57 {
		t.Fatalf("bidirectional shared budget: sent200 received%d expected57", len(got))
	}
	a := f.gateway.Audit.(*memoryAudit)
	a.mu.Lock()
	defer a.mu.Unlock()
	last := a.rows[len(a.rows)-1]
	if last.Kind != "closed" || last.Bytes != 257 {
		t.Fatalf("forwarded audit: %+v", last)
	}
}
func TestExpiredMTLS(t *testing.T) {

	f := newFixture(t, echo, nil)
	cert, e := f.pki.expiredClient()
	if e != nil {
		t.Fatal(e)
	}
	c, _, status, e := labConnect(f.server.address, f.destination, f.pki, &cert)
	if c != nil {
		c.Close()
	}
	if e == nil {
		t.Fatalf("expired certificate reached HTTP status%d", status)
	}
}
