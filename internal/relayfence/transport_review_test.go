package relayfence

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The production public-IP decision remains enabled. The recording dialer
// explicitly remaps its approved literal to this owned real TCP listener;
// these tests verify pinning/transport, not actual public Internet routing.
type reviewTransport struct {
	fixture
	accepts, received, lookups atomic.Int64
	mu                         sync.Mutex
	dials                      []string
	payload                    []byte
	acceptDone                 chan struct{}
	handlers                   sync.WaitGroup
	closeOnce                  sync.Once
}

func newReviewTransport(t *testing.T, answers []netip.Addr, audit Audit) *reviewTransport {
	t.Helper()
	f := &reviewTransport{acceptDone: make(chan struct{})}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.upstream = listener
	go func() {
		defer close(f.acceptDone)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			f.accepts.Add(1)
			f.handlers.Add(1)
			go func() {
				defer f.handlers.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var captured bytes.Buffer
				n, _ := io.Copy(io.MultiWriter(&captured, c), c)
				f.received.Add(n)
				f.mu.Lock()
				f.payload = append(f.payload, captured.Bytes()...)
				f.mu.Unlock()
			}()
		}
	}()
	t.Cleanup(f.close)
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	f.destination = "echo.test:" + port
	store := mustStore(t, labPolicy(f.destination))
	if audit == nil {
		audit = &memoryAudit{}
	}
	f.gateway, err = NewGateway(store, audit)
	if err != nil {
		t.Fatal(err)
	}
	f.gateway.Resolver = resolverFunc(func(_ context.Context, network, host string) ([]netip.Addr, error) {
		f.lookups.Add(1)
		if network != "ip" || host != "echo.test" {
			return nil, fmt.Errorf("unexpected resolution %s %s", network, host)
		}
		return append([]netip.Addr(nil), answers...), nil
	})
	f.gateway.Dialer = dialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		f.mu.Lock()
		f.dials = append(f.dials, address)
		f.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})
	f.pki, err = newLabPKI()
	if err != nil {
		t.Fatal(err)
	}
	f.server, err = startLabGateway(f.gateway, f.pki)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *reviewTransport) close() {
	f.closeOnce.Do(func() {
		if f.server != nil {
			f.server.close()
		}
		f.upstream.Close()
		<-f.acceptDone
		f.handlers.Wait()
	})
}

func (f *reviewTransport) assertNoUpstream(t *testing.T) {
	t.Helper()
	f.close() // Join accept and handler completion before observing final effects.
	if len(f.dials) != 0 || f.accepts.Load() != 0 || f.received.Load() != 0 {
		t.Fatalf("forbidden upstream effects: dials=%v accepts=%d bytes=%d", f.dials, f.accepts.Load(), f.received.Load())
	}
}

func TestReviewDNSPinningRealTCP(t *testing.T) {
	f := newReviewTransport(t, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil)
	c, r := connectOK(t, &f.fixture)
	payload := []byte("synthetic-pinning-real-tcp")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(r, actual); err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("real upstream echo %q: %v", actual, err)
	}
	c.Close()
	f.close()
	_, port, _ := net.SplitHostPort(f.destination)
	if f.lookups.Load() != 1 || len(f.dials) != 1 || f.dials[0] != "8.8.8.8:"+port || f.accepts.Load() != 1 || !bytes.Equal(f.payload, payload) || f.received.Load() != int64(len(payload)) {
		t.Fatalf("pinning/forwarding: DNS=%d dials=%v accepts=%d bytes=%d payload=%q", f.lookups.Load(), f.dials, f.accepts.Load(), f.received.Load(), f.payload)
	}
}

func TestReviewMixedDNSNoUpstream(t *testing.T) {
	for _, answers := range [][]netip.Addr{
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")},
		{},
	} {
		t.Run(fmt.Sprint(answers), func(t *testing.T) {
			f := newReviewTransport(t, answers, nil)
			c, _, status, err := rawQueuedConnect(&f.fixture, "SYNTHETIC_DENIED_DNS_PAYLOAD")
			if c != nil {
				c.Close()
			}
			f.assertNoUpstream(t)
			if err != nil || status != http.StatusForbidden || f.lookups.Load() != 1 {
				t.Fatalf("mixed/empty DNS denial: status=%d DNS=%d err=%v", status, f.lookups.Load(), err)
			}
		})
	}
}

func TestReviewMTLSNoUpstream(t *testing.T) {
	for _, kind := range []string{"missing", "wrong_ca", "ambiguous", "no_uri", "unknown_identity"} {
		t.Run(kind, func(t *testing.T) {
			f := newReviewTransport(t, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil)
			var cert *tls.Certificate
			var leaf tls.Certificate
			var err error
			switch kind {
			case "wrong_ca":
				other, e := newLabPKI()
				if e != nil {
					t.Fatal(e)
				}
				cert = &other.client
			case "ambiguous":
				leaf, err = f.pki.leaf(true, []string{labIdentity, "urn:relayfence:workload:other"})
				cert = &leaf
			case "no_uri":
				leaf, err = f.pki.leaf(true, nil)
				cert = &leaf
			case "unknown_identity":
				leaf, err = f.pki.leaf(true, []string{"urn:relayfence:workload:other"})
				cert = &leaf
			}
			if err != nil {
				t.Fatal(err)
			}
			c, _, status, err := labConnect(f.server.address, f.destination, f.pki, cert)
			if c != nil {
				c.Close()
			}
			f.assertNoUpstream(t)
			if f.lookups.Load() != 0 || (err == nil && status != http.StatusForbidden) {
				t.Fatalf("authentication denial: status=%d DNS=%d err=%v", status, f.lookups.Load(), err)
			}
		})
	}
}

func TestReviewAuditFailureJoinedPayload(t *testing.T) {
	f := newReviewTransport(t, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, &memoryAudit{fail: true})
	c, _, status, err := rawQueuedConnect(&f.fixture, "SYNTHETIC_AUDIT_MUST_NOT_FORWARD")
	if c != nil {
		c.Close()
	}
	firstStatus, firstErr := status, err
	c, _, status, err = labConnect(f.server.address, f.destination, f.pki, &f.pki.client)
	if c != nil {
		c.Close()
	}
	f.close()
	if f.received.Load() != 0 || len(f.payload) != 0 {
		t.Fatalf("audit failure forwarded payload after upstream completion: bytes=%d payload=%q", f.received.Load(), f.payload)
	}
	if firstErr != nil || firstStatus != http.StatusServiceUnavailable || !f.gateway.Store.Status().Poisoned {
		t.Fatalf("audit failure response: status=%d store=%v err=%v", firstStatus, f.gateway.Store.Status(), firstErr)
	}
	if err != nil || status != http.StatusServiceUnavailable || len(f.dials) != 1 || f.accepts.Load() != 1 || f.lookups.Load() != 1 {
		t.Fatalf("poisoned grant effects: status=%d DNS=%d dials=%v accepts=%d err=%v", status, f.lookups.Load(), f.dials, f.accepts.Load(), err)
	}
}
