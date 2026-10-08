package relayfence

import (
	"context"
	"net/netip"

	"os"

	"errors"
	"sync/atomic"
	"testing"

	"net"

	"path/filepath"
	"sync"

	"time"
)

func TestAdmissionLimits(t *testing.T) {
	t.Run("exact_global2_identity1", func(t *testing.T) {
		p := labPolicy("a.test:443")
		p.GlobalMaxActive = 2
		p.Rules[0].MaxActive = 1
		for _, id := range []string{"urn:relayfence:workload:second", "urn:relayfence:workload:third"} {
			rule := p.Rules[0]
			rule.Identity = id
			p.Rules = append(p.Rules, rule)
		}
		s := mustStore(t, p)
		first, e := s.Reserve(context.Background(), p.Rules[0].Identity, "a.test:443")
		if e != nil {
			t.Fatal(e)
		}
		defer first.Release()
		if _, e = s.Reserve(context.Background(), p.Rules[0].Identity, "a.test:443"); !errors.Is(e, ErrCapacity) {
			t.Fatalf("identity1 limit: %v", e)
		}
		second, e := s.Reserve(context.Background(), p.Rules[1].Identity, "a.test:443")
		if e != nil {
			t.Fatal(e)
		}
		defer second.Release()
		if _, e = s.Reserve(context.Background(), p.Rules[2].Identity, "a.test:443"); !errors.Is(e, ErrCapacity) {
			t.Fatalf("global2 limit: %v", e)
		}
		if s.Status().Active != 2 {
			t.Fatal("expected exactly two reserved sessions")
		}
	})
	t.Run("rejected_session_never_resolves", func(t *testing.T) {
		var calls atomic.Int64
		f := newFixture(t, echo, func(p *Policy, g *Gateway) {
			p.GlobalMaxActive = 2
			p.Rules[0].MaxActive = 1
			g.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
				calls.Add(1)
				return nil, errors.New("must not resolve")
			})
		})
		pending, e := f.gateway.Store.Reserve(context.Background(), labIdentity, f.destination)
		if e != nil {
			t.Fatal(e)
		}
		defer pending.Release()
		c, _, status, e := labConnect(f.server.address, f.destination, f.pki, &f.pki.client)
		if c != nil {
			c.Close()
		}
		if e != nil || status != 429 || calls.Load() != 0 {
			t.Fatalf("admission denial status=%d error=%v DNS=%d", status, e, calls.Load())
		}
	})
	p := labPolicy("a.test:443")
	p.GlobalMaxActive = 3
	p.Rules[0].MaxActive = 2
	second := p.Rules[0]
	second.Identity = "urn:relayfence:workload:second"
	p.Rules = append(p.Rules, second)
	s := mustStore(t, p)
	a, e := s.Reserve(context.Background(), labIdentity, "a.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer a.Release()
	b, e := s.Reserve(context.Background(), labIdentity, "a.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer b.Release()
	if _, e = s.Reserve(context.Background(), labIdentity, "a.test:443"); !errors.Is(e, ErrCapacity) {
		t.Fatalf("identity quota: %v", e)
	}
	c, e := s.Reserve(context.Background(), second.Identity, "a.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Release()
	if _, e = s.Reserve(context.Background(), second.Identity, "a.test:443"); !errors.Is(e, ErrCapacity) {
		t.Fatalf("global quota: %v", e)
	}
	a.Release()
	a.Release()
	if s.Status().Active != 2 {
		t.Fatal("release did not execute exactly once")
	}
	d, e := s.Reserve(context.Background(), labIdentity, "a.test:443")
	if e != nil {
		t.Fatal(e)
	}
	d.Release()
	if _, e = s.Reserve(context.Background(), labIdentity, "bad.test:443"); !errors.Is(e, ErrDenied) {
		t.Fatalf("unauthorized authority: %v", e)
	}
}
func TestAdmissionConcurrent(t *testing.T) {
	p := labPolicy("a.test:443")
	p.Rules[0].MaxActive = 4
	p.GlobalMaxActive = 4
	s := mustStore(t, p)
	var count atomic.Int64
	ready := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			session, e := s.Reserve(context.Background(), labIdentity, "a.test:443")
			if e == nil {
				count.Add(1)
				<-release
				session.Release()
			} else if !errors.Is(e, ErrCapacity) {
				t.Errorf("unexpected: %v", e)
			}
		}()
	}
	close(ready)
	deadline := time.Now().Add(time.Second)
	for count.Load() != 4 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if count.Load() != 4 || s.Status().Active != 4 {
		t.Fatalf("admission count=%d status=%v", count.Load(), s.Status())
	}
	close(release)
	wg.Wait()
	if s.Status().Active != 0 {
		t.Fatal("leaked admission")
	}
}

func TestPolicyPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	p := labPolicy("a.test:443")
	if e := PersistPolicy(path, p); e != nil {
		t.Fatal(e)
	}
	s, e := LoadStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	p.Revision = 2
	p.Rules = nil
	if e = s.Replace(1, p); e != nil {
		t.Fatal(e)
	}
	reloaded, e := LoadStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reloaded.Close()
	if reloaded.Status().Revision != 2 {
		t.Fatal("replacement not durable")
	}
	if e = s.Replace(1, p); !errors.Is(e, ErrStale) {
		t.Fatalf("stale CAS: %v", e)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v", st.Mode())
	}
	p.Revision = 3
	s.persist = func(Policy) error { return errors.New("injected fsync failure") }
	if e = s.Replace(2, p); !errors.Is(e, ErrUnavailable) || !s.Status().Poisoned {
		t.Fatalf("failed persistence not closed: %v", e)
	}
	if _, e = s.Reserve(context.Background(), labIdentity, "a.test:443"); !errors.Is(e, ErrUnavailable) {
		t.Fatal("poisoned store admitted work")
	}
}
func TestRevisionFence(t *testing.T) {
	s := mustStore(t, labPolicy("a.test:443"))
	session, e := s.Reserve(context.Background(), labIdentity, "a.test:443")
	if e != nil {
		t.Fatal(e)
	}
	defer session.Release()
	session.Limits.Destinations[0] = "mutated.test:443"
	s.mu.Lock()
	if s.policy.Rules[0].Destinations[0] != "a.test:443" {
		t.Fatal("session aliases internal snapshot")
	}
	s.policy.Revision++
	s.mu.Unlock()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	if e = s.Attach(session, a); !errors.Is(e, ErrStale) {
		t.Fatalf("stale revision attached: %v", e)
	}
}
func TestPolicyCASConcurrent(t *testing.T) {
	s := mustStore(t, labPolicy("a.test:443"))
	p := labPolicy("a.test:443")
	p.Revision = 2
	var successes atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := s.Replace(1, p)
			if e == nil {
				successes.Add(1)
			} else if !errors.Is(e, ErrStale) {
				t.Errorf("unexpected: %v", e)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("CAS winners=%d", successes.Load())
	}
}

func BenchmarkAdmission(b *testing.B) {
	s, _ := NewStore(labPolicy("a.test:443"), "")
	defer s.Close()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v, e := s.Reserve(context.Background(), labIdentity, "a.test:443")
		if e != nil {
			b.Fatal(e)
		}
		v.Release()
	}
}
