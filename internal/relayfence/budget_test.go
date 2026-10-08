package relayfence

import (
	"sync"
	"sync/atomic"

	"testing"
)

func TestBudgetConcurrent(t *testing.T) {
	const max = 10003
	b := NewBudget(max)
	var total atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := b.Take(37)
				if n == 0 {
					return
				}
				if n < 0 || n > 37 {
					t.Errorf("invalid grant %d", n)
					return
				}
				total.Add(int64(n))
			}
		}()
	}
	wg.Wait()
	if total.Load() != max || b.Remaining() != 0 {
		t.Fatalf("total=%d remaining=%d", total.Load(), b.Remaining())
	}
	if b.Take(-1) != 0 || b.Take(0) != 0 {
		t.Fatal("invalid reservation")
	}
}

func BenchmarkBudget(b *testing.B) {
	for i := 0; i < b.N; i++ {
		v := NewBudget(1000)
		for v.Take(37) != 0 {
		}
	}
}
