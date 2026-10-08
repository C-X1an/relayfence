package relayfence

import "sync/atomic"

// Budget is shared by both relay directions. Reservations are deliberately not
// refunded after partial writes: actual delivered bytes can never exceed them.
type Budget struct{ remaining atomic.Int64 }

func NewBudget(limit int64) *Budget {
	b := &Budget{}
	if limit > 0 {
		b.remaining.Store(limit)
	}
	return b
}
func (b *Budget) Take(requested int) int {
	if requested <= 0 {
		return 0
	}
	for {
		old := b.remaining.Load()
		if old <= 0 {
			return 0
		}
		n := int64(requested)
		if n > old {
			n = old
		} // MUTATION_POINT_BUDGET
		if b.remaining.CompareAndSwap(old, old-n) {
			return int(n)
		}
	}
}
func (b *Budget) Remaining() int64 { return b.remaining.Load() }
