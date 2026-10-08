package relayfence

import "testing"

func mustStore(t *testing.T, p Policy) *Store {
	t.Helper()
	s, e := NewStore(p, "")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.Close)
	return s
}
