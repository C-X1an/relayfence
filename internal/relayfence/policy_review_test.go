package relayfence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func reviewLargePolicy(identities, destinations int) Policy {
	p := Policy{SchemaVersion: 1, Revision: 2, GlobalMaxActive: 64}
	for i := 0; i < identities; i++ {
		r := Rule{Identity: fmt.Sprintf("urn:relayfence:workload:large-%d", i), MaxActive: 1, MaxBytes: 2048, MaxDurationMS: 1000, IdleTimeoutMS: 100}
		for d := 0; d < destinations; d++ {
			r.Destinations = append(r.Destinations, fmt.Sprintf("d%d.test:443", d))
		}
		p.Rules = append(p.Rules, r)
	}
	return p
}

func TestPolicyPersistenceSizeBound(t *testing.T) {
	p := reviewLargePolicy(500, 80)
	compact, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	indented, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(compact)+1 >= MaxPolicyBytes || len(indented)+1 <= MaxPolicyBytes {
		t.Fatalf("regression fixture sizes compact=%d indented=%d limit=%d", len(compact), len(indented), MaxPolicyBytes)
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	initial, err := json.Marshal(labPolicy("a.test:443"))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, initial, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Replace(1, p); err != nil {
		t.Fatalf("valid compact policy replacement failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > MaxPolicyBytes {
		t.Fatalf("successful replacement wrote %d bytes, exceeding restart read bound %d", info.Size(), MaxPolicyBytes)
	}
	reloaded, err := LoadStore(path)
	if err != nil {
		t.Fatalf("successful replacement cannot be restarted: %v", err)
	}
	defer reloaded.Close()
	if reloaded.Status().Revision != 2 {
		t.Fatalf("restart revision=%d, want 2", reloaded.Status().Revision)
	}
}

func TestOversizedPolicyRejectedBeforePersistence(t *testing.T) {
	p := reviewLargePolicy(1024, 256)
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) <= MaxPolicyBytes {
		t.Fatalf("oversized fixture invalid: bytes=%d err=%v", len(encoded), err)
	}
	store := mustStore(t, labPolicy("a.test:443"))
	persisted := false
	store.persist = func(Policy) error { persisted = true; return nil }
	if err := store.Replace(1, p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized policy accepted: %v", err)
	}
	if persisted || store.Status().Revision != 1 || store.Status().Poisoned {
		t.Fatalf("invalid update changed live/durable state: persisted=%v status=%+v", persisted, store.Status())
	}
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := PersistPolicy(path, p); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized direct persistence accepted: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid direct persistence touched target: %v", err)
	}
}
