package relayfence

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Status struct {
	Revision uint64 `json:"revision"`
	Active   int    `json:"active"`
	Poisoned bool   `json:"poisoned"`
}
type Store struct {
	mu       sync.Mutex
	policy   Policy
	active   map[uint64]*Session
	counts   map[string]int
	nextID   uint64
	poisoned bool
	persist  func(Policy) error
}
type Session struct {
	ID          uint64
	Revision    uint64
	Identity    string
	Destination string
	Limits      Rule
	Context     context.Context
	cancel      context.CancelFunc
	store       *Store
	mu          sync.Mutex
	connections []net.Conn
	closed      bool
	closeOnce   sync.Once
	releaseOnce sync.Once
}

func NewStore(p Policy, path string) (*Store, error) {
	p, err := p.Validate()
	if err != nil {
		return nil, err
	}
	s := &Store{policy: p, active: map[uint64]*Session{}, counts: map[string]int{}}
	if path != "" {
		s.persist = func(next Policy) error { return PersistPolicy(path, next) }
	}
	return s, nil
}
func LoadStore(path string) (*Store, error) {
	p, err := ReadPolicy(path)
	if err != nil {
		return nil, err
	}
	return NewStore(p, path)
}
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{s.policy.Revision, len(s.active), s.poisoned}
}
func (s *Store) Reserve(ctx context.Context, identity, destination string) (*Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned {
		return nil, ErrUnavailable
	}
	var rule Rule
	allowed := false
	for _, r := range s.policy.Rules {
		if r.Identity == identity {
			rule = r
			for _, d := range r.Destinations {
				if d == destination {
					allowed = true
					break
				}
			}
			break
		}
	}
	if !allowed {
		return nil, ErrDenied
	} // MUTATION_POINT_AUTH
	if len(s.active) >= s.policy.GlobalMaxActive || s.counts[identity] >= rule.MaxActive {
		return nil, ErrCapacity
	}
	if s.nextID == math.MaxUint64 {
		s.poisoned = true
		return nil, ErrUnavailable
	}
	s.nextID++
	rule.Destinations = append([]string(nil), rule.Destinations...)
	child, cancel := context.WithTimeout(ctx, time.Duration(rule.MaxDurationMS)*time.Millisecond)
	session := &Session{ID: s.nextID, Revision: s.policy.Revision, Identity: identity, Destination: destination, Limits: rule, Context: child, cancel: cancel, store: s}
	s.active[session.ID] = session
	s.counts[identity]++
	return session, nil
}
func (s *Store) Attach(session *Session, connections ...net.Conn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.poisoned || s.active[session.ID] != session || session.Revision != s.policy.Revision || session.Context.Err() != nil {
		return ErrStale
	} // MUTATION_POINT_REVISION
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return ErrStale
	}
	session.connections = append(session.connections, connections...)
	return nil
}
func (s *Session) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		connections := append([]net.Conn(nil), s.connections...)
		s.mu.Unlock()
		s.cancel()
		for _, c := range connections {
			closeTransport(c)
		}
	})
}

// Terminal cancellation must interrupt the underlying I/O before asking TLS
// to close: close_notify takes the TLS output lock and replaces write deadlines
// with a five-second deadline. Closing the owned transport also wakes an
// in-flight CloseWrite without abandoning a pump or releasing its reservation.
// Normal EOF still uses CloseWrite to preserve the response half of a tunnel.
func closeTransport(c net.Conn) {
	if secured, ok := c.(*tls.Conn); ok {
		_ = secured.NetConn().Close()
	}
	_ = c.Close()
}
func (s *Session) Release() {
	s.releaseOnce.Do(func() {
		s.Close()
		s.store.mu.Lock()
		defer s.store.mu.Unlock()
		if s.store.active[s.ID] == s {
			delete(s.store.active, s.ID)
			s.store.counts[s.Identity]--
			if s.store.counts[s.Identity] == 0 {
				delete(s.store.counts, s.Identity)
			}
		}
	})
}
func (s *Store) snapshotSessionsLocked() []*Session {
	list := make([]*Session, 0, len(s.active))
	for _, v := range s.active {
		list = append(list, v)
	}
	return list
}
func (s *Store) Replace(expected uint64, next Policy) error {
	validated, err := next.Validate()
	if err != nil {
		return err
	}
	if expected == math.MaxUint64 || next.Revision != expected+1 {
		return ErrInvalid
	}
	s.mu.Lock()
	if s.poisoned {
		s.mu.Unlock()
		return ErrUnavailable
	}
	if s.policy.Revision != expected {
		s.mu.Unlock()
		return ErrStale
	}
	if s.persist != nil {
		if err := s.persist(validated); err != nil {
			s.poisoned = true
			list := s.snapshotSessionsLocked()
			s.mu.Unlock()
			for _, session := range list {
				session.Close()
			}
			return ErrUnavailable
		}
	}
	s.policy = validated
	list := s.snapshotSessionsLocked()
	s.mu.Unlock()
	for _, session := range list {
		session.Close()
	}
	return nil
}
func (s *Store) Poison() {
	s.mu.Lock()
	s.poisoned = true
	list := s.snapshotSessionsLocked()
	s.mu.Unlock()
	for _, session := range list {
		session.Close()
	}
}
func (s *Store) Close() { s.Poison() }

// PersistPolicy uses a same-directory atomic replacement. Failure can mean the
// rename became visible without confirmed durability; callers must fail closed.
func PersistPolicy(path string, p Policy) error {
	validated, err := p.Validate()
	if err != nil {
		return err
	}
	// Compact encoding keeps every accepted policy within ReadPolicy's bound;
	// indentation can expand an otherwise valid compact admin request past it.
	bytes, err := json.Marshal(validated)
	if err != nil {
		return err
	}
	bytes = append(bytes, '\n')
	if len(bytes) > MaxPolicyBytes {
		return ErrInvalid
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".policy-*")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(bytes)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(temp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
