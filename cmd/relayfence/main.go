package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	rf "github.com/C-X1an/relayfence/internal/relayfence"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "relayfence:", err)
		os.Exit(1)
	}
}
func run(args []string) (retErr error) {
	if len(args) == 0 {
		return errors.New("use serve, demo, inspect, status or policy")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "demo":
		out := flags.String("out", ".state/demo", "fresh private output directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if err := rf.Demo(*out); err != nil {
			return err
		}
		fmt.Println("PASS: real local mTLS echo, policy denial and live revocation; synthetic DNS fixture")
		return nil
	case "inspect":
		audit := flags.String("audit", "", "audit JSONL")
		out := flags.String("out", "", "output HTML")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *audit == "" || *out == "" || flags.NArg() != 0 {
			return errors.New("--audit and --out required")
		}
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		e := rf.InspectAudit(*audit, f)
		ce := f.Close()
		if e != nil {
			_ = os.Remove(*out)
			return e
		}
		return ce
	case "status", "policy":
		admin := flags.String("admin", ".state/admin.sock", "local Unix admin socket")
		file := flags.String("file", "", "policy update JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		method, path := http.MethodGet, "/v1/status"
		var data []byte
		if args[0] == "policy" {
			if *file == "" {
				return errors.New("--file required")
			}
			var err error
			data, err = os.ReadFile(*file)
			if err != nil {
				return err
			}
			var update rf.PolicyUpdate
			if err = rf.StrictJSON(data, &update); err != nil {
				return err
			}
			method, path = http.MethodPut, "/v1/policy"
		}
		req, err := http.NewRequest(method, "http://unix"+path, bytes.NewReader(data))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		client := rf.AdminClient(*admin)
		defer client.CloseIdleConnections()
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		if err != nil {
			return err
		}
		if _, err = os.Stdout.Write(body); err != nil {
			return err
		}
		if response.StatusCode != 200 {
			return fmt.Errorf("admin returned %d", response.StatusCode)
		}
		return nil
	case "serve":
		listen := flags.String("listen", "127.0.0.1:8443", "gateway TLS listen address")
		certPath := flags.String("cert", "", "server certificate PEM")
		keyPath := flags.String("key", "", "server private key PEM")
		caPath := flags.String("ca", "", "client CA PEM")
		policyPath := flags.String("policy", ".state/policy.json", "durable policy")
		auditPath := flags.String("audit", ".state/audit.jsonl", "audit file")
		adminPath := flags.String("admin", ".state/admin.sock", "local admin socket")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *certPath == "" || *keyPath == "" || *caPath == "" || flags.NArg() != 0 {
			return errors.New("--cert --key --ca required")
		}
		st, err := os.Stat(*keyPath)
		if err != nil {
			return err
		}
		if st.Mode().Perm()&0077 != 0 {
			return errors.New("private key must not be group/world accessible")
		}
		cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			return err
		}
		ca, err := os.ReadFile(*caPath)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(ca) {
			return errors.New("invalid CA bundle")
		}
		store, err := rf.LoadStore(*policyPath)
		if err != nil {
			return err
		}
		defer store.Close()
		audit, err := rf.OpenAudit(*auditPath)
		if err != nil {
			return err
		}
		owned := true
		defer func() {
			if owned {
				retErr = errors.Join(retErr, audit.Close())
			}
		}()
		tracked := &daemonAudit{Audit: audit}
		gateway, err := rf.NewGateway(store, tracked)
		if err != nil {
			return err
		}
		admin, err := rf.StartAdmin(*adminPath, store)
		if err != nil {
			return err
		}
		defer func() {
			if owned {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				retErr = errors.Join(retErr, admin.Close(ctx))
			}
		}()
		listener, err := net.Listen("tcp", *listen)
		if err != nil {
			return err
		}
		server := rf.HTTPServer(gateway, rf.TLSConfig(cert, pool))
		signals, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "listening", "address": listener.Addr().String(), "revision": store.Status().Revision})
		owned = false
		return serveDaemon(signals, tls.NewListener(listener, server.TLSConfig), server, store, tracked, audit.Close, admin.Close)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// daemonAudit preserves the first audit failure for the daemon's exit status.
// The gateway separately poisons admission as soon as Record fails.
type daemonAudit struct {
	rf.Audit
	mu  sync.Mutex
	err error
}

func (a *daemonAudit) Record(event rf.Event) error {
	err := a.Audit.Record(event)
	if err != nil {
		a.mu.Lock()
		if a.err == nil {
			a.err = err
		}
		a.mu.Unlock()
	}
	return err
}

func (a *daemonAudit) failure() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.err
}

// handlerDrain joins the complete handler, including hijacked pumps, audit,
// deferred Release, and denial paths. Admission and drain share the same lock;
// no handler can enter after the zero-completion observation.
type handlerDrain struct {
	next     http.Handler
	mu       sync.Mutex
	active   int
	draining bool
	done     chan struct{}
}

func (d *handlerDrain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	if d.draining {
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "unavailable"}})
		return
	}
	d.active++
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.active--
		if d.draining && d.active == 0 {
			close(d.done)
		}
	}()
	d.next.ServeHTTP(w, r)
}

func (d *handlerDrain) begin() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.draining = true
	if d.active == 0 {
		close(d.done)
	}
}

func serveDaemon(ctx context.Context, listener net.Listener, server *http.Server, store *rf.Store, audit *daemonAudit, closeAudit func() error, closeAdmin func(context.Context) error) error {
	drain := &handlerDrain{next: server.Handler, done: make(chan struct{})}
	server.Handler = drain
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	var result error
	served := false
	select {
	case result = <-done:
		served = true
		if errors.Is(result, http.ErrServerClosed) {
			result = nil
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	drain.begin()
	store.Close() // HTTP shutdown cannot cancel hijacked CONNECT sockets.
	if err := server.Shutdown(shutdown); err != nil {
		result = errors.Join(result, fmt.Errorf("HTTP shutdown: %w", err), server.Close())
	}
	if !served {
		select {
		case err := <-done:
			if !errors.Is(err, http.ErrServerClosed) {
				result = errors.Join(result, err)
			}
		case <-shutdown.Done():
			result = errors.Join(result, fmt.Errorf("HTTP serve join: %w", shutdown.Err()))
		}
	}
	joined := false
	select {
	case <-drain.done:
		joined = true
	case <-shutdown.Done():
		result = errors.Join(result, fmt.Errorf("handler finalization: %w", shutdown.Err()))
	}
	result = errors.Join(result, closeAdmin(shutdown), audit.failure())
	if joined {
		if active := store.Status().Active; active != 0 {
			result = errors.Join(result, fmt.Errorf("shutdown left %d sessions", active))
		}
		result = errors.Join(result, closeAudit())
	}
	// On a drain timeout, leave audit open for the unfinished handlers. The
	// daemon reports failure and process exit closes descriptors; closing the
	// writer here could race a late Record or block behind its disk I/O.
	return result
}
