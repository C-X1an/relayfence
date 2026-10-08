package relayfence

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type BenchmarkSample struct {
	Index     int    `json:"index"`
	LatencyNS int64  `json:"latency_ns"`
	Error     string `json:"error,omitempty"`
}
type BenchmarkGroup struct {
	Mode                   string            `json:"mode"`
	Concurrency            int               `json:"concurrency"`
	Repetition             int               `json:"repetition"`
	Samples                []BenchmarkSample `json:"samples"`
	WallNS                 int64             `json:"wall_ns"`
	Successful             int               `json:"successful"`
	Failures               int               `json:"failures"`
	P50NS                  int64             `json:"p50_ns"`
	P95NS                  int64             `json:"p95_ns"`
	P99NS                  int64             `json:"p99_ns"`
	PeakObservedGoroutines int64             `json:"peak_observed_goroutines"`
	PeakObservedHeapBytes  uint64            `json:"peak_observed_heap_bytes"`
	TotalAllocBytes        uint64            `json:"total_alloc_bytes"`
	PeakObservedActive     int64             `json:"peak_observed_active"`
}
type BenchmarkAttempt struct {
	Index      int    `json:"index"`
	Mode       string `json:"mode,omitempty"`
	Stage      string `json:"stage"`
	Repetition int    `json:"repetition,omitempty"`
	LatencyNS  *int64 `json:"latency_ns,omitempty"`
	Error      string `json:"error,omitempty"`
}
type BenchmarkReport struct {
	SchemaVersion       int                `json:"schema_version"`
	Kind                string             `json:"kind"`
	GoVersion           string             `json:"go_version"`
	GOOS                string             `json:"goos"`
	GOARCH              string             `json:"goarch"`
	CPUs                int                `json:"cpus"`
	GOMAXPROCS          int                `json:"gomaxprocs"`
	PayloadBytes        int                `json:"payload_bytes"`
	Warmup              int                `json:"warmup"`
	Started             string             `json:"started"`
	Groups              []BenchmarkGroup   `json:"groups"`
	SetupGroups         []BenchmarkGroup   `json:"setup_groups"`
	StallGroups         []StallReport      `json:"stall_groups"`
	RevocationNS        []int64            `json:"revocation_ns"`
	Notes               []string           `json:"notes"`
	Status              string             `json:"status"`
	FailureStage        string             `json:"failure_stage,omitempty"`
	Error               string             `json:"error,omitempty"`
	WarmupAttempts      []BenchmarkAttempt `json:"warmup_attempts"`
	RevocationAttempts  []BenchmarkAttempt `json:"revocation_attempts"`
	WarmupAttempted     int                `json:"warmup_attempted"`
	RevocationAttempted int                `json:"revocation_attempted"`
}

func percentile(samples []BenchmarkSample, q float64) int64 {
	values := make([]int64, 0, len(samples))
	for _, s := range samples {
		if s.Error == "" {
			values = append(values, s.LatencyNS)
		}
	}
	if len(values) == 0 {
		return 0
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	i := int(math.Ceil(q*float64(len(values)))) - 1
	if i < 0 {
		i = 0
	}
	return values[i]
}
func startEchoListener(listener net.Listener) func() {
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return func() { listener.Close(); <-done; wg.Wait() }
}
func exchange(c net.Conn, reader io.Reader) error {
	payload := bytes.Repeat([]byte("R"), 1024)
	if _, e := c.Write(payload); e != nil {
		return e
	}
	actual := make([]byte, len(payload))
	if _, e := io.ReadFull(reader, actual); e != nil {
		return e
	}
	if !bytes.Equal(actual, payload) {
		return errors.New("payload mismatch")
	}
	if cw, ok := c.(closeWriter); ok {
		if e := cw.CloseWrite(); e != nil {
			return e
		}
	}
	remainder, e := io.ReadAll(reader)
	if e != nil {
		return e
	}
	if len(remainder) != 0 {
		return errors.New("unexpected trailing payload")
	}
	return nil
}
func benchmarkGroup(mode string, concurrency, repetition, operations int, work func() (int64, error), store *Store) BenchmarkGroup {
	g := BenchmarkGroup{Mode: mode, Concurrency: concurrency, Repetition: repetition, Samples: make([]BenchmarkSample, operations)}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	var peakG atomic.Int64
	var peakActive atomic.Int64
	var peakHeap atomic.Uint64
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(2 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				active := int64(store.Status().Active)
				if active > peakActive.Load() {
					peakActive.Store(active)
				}
				n := int64(runtime.NumGoroutine())
				if n > peakG.Load() {
					peakG.Store(n)
				}
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > peakHeap.Load() {
					peakHeap.Store(m.HeapAlloc)
				}
			}
		}
	}()
	start := time.Now()
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				latency, e := work()
				s := BenchmarkSample{Index: index, LatencyNS: latency}
				if e != nil {
					s.Error = e.Error()
				}
				g.Samples[index] = s
			}
		}()
	}
	for i := 0; i < operations; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for store.Status().Active != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	g.WallNS = time.Since(start).Nanoseconds()
	close(stop)
	<-stopped
	runtime.ReadMemStats(&after)
	g.PeakObservedGoroutines = peakG.Load()
	g.PeakObservedActive = peakActive.Load()
	g.PeakObservedHeapBytes = peakHeap.Load()
	g.TotalAllocBytes = after.TotalAlloc - before.TotalAlloc
	for _, s := range g.Samples {
		if s.Error == "" {
			g.Successful++
		} else {
			g.Failures++
		}
	}
	if store.Status().Active != 0 {
		g.Failures++
	}
	g.P50NS = percentile(g.Samples, .50)
	g.P95NS = percentile(g.Samples, .95)
	g.P99NS = percentile(g.Samples, .99)
	return g
}

// RunBenchmark measures a synthetic loopback harness, not production capacity.
// Resource counters cover both clients and servers in this process.
func RunBenchmark(out string, operations, repeats int) error {
	return runBenchmark(out, operations, repeats, nil)
}

// beforeAttempt is an internal fault-injection dependency. Successful samples
// always execute the real transport; injected failures have no latency value.
func runBenchmark(out string, operations, repeats int, beforeAttempt func(stage string, index int) error) (err error) {
	if operations < 16 || operations > 500 || repeats < 1 || repeats > 5 {
		return ErrInvalid
	}
	if err := os.MkdirAll(out, 0700); err != nil {
		return err
	}
	path := filepath.Join(out, "results.json")
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		return errors.New("benchmark output must be fresh")
	}
	report := BenchmarkReport{SchemaVersion: 4, Kind: "synthetic loopback mTLS setup, exchange and stalled-tunnel harness", GoVersion: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, CPUs: runtime.NumCPU(), GOMAXPROCS: runtime.GOMAXPROCS(0), PayloadBytes: 1024, Warmup: 10, Started: time.Now().UTC().Format(time.RFC3339Nano), Notes: []string{
		"Both client and servers share one process/host. This is not production capacity or isolated daemon RSS.",
		"Direct baseline includes mTLS echo, but no CONNECT parsing, destination authorization, upstream dial or audit fsync. Difference measures that bundle, not one control.",
		"Proxy DNS is an explicit deterministic loopback fixture. Production address denial remains enabled outside this laboratory.",
		"Durable admission/close audit enabled; policy revocations include atomic persistence. Whole-process Go heap/goroutines sampled every2ms; sampling perturbs timings.",
		"Setup samples stop after verified mTLS handshake (direct) or successful CONNECT headers (proxy). Exchange samples also include 1KiB echo and half-close/EOF; sample timers exclude deferred client close. Group wall time includes cleanup/drain.",
		"Each repetition starts with ten warmups per mode. Stalled clients first prepare real verified mTLS connections; preparation timings and errors are retained separately. A CONNECT barrier starts the fixed500ms observation window, identity/global ceilings4/8 and idle/lifetime200/1000ms. Peak-active is sampled only inside that window and is a lower bound. Final active is observed after all clients finish and server drain, bounded by the latest admitted CONNECT observation plus700ms. Group wall time includes preparation and drain. Every attempt is retained.",
		"All completed groups and attempted warmups/revocations retained on returned failures when report storage is writable. Abrupt termination can interrupt report persistence; collector failures remain visible. Nearest-rank quantiles; no normality assumption or significance claim. Filesystem/hardware details are in machine run manifests.",
	}}
	stage := "setup"
	// Registered before resource cleanup: partial reports are written after all
	// deferred cleanup, and report-write errors remain visible to the caller.
	defer func() {
		report.Status = "PASS"
		if err != nil {
			report.Status = "FAIL"
			report.FailureStage = stage
			report.Error = err.Error()
		}
		report.WarmupAttempted = len(report.WarmupAttempts)
		report.RevocationAttempted = len(report.RevocationAttempts)
		data, writeErr := json.MarshalIndent(report, "", "  ")
		if writeErr == nil {
			writeErr = os.WriteFile(path, append(data, '\n'), 0600)
		}
		if writeErr != nil {
			err = errors.Join(err, fmt.Errorf("benchmark report write: %w", writeErr))
		}
	}()
	audit, e := OpenAudit(filepath.Join(out, "audit.jsonl"))
	if e != nil {
		return e
	}
	defer func() { err = errors.Join(err, audit.Close()) }()
	pki, e := newLabPKI()
	if e != nil {
		return e
	}
	plain, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	defer startEchoListener(plain)()
	_, port, _ := net.SplitHostPort(plain.Addr().String())
	destination := "echo.test:" + port
	policy := labPolicy(destination)
	policy.GlobalMaxActive = 256
	policy.Rules[0].MaxActive = 256
	policy.Rules[0].MaxDurationMS = 30000
	policy.Rules[0].IdleTimeoutMS = 5000
	policyPath := filepath.Join(out, "policy.json")
	if e = PersistPolicy(policyPath, policy); e != nil {
		return e
	}
	store, e := LoadStore(policyPath)
	if e != nil {
		return e
	}
	defer store.Close()
	gateway, e := NewGateway(store, audit)
	if e != nil {
		return e
	}
	gateway.labLoopback = true
	gateway.Resolver = resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	server, e := startLabGateway(gateway, pki)
	if e != nil {
		return e
	}
	defer server.close()
	direct, e := tls.Listen("tcp", "127.0.0.1:0", TLSConfig(pki.server, pki.pool))
	if e != nil {
		return e
	}
	defer startEchoListener(direct)()
	workProxy := func(setup bool) func() (int64, error) {
		return func() (int64, error) {
			at := time.Now()
			c, r, status, e := labConnect(server.address, destination, pki, &pki.client)
			if e != nil {
				return time.Since(at).Nanoseconds(), e
			}
			defer c.Close()
			if status != 200 {
				return time.Since(at).Nanoseconds(), fmt.Errorf("CONNECT status %d", status)
			}
			if setup {
				return time.Since(at).Nanoseconds(), nil
			}
			e = exchange(c, r)
			return time.Since(at).Nanoseconds(), e
		}
	}
	workDirect := func(setup bool) func() (int64, error) {
		return func() (int64, error) {
			at := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, e := (&tls.Dialer{Config: &tls.Config{RootCAs: pki.pool, ServerName: "proxy.test", Certificates: []tls.Certificate{pki.client}, MinVersion: tls.VersionTLS13}}).DialContext(ctx, "tcp", direct.Addr().String())
			if e != nil {
				return time.Since(at).Nanoseconds(), e
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			if setup {
				return time.Since(at).Nanoseconds(), nil
			}
			e = exchange(c, c)
			return time.Since(at).Nanoseconds(), e
		}
	}
	failed := false
	for repetition := 1; repetition <= repeats; repetition++ {
		stage = "warmup"
		for i := 0; i < 10; i++ {
			for _, mode := range []string{"proxy_mtls", "direct_mtls"} {
				attempt := BenchmarkAttempt{Index: i, Mode: mode, Stage: "warmup", Repetition: repetition}
				if beforeAttempt != nil {
					e = beforeAttempt("warmup_"+mode, i)
				}
				if e == nil {
					work := workProxy(false)
					if mode == "direct_mtls" {
						work = workDirect(false)
					}
					duration, workErr := work()
					e = workErr
					attempt.LatencyNS = &duration
				}
				if e != nil {
					attempt.Error = e.Error()
				}
				report.WarmupAttempts = append(report.WarmupAttempts, attempt)
				if e != nil {
					return e
				}
			}
		}
		stage = "groups"
		for _, concurrency := range []int{1, 4, 8, 16, 64} {
			modes := []string{"direct_mtls", "proxy_mtls"}
			if repetition%2 == 0 {
				modes[0], modes[1] = modes[1], modes[0]
			}
			for _, mode := range modes {
				work := workDirect(false)
				if mode == "proxy_mtls" {
					work = workProxy(false)
				}
				g := benchmarkGroup(mode, concurrency, repetition, operations, work, store)
				if g.Failures != 0 {
					failed = true
				}
				report.Groups = append(report.Groups, g)
			}
		}
		stage = "setup-groups"
		for _, concurrency := range []int{1, 8} {
			modes := []string{"direct_mtls", "proxy_mtls"}
			if repetition%2 == 0 {
				modes[0], modes[1] = modes[1], modes[0]
			}
			for _, mode := range modes {
				work := workDirect(true)
				if mode == "proxy_mtls" {
					work = workProxy(true)
				}
				group := benchmarkGroup(mode, concurrency, repetition, operations, work, store)
				if group.Failures != 0 {
					failed = true
				}
				report.SetupGroups = append(report.SetupGroups, group)
			}
		}
		stage = "stalls"
		stalls, stallErr := benchmarkStalls(server, pki, store, &policy, repetition)
		report.StallGroups = append(report.StallGroups, stalls...)
		if stallErr != nil {
			return stallErr
		}
	}
	stage = "revocation"
	for i := 0; i < 100; i++ {
		attempt := BenchmarkAttempt{Index: i, Stage: "connect"}
		revokeErr := func() (attemptErr error) {
			defer func() {
				if attemptErr != nil {
					attempt.Error = attemptErr.Error()
				}
				report.RevocationAttempts = append(report.RevocationAttempts, attempt)
			}()
			if beforeAttempt != nil {
				if e := beforeAttempt("revocation", i); e != nil {
					return e
				}
			}
			c, r, status, e := labConnect(server.address, destination, pki, &pki.client)
			if e != nil {
				return e
			}
			defer c.Close()
			if status != 200 {
				return fmt.Errorf("revocation CONNECT %d", status)
			}
			attempt.Stage = "replace"
			expected := store.Status().Revision
			policy.Revision = expected + 1
			start := time.Now()
			e = store.Replace(expected, policy)
			if e != nil {
				duration := time.Since(start).Nanoseconds()
				attempt.LatencyNS = &duration
				return e
			}
			attempt.Stage = "observe-close"
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			_, e = r.ReadByte()
			duration := time.Since(start).Nanoseconds()
			attempt.LatencyNS = &duration
			if e == nil {
				return errors.New("revoked connection survived")
			}
			if ne, ok := e.(net.Error); ok && ne.Timeout() {
				return errors.New("revocation timed out")
			}
			report.RevocationNS = append(report.RevocationNS, duration)
			attempt.Stage = "complete"
			return nil
		}()
		if revokeErr != nil {
			return revokeErr
		}
	}
	if failed {
		stage = "groups"
		return errors.New("benchmark retained nonzero failures")
	}
	stage = "cleanup"
	return nil
}
