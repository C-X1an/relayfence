package relayfence

// This workload is part of the explicitly synthetic socket laboratory. Clients
// leave authenticated tunnels idle; the real gateway must enforce its ceiling
// and idle deadline. It has no production flag or alternate authorization path.
import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type StallAttempt struct {
	Index      int    `json:"index"`
	Status     int    `json:"connect_status"`
	TLSSetupNS int64  `json:"tls_setup_ns"`
	ConnectNS  int64  `json:"connect_observed_ns,omitempty"`
	CloseNS    int64  `json:"close_ns,omitempty"`
	Error      string `json:"error,omitempty"`
}
type StallActiveSample struct {
	ElapsedNS int64 `json:"elapsed_ns"`
	Active    int   `json:"active"`
}
type StallReport struct {
	Concurrency        int                 `json:"concurrency"`
	Repetition         int                 `json:"repetition"`
	IdentityLimit      int                 `json:"identity_limit"`
	GlobalLimit        int                 `json:"global_limit"`
	WindowNS           int64               `json:"observation_window_ns"`
	PreparationNS      int64               `json:"preparation_ns"`
	DrainNS            int64               `json:"server_drain_ns"`
	ReleaseObservedNS  int64               `json:"release_observed_ns,omitempty"`
	WallNS             int64               `json:"wall_ns"`
	PeakObservedActive int                 `json:"peak_observed_active"`
	FinalActive        int                 `json:"final_active"`
	Admitted           int                 `json:"admitted"`
	Denied             int                 `json:"denied"`
	Failures           int                 `json:"failures"`
	Attempts           []StallAttempt      `json:"attempts"`
	ActiveSamples      []StallActiveSample `json:"active_samples"`
}

func benchmarkStalls(server *labServer, pki *labPKI, store *Store, policy *Policy, repetition int) (reports []StallReport, err error) {
	limited := *policy
	limited.Rules = append([]Rule(nil), policy.Rules...)
	limited.GlobalMaxActive = 8
	limited.Rules[0].MaxActive = 4
	limited.Rules[0].IdleTimeoutMS = 200
	limited.Rules[0].MaxDurationMS = 1000
	limited.Revision = store.Status().Revision + 1
	if err = store.Replace(limited.Revision-1, limited); err != nil {
		return reports, err
	}
	for _, concurrency := range []int{1, 4, 16, 64} {
		report := StallReport{Concurrency: concurrency, Repetition: repetition, IdentityLimit: 4, GlobalLimit: 8, Attempts: make([]StallAttempt, concurrency)}
		start := time.Now()
		var burstStart time.Time // published to workers by closing ready.
		ready := make(chan struct{})
		done := make(chan struct{})
		var workers, prepared sync.WaitGroup
		for index := range report.Attempts {
			workers.Add(1)
			prepared.Add(1)
			go func(index int) {
				defer workers.Done()
				attempt := StallAttempt{Index: index}
				defer func() { report.Attempts[index] = attempt }()
				setupStart := time.Now()
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				config := &tls.Config{RootCAs: pki.pool, ServerName: "proxy.test", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, Certificates: []tls.Certificate{pki.client}}
				c, connectErr := (&tls.Dialer{NetDialer: &net.Dialer{}, Config: config}).DialContext(ctx, "tcp", server.address)
				cancel()
				attempt.TLSSetupNS = time.Since(setupStart).Nanoseconds()
				prepared.Done()
				if connectErr != nil {
					attempt.Error = "TLS preparation: " + connectErr.Error()
					return
				}
				defer c.Close()
				<-ready
				if deadlineErr := c.SetDeadline(burstStart.Add(3 * time.Second)); deadlineErr != nil {
					attempt.Error = deadlineErr.Error()
					return
				}
				destination := policy.Rules[0].Destinations[0]
				if _, connectErr = fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", destination, destination); connectErr != nil {
					attempt.Error = connectErr.Error()
					return
				}
				reader := bufio.NewReader(c)
				response, connectErr := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
				attempt.ConnectNS = time.Since(burstStart).Nanoseconds()
				if connectErr != nil {
					attempt.Error = connectErr.Error()
					return
				}
				status := response.StatusCode
				attempt.Status = status
				if status == 429 {
					return
				}
				if status != 200 {
					attempt.Error = fmt.Sprintf("unexpected CONNECT %d", status)
					return
				}
				at := time.Now()
				if deadlineErr := c.SetReadDeadline(at.Add(time.Second)); deadlineErr != nil {
					attempt.Error = deadlineErr.Error()
					return
				}
				_, readErr := reader.ReadByte()
				attempt.CloseNS = time.Since(at).Nanoseconds()
				if readErr == nil {
					attempt.Error = "idle tunnel produced unexpected payload"
				} else if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
					attempt.Error = "idle tunnel survived its deadline"
				} else if attempt.CloseNS > int64(700*time.Millisecond) {
					attempt.Error = "idle close exceeded 200ms deadline plus 500ms observation tolerance"
				}
			}(index)
		}
		prepared.Wait()
		report.PreparationNS = time.Since(start).Nanoseconds()
		burstStart = time.Now()
		close(ready)
		go func() { workers.Wait(); close(done) }()
		ticker := time.NewTicker(2 * time.Millisecond)
		window := time.NewTimer(500 * time.Millisecond)
		windowDone, clientsDone := false, false
		windowC, clientC := window.C, done
		sample := func() {
			active := store.Status().Active
			elapsed := time.Since(burstStart).Nanoseconds()
			report.ActiveSamples = append(report.ActiveSamples, StallActiveSample{ElapsedNS: elapsed, Active: active})
			if elapsed <= int64(500*time.Millisecond) && active > report.PeakObservedActive {
				report.PeakObservedActive = active
			}
		}
		for !windowDone || !clientsDone {
			select {
			case <-ticker.C:
				sample()
			case <-windowC:
				report.WindowNS = time.Since(burstStart).Nanoseconds()
				windowDone, windowC = true, nil
			case <-clientC:
				clientsDone, clientC = true, nil
			}
		}
		// EOF is observable before the server joins its pumps, records the
		// closed event and releases admission. Observe that separate endpoint
		// under the same absolute idle+500ms bound; never reset it after EOF.
		releaseBy := burstStart.Add(700 * time.Millisecond)
		var lastAdmittedNS int64
		for _, attempt := range report.Attempts {
			if attempt.Status == 200 {
				if attempt.ConnectNS > lastAdmittedNS {
					lastAdmittedNS = attempt.ConnectNS
				}
				deadline := burstStart.Add(time.Duration(attempt.ConnectNS) + 700*time.Millisecond)
				if deadline.After(releaseBy) {
					releaseBy = deadline
				}
			}
			if attempt.Error != "" {
				report.Failures++
			} else if attempt.Status == 200 {
				report.Admitted++
			} else if attempt.Status == 429 {
				report.Denied++
			}
		}
		drainStart := time.Now()
		for store.Status().Active != 0 && time.Now().Before(releaseBy) {
			<-ticker.C
			sample()
		}
		sample()
		ticker.Stop()
		report.DrainNS = time.Since(drainStart).Nanoseconds()
		report.FinalActive = store.Status().Active
		report.WallNS = time.Since(start).Nanoseconds()
		for _, observation := range report.ActiveSamples {
			if observation.Active > report.IdentityLimit {
				report.Failures++
			}
			if observation.Active == 0 && observation.ElapsedNS >= lastAdmittedNS {
				report.ReleaseObservedNS = observation.ElapsedNS
				break
			}
		}
		if report.PeakObservedActive == 0 || report.PeakObservedActive > report.IdentityLimit || report.FinalActive != 0 || report.ReleaseObservedNS == 0 || report.ReleaseObservedNS > lastAdmittedNS+int64(700*time.Millisecond) || report.Admitted == 0 || (concurrency > report.IdentityLimit && report.Denied == 0) {
			report.Failures++
		}
		reports = append(reports, report)
		if report.Failures != 0 {
			return reports, fmt.Errorf("stalled-tunnel observations retained %d failures at concurrency %d: %+v", report.Failures, concurrency, report)
		}
	}
	policy.Revision = store.Status().Revision + 1
	err = store.Replace(policy.Revision-1, *policy)
	return reports, err
}
