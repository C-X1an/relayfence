package relayfence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readReviewBenchmark(t *testing.T, out string) BenchmarkReport {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(out, "results.json"))
	if err != nil {
		t.Fatalf("completed benchmark observations were discarded: %v", err)
	}
	var report BenchmarkReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func TestReviewBenchmarkWarmupFailureRetained(t *testing.T) {
	out := t.TempDir()
	fault := errors.New("synthetic warmup fault")
	err := runBenchmark(out, 16, 1, func(stage string, index int) error {
		if stage == "warmup_proxy_mtls" && index == 1 {
			return fault
		}
		return nil
	})
	if !errors.Is(err, fault) {
		t.Fatalf("warmup failure must propagate: %v", err)
	}
	report := readReviewBenchmark(t, out)
	if report.Status != "FAIL" || report.FailureStage != "warmup" || report.Error != fault.Error() || report.WarmupAttempted != 3 || len(report.WarmupAttempts) != 3 || len(report.Groups) != 0 || report.RevocationAttempted != 0 {
		t.Fatalf("warmup report lost attempts/stage: %+v", report)
	}
	for _, sample := range report.WarmupAttempts[:2] {
		if sample.LatencyNS == nil || *sample.LatencyNS <= 0 || sample.Error != "" {
			t.Fatalf("successful real warmup observation absent: %+v", sample)
		}
	}
	last := report.WarmupAttempts[2]
	if last.Index != 1 || last.Mode != "proxy_mtls" || last.Error != fault.Error() || last.LatencyNS != nil {
		t.Fatalf("injected failure fabricated a latency or lost error: %+v", last)
	}
}

func TestReviewBenchmarkRevocationFailureRetained(t *testing.T) {
	out := t.TempDir()
	fault := errors.New("synthetic revocation fault")
	err := runBenchmark(out, 16, 1, func(stage string, index int) error {
		if stage == "revocation" && index == 3 {
			return fault
		}
		return nil
	})
	if !errors.Is(err, fault) {
		t.Fatalf("revocation failure must propagate: %v", err)
	}
	report := readReviewBenchmark(t, out)
	if report.Status != "FAIL" || report.FailureStage != "revocation" || report.Error != fault.Error() || len(report.Groups) != 10 || len(report.SetupGroups) != 4 || len(report.StallGroups) != 4 || report.WarmupAttempted != 20 || len(report.RevocationNS) != 3 || report.RevocationAttempted != 4 || len(report.RevocationAttempts) != 4 {
		t.Fatalf("revocation report lost groups/attempts: %+v", report)
	}
	for _, group := range report.Groups {
		if len(group.Samples) != 16 || group.Successful+group.Failures < 16 {
			t.Fatalf("completed real transport group lost observations: %+v", group)
		}
	}
	for index, sample := range report.RevocationAttempts[:3] {
		if sample.Index != index || sample.LatencyNS == nil || *sample.LatencyNS != report.RevocationNS[index] || sample.Error != "" || sample.Stage != "complete" {
			t.Fatalf("successful revocation lost measured observation: %+v", sample)
		}
	}
	last := report.RevocationAttempts[3]
	if last.Index != 3 || last.Error != fault.Error() || last.LatencyNS != nil || last.Stage != "connect" {
		t.Fatalf("failed attempt must retain index/error without an invented latency: %+v", last)
	}
}

func TestReviewBenchmarkReportWriteFailurePropagates(t *testing.T) {
	out := t.TempDir()
	fault := errors.New("synthetic warmup fault before report write")
	err := runBenchmark(out, 16, 1, func(stage string, index int) error {
		if stage == "warmup_proxy_mtls" && index == 0 {
			if err := os.Mkdir(filepath.Join(out, "results.json"), 0700); err != nil {
				return err
			}
			return fault
		}
		return nil
	})
	if !errors.Is(err, fault) || !strings.Contains(err.Error(), "benchmark report write:") {
		t.Fatalf("report write failure or original operation failure suppressed: %v", err)
	}
}

func TestReviewBenchmarkSuccessReport(t *testing.T) {
	out := t.TempDir()
	if err := RunBenchmark(out, 16, 1); err != nil {
		t.Fatal(err)
	}
	report := readReviewBenchmark(t, out)
	if report.Status != "PASS" || report.SchemaVersion != 4 || report.Error != "" || report.FailureStage != "" || len(report.Groups) != 10 || len(report.SetupGroups) != 4 || len(report.StallGroups) != 4 || report.WarmupAttempted != 20 || report.RevocationAttempted != 100 || len(report.RevocationNS) != 100 {
		t.Fatalf("successful real benchmark report incomplete: %+v", report)
	}
	seen := map[string]bool{}
	for _, group := range report.SetupGroups {
		key := group.Mode + fmt.Sprint(group.Concurrency)
		if seen[key] || (group.Concurrency != 1 && group.Concurrency != 8) || (group.Mode != "proxy_mtls" && group.Mode != "direct_mtls") || group.Repetition != 1 || len(group.Samples) != 16 || group.Successful != 16 || group.Failures != 0 {
			t.Fatalf("setup samples incomplete or duplicated: %+v", group)
		}
		seen[key] = true
	}
	for _, group := range report.StallGroups {
		if group.PreparationNS <= 0 || group.WindowNS < int64(500*time.Millisecond) || group.PeakObservedActive < 1 || group.PeakObservedActive > 4 || group.FinalActive != 0 || group.Failures != 0 || len(group.Attempts) != group.Concurrency || group.Admitted+group.Denied != group.Concurrency || (group.Concurrency > 4 && group.Denied == 0) {
			t.Fatalf("stalled workloads did not enforce measured bounds: %+v", group)
		}
		var lastAdmittedNS int64
		for _, attempt := range group.Attempts {
			if attempt.TLSSetupNS <= 0 || attempt.ConnectNS <= 0 {
				t.Fatalf("real preparation/CONNECT timing missing: %+v", attempt)
			}
			if attempt.Status == 200 && attempt.ConnectNS > lastAdmittedNS {
				lastAdmittedNS = attempt.ConnectNS
			}
		}
		if group.ReleaseObservedNS < lastAdmittedNS || group.ReleaseObservedNS > lastAdmittedNS+int64(700*time.Millisecond) {
			t.Fatalf("server release was not observed inside the absolute deadline: %+v", group)
		}
		observed := false
		for _, sample := range group.ActiveSamples {
			if sample.Active < 0 || sample.Active > 4 {
				t.Fatalf("sampled admission ceiling exceeded: %+v", sample)
			}
			if sample.Active == 0 && sample.ElapsedNS == group.ReleaseObservedNS {
				observed = true
			}
		}
		if !observed {
			t.Fatalf("server release observation absent from retained samples: %+v", group)
		}
	}
}
