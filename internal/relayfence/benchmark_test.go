package relayfence

import "testing"

func TestBenchmarkQuantiles(t *testing.T) {
	samples := []BenchmarkSample{{LatencyNS: 30}, {LatencyNS: 10}, {LatencyNS: 20}, {LatencyNS: 999999, Error: "explicit failed sample"}}
	if got := percentile(samples, .5); got != 20 {
		t.Fatalf("median=%d want20", got)
	}
	if got := percentile(samples, .95); got != 30 {
		t.Fatalf("p95=%d want30", got)
	}
	if got := percentile(nil, .5); got != 0 {
		t.Fatalf("empty=%d want0", got)
	}
	if got := percentile([]BenchmarkSample{{Error: "failed"}}, .99); got != 0 {
		t.Fatalf("all-failed=%d want0", got)
	}
}
