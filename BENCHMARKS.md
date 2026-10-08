# Benchmarks

Run the experiments locally:

```sh
make benchmark-smoke
make benchmark
```

Reports and individual observations are generated under ignored `verification/benchmarks/`. Record your commit, OS/kernel, CPU, memory, filesystem, virtualization, Go version and GOMAXPROCS alongside results. Avoid concurrent test loads. Do not claim a performance result from a smoke check.

## Method

The full socket experiment compares a direct mTLS echo with the gateway path. Both modes run in one process/host. The proxy mode adds CONNECT parsing, authorization, DNS fixture handling, upstream dialing and durable audit writes; the difference measures that bundle rather than one isolated control.

The full run uses five repetitions with 100 samples per group: 5,000 full 1 KiB exchanges at concurrency 1/4/8/16/64 across both modes, and 2,000 setup samples at concurrency 1/8. It also retains 100 warmups, 100 policy revocations and 425 idle-stall attempts. Setup stops at verified mTLS handshake or successful CONNECT headers; exchange includes echo and half-close/EOF. Group wall time includes cleanup/drain. Audit admission/close fsync and policy persistence are enabled.

Stall experiments use identity/global ceilings 4/8, idle/lifetime 200/1000 ms and a fixed 500 ms observation window after prepared TLS connections. Intentional capacity denials are counted separately from failures. Sampled peak active is a lower bound; each group must finish with active zero. Whole-process Go heap and goroutine sampling every 2 ms perturbs timing and does not measure isolated daemon RSS.

Raw samples, repetitions and errors are retained on ordinary returned failures when report storage is writable. Abrupt termination may interrupt report persistence. Quantiles use nearest rank; summary tables show median per-repetition quantiles, not pooled tails or statistical significance. The 16-sample, one-repetition smoke run verifies the pipeline and does not support p95/p99 claims.

The core microbenchmarks separately cover authority parsing, address classification, admission and budget reservations. These are not end-to-end latency measurements. There is no mature-proxy comparison or production workload study.

## Historical developer observation

On 2026-10-07, a developer run using Go 1.27.1 in a disposable Debian 13 VM (4 vCPUs, GOMAXPROCS 4, 6 GiB configured RAM, ext4, WHPX virtualization) completed the full sample counts above. Setup, exchange, warmup and revocation had zero unexpected failures; stalls had 65 admissions and 360 intentional capacity denials, with all groups ending at active zero. Observed revocation p95 was 3.611333 ms across 100 samples.

That observation refers to implementation digest `ac271b1c1a9c1f42f2ff62e242e17b0b9e30327605218cc131ef8e8e1f1cc3f1`. It is a bounded historical developer report, not a public evidence badge or a fresh measurement of your checkout. Reproduce the experiment to evaluate your environment. Local revocation observations cannot promise real-time behavior or retract bytes already forwarded.
