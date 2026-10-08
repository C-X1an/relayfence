# RelayFence

An experimental single-host mTLS egress gateway for autonomous tools.

RelayFence accepts HTTP/1.1 CONNECT tunnels from authenticated workload identities. It authorizes an exact hostname and port before DNS, validates every returned address, then dials one checked literal IP. Revisioned policy replacement cancels pending and connected sessions. Admission limits, a shared bidirectional byte budget, idle/lifetime deadlines and synchronous audit records bound each tunnel.

The runtime uses Go's standard library. No model API, cloud account or external dataset is required.

## Try it locally

Use Linux, Go 1.27.1, Python 3.11+, Git and make. Use a supported Go security patch for deployment; the public CI baseline is Go 1.27.1. Windows users should use WSL2 or a Linux VM for the Unix administration socket. Race testing also needs a C compiler.

```sh
git clone https://github.com/C-X1an/relayfence.git
cd relayfence
make bootstrap
make verify
make demo
make inspect
```

`make build` produces `bin/relayfence`. The demo uses real TLS and TCP sockets, ephemeral certificates and an explicitly labelled loopback DNS fixture. It asserts allowed echo, destination denial and live revocation, then writes an escaped HTML audit view. Generated demo and benchmark outputs stay under ignored `verification/`; `make inspect` reports the latest demo view.

`make verify` runs the public build, formatting, static, Go test, race and source-audit checks. It does not run the privileged containment laboratory or establish production readiness. For a fresh-clone reproduction, commit your changes and run `make clean-verify`.

## Boundary and scope

A workload with another network route can bypass the proxy. The separate [Linux containment laboratory](infra/containment.md) tests direct TCP, UDP and DNS attempts using namespaces, capability removal and receiver observations. Proxy environment variables alone provide no containment.

CONNECT payloads are opaque. An allowed endpoint can relay data elsewhere; RelayFence does not authorize HTTP paths, inspect inner TLS, detect prompt injection or supply distributed quotas. Policy replacement closes every existing session, including unchanged grants. Already-forwarded bytes cannot be recalled. The local audit hash chain cannot defeat a privileged writer who replaces the records.

## Explore the implementation

| Area | Source |
|---|---|
| Identity, DNS checks and relay | `internal/relayfence/gateway.go`, `address.go` |
| Policy, admission and revocation | `internal/relayfence/policy.go`, `store.go` |
| Shared byte reservations | `internal/relayfence/budget.go` |
| Local administration and audit | `internal/relayfence/admin.go`, `audit.go` |
| Real-socket tests and experiments | `internal/relayfence/*_test.go`, `tests/`, `cmd/relaybench/` |

Read the [architecture](ARCHITECTURE.md), [API contract](API_SPEC.md), [threat model](THREAT_MODEL.md), [limitations](LIMITATIONS.md), [operations guide](DEPLOYMENT_AND_OPERATIONS.md) and [benchmark method](BENCHMARKS.md). See [CONTRIBUTING.md](CONTRIBUTING.md) for development and [SECURITY.md](SECURITY.md) for vulnerability reporting.

Original source is licensed under [MIT](LICENSE). This is an engineering reference project with no stable release or production security warranty.
