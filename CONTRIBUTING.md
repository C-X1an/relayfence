# Contributing

Read the [architecture](ARCHITECTURE.md), [API contract](API_SPEC.md) and [threat model](THREAT_MODEL.md) before changing behavior. Use a branch and keep changes focused. Document protocol, schema and error-envelope changes explicitly.

```sh
make bootstrap
make fmt
make verify
```

For security or concurrency changes, also run `make fuzz` and `make mutation`. Mutation checks use disposable copies and require deliberate defects to fail their targeted tests. Run privileged `make containment` only on an authorized disposable Linux host. Commit changes before `make clean-verify` so the fresh clone contains the code being checked. A performance claim needs `make benchmark`; `make benchmark-smoke` only checks the experiment pipeline.

Preserve meaningful failure assertions. Do not remove assertions, skip failing tests or replace real integration traffic with mocks to make checks pass. New tests should assert upstream effects and session cleanup, not only HTTP status strings.

Keep generated reports under ignored `verification/` and review them before making claims. Do not commit credentials, private data, keys or real workload logs. Use [SECURITY.md](SECURITY.md) for sensitive reports. Check licenses before adding dependencies or copied material; contributions use the repository's MIT license.
