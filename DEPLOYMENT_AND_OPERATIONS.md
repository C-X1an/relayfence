# Deployment and operations

## Local development

Use Linux, Go 1.27.1, Python 3.11+, Git and make; race tests need a C compiler. Use a supported Go security patch for deployment and review the CI pin when upgrading. Windows users should use WSL2/Linux for the Unix administration socket. Core verification/demo requires no external service credentials.

```sh
make bootstrap
make verify
make demo
make inspect
make benchmark-smoke
```

Build output is `bin/relayfence`. Generated demo/benchmark reports live under ignored `verification/`. `make clean-verify` clones the committed source into a fresh temporary checkout and verifies there; commit the changes you intend to reproduce first. Full socket experiments use `make benchmark`. Privileged containment and online vulnerability checks are separate commands.

## Run a daemon

Provision your own CA, server certificate and client certificate with the [required URI identity](API_SPEC.md). Keep the CA private key outside the service/workload environment. The client validates the gateway server certificate; the gateway trusts the configured client CA. Use separate server/client EKUs and short client lifetimes. This version requires restart for server certificate or CA rotation.

Create a private state directory and a complete policy such as the example in [API_SPEC.md](API_SPEC.md). Set directory mode `0700` and key/policy/audit files `0600`.

```sh
bin/relayfence serve \
  --listen 127.0.0.1:8443 \
  --cert /var/lib/relayfence/server.crt \
  --key /var/lib/relayfence/server.key \
  --ca /var/lib/relayfence/client-ca.crt \
  --policy /var/lib/relayfence/policy.json \
  --audit /var/lib/relayfence/audit.jsonl \
  --admin /var/lib/relayfence/admin.sock
```

The [systemd example](infra/relayfence.service) runs an unprivileged `relayfence` account, restricts capabilities and filesystem writes, and supplies memory/task/descriptor limits. Provision that account, install the reviewed binary at `/usr/local/bin/relayfence` and create the state directory before using it. Review its loopback bind and certificate names for your topology. Remote workloads need an explicit private interface and firewall rules; do not expose a public demo proxy. Keep the Unix admin socket inaccessible to workloads.

## Policy and monitoring

```sh
bin/relayfence status --admin /var/lib/relayfence/admin.sock
bin/relayfence policy --admin /var/lib/relayfence/admin.sock --file update.json
```

Status exposes revision, active reservations and poisoned state. Use a full compare-and-swap policy update with the next revision. Removing an identity revokes its grant; every replacement also closes all other sessions. On conflict, read current status before creating another update.

Monitor capacity denials, setup failures, audit failures and close reasons. `poisoned:true` requires investigation; repeated restarts do not repair corrupt state. Audit records contain identity/destination metadata but no payload. Keep real logs private. Audit reaches a hard 16 MiB bound; schedule rotation before that limit. Retention is operator-managed, with no automatic pruning.

## Recovery and upgrades

Stop the service before editing state. Preserve ambiguous/corrupt files privately. Restore a validated policy using a new revision and correct permissions. Archive a broken/full audit rather than silently truncating it; record the operational discontinuity before starting a new chain. Verify status after restart. Recovery cannot roll back network effects.

Upgrade on a stopped service after running relevant tests and `make security-online`. Keep binary rollback schema-compatible; unknown policy schema refuses startup. The persistence protocol relies on local filesystem rename/fsync behavior and does not prove physical power-loss durability.

## Containment and CI

The [containment laboratory](infra/containment.md) requires an authorized disposable Linux host with root and namespace capabilities. Run it separately from ordinary development and from untrusted pull requests. Missing prerequisites return a blocked/nonzero result, never a successful containment assertion.

Public CI uses hosted unprivileged runners, restricted checkout credentials, real tests, vulnerability scanning and CodeQL. Generated CI artifacts should contain only synthetic test outputs. Never provide production keys, private logs or privileged host access to forked PR jobs. Host limits and firewall protection remain necessary for pre-authentication floods.
