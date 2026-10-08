# Security policy

RelayFence is an experimental single-host gateway with no stable release. It is not an audited production security boundary. Read [THREAT_MODEL.md](THREAT_MODEL.md) and [LIMITATIONS.md](LIMITATIONS.md) before deployment. Keep client authentication mandatory and the administration socket private.

Use [private vulnerability reporting](https://github.com/C-X1an/relayfence/security/advisories/new) if available; otherwise contact the maintainer through the [GitHub profile](https://github.com/C-X1an) without sending secrets or exploit details publicly. Public issues should contain only non-sensitive reproductions. Include the affected commit/version, expected behavior, observed effect and minimal reproduction.

The CI baseline is Go 1.27.1. Review supported Go security patches and run `make security-online` after toolchain or dependency changes. There is no support SLA or vulnerability bounty.

Never commit private keys, credentials or real workload audit logs. Demo keys are ephemeral. Audit records include identity and destination metadata; protect them even though they contain no payloads. A local SHA-256 chain detects ordinary edits but offers no signed attestation or protection against a privileged writer replacing or truncating the chain.
