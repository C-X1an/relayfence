# Limitations

RelayFence is an experimental engineering reference with no stable release, production security audit, availability SLA or certified capacity.

- It controls traffic through one gateway process. A workload can bypass it through another route unless equivalent host containment is applied and tested.
- CONNECT is opaque. There is no HTTP path policy, inner TLS verification, credential insertion, semantic tool authorization or prompt-injection detection. An allowed endpoint can relay traffic elsewhere.
- Policy, sessions and quotas are local to one process. There is no distributed quota, high availability, multi-region consistency or tenant kernel isolation.
- Every policy replacement terminates every session. Revocation cannot retract already-forwarded or kernel-buffered bytes. Certificate validity is checked at TLS establishment; tunnel lifetime and policy cancellation bound established sessions, with no continuous CRL/OCSP monitoring.
- Short writes can consume unused byte reservations. Authenticated admission caps include pending work but do not fully defend against unauthenticated SYN/TLS floods.
- The IP classifier deliberately denies some special globally reachable ranges. It is neither a permanently current address registry nor a route/NAT reachability oracle. There is one dial candidate and no retry.
- Local policy durability assumes a suitable local filesystem. Audit files stop at 16 MiB and need operator-managed offline rotation. Hash chains do not prevent privileged rewriting or valid-prefix truncation.
- The demo and benchmarks use labelled loopback DNS fixtures. Synthetic same-process timings are not production usage, Internet behavior, isolated daemon RSS or a comparison with mature proxies.
- The containment laboratory covers its specific Linux topology. Arbitrary firewall managers, extra interfaces, privileged workloads, host mounts and other operating systems need their own integration review and tests.

Read [THREAT_MODEL.md](THREAT_MODEL.md) and [DEPLOYMENT_AND_OPERATIONS.md](DEPLOYMENT_AND_OPERATIONS.md) for assumptions and operational constraints.
