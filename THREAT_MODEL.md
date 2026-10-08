# Threat model

The protected assets are destination authorization, workload identity, policy generation, connection/byte budgets and audit continuity. The workload, DNS answers and upstream endpoints are untrusted. The local operator, CA, kernel and Go TLS stack are trusted. Theft of a valid client key compromises that identity; same-user/root access can control local administration and state.

| Threat | Control | Residual risk |
|---|---|---|
| Spoofed identity | Verified mTLS chain and exactly one accepted URI SAN | Stolen valid keys remain usable until policy revocation; no continuous CRL/OCSP check |
| Authority confusion | One strict ASCII parser; exact canonical hostname/port | Inner TLS/SNI or endpoint tenants are not inspected |
| DNS rebinding or mixed answers | Validate the whole set once; dial a checked literal IP | Public attacker-controlled endpoints and routing/NAT behavior remain operator concerns |
| Special-purpose address access | Conservative IPv4/IPv6 classifier and unmapping | Registry assignments can change; this is not a reachability oracle |
| Revocation during DNS/dial/attach | Serialized reservation and revision attachment; session cancellation | Bytes already delivered or handed to the OS cannot be recalled |
| Concurrent quota overshoot | Serialized admission; atomic shared byte reservations; release once | Short writes can consume quota without forwarding it |
| Slow peers and exhaustion | Active caps, fixed buffers, DNS/dial/header/idle/lifetime timeouts | Unauthenticated SYN/TLS floods need host firewall and resource controls |
| Audit/storage failure | Sync admission before payload; poison and cancel on failure; atomic policy replacement | Local filesystem durability assumptions; later close failure cannot undo traffic |
| Audit tampering | Verify sequence and local hash chain before append/inspection | Privileged rewrite or valid-prefix truncation is not detected without external anchoring |
| Direct network bypass | Separate namespace/firewall/capability containment profile | Proxy-only operation leaves alternate routes; kernel/root compromise is out of scope |
| Admin exposure | Private Unix socket in private directory; bounded strict JSON | Same-user processes remain trusted administrative actors |
| Stored HTML injection | Verify audit first and use escaped static templates | Browser security remains a separate dependency |
| Supply-chain compromise | Standard-library runtime, pinned CI actions and vulnerability checks | Toolchain and scanner/action maintenance remain necessary |

An authorized remote endpoint can act as a relay or receive exfiltrated data. The gateway cannot solve semantic authorization through opaque CONNECT. Review endpoint ownership and grant only the destinations needed by each workload.

Tests use owned synthetic fixtures and real local sockets. Address, authentication, revision and budget mutants run in disposable copies and must be detected. The containment experiment observes receiver effects and includes removed-control positive tests. Local fixture results do not establish Internet-wide DNS security or universal host isolation.
