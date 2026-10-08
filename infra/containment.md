# Disposable Linux containment laboratory

The laboratory tests a particular namespace/firewall topology. Run it only on an authorized disposable Linux host with root, CAP_NET_ADMIN/CAP_SYS_ADMIN, `ip`, `nft`, `setpriv`, `sysctl`, `openssl`, Go and Python 3. Missing prerequisites return exit 77; that is a blocked run, not successful containment.

```sh
RELAYFENCE_DISPOSABLE_HOST=1 make containment
```

The script creates uniquely named workload, gateway and target namespaces, veth interfaces, namespace-local routing/firewall state and temporary PKI. It cleans up its fixtures. It does not change the host's default route, forwarding policy or nftables rules. Never run untrusted code with these privileges.

The capability-free unprivileged workload can reach only the gateway's mTLS port. The gateway runs as another unprivileged UID and reaches an isolated public-shaped IPv4 echo target through deterministic fixture DNS. There is no Internet route. Management and target receivers also expose IPv4/IPv6 TCP, UDP echo and DNS canaries for forbidden direct paths. The target's private IPv6 address is a direct-path canary, not an authorized proxy destination.

Guarded phases require authenticated proxy echo, denied private Unix-socket access and zero workload-origin receiver effects for direct TCP/UDP/DNS attempts. Privileged receiver-side packet observers and application counters distinguish workload traffic from positive gateway TCP/DNS effects. Packet/payload bytes are not retained. A missing reply alone cannot establish containment.

Control acknowledgements drain receiver events for a bounded quiet window. Dead fixtures, observer drops, mismatched phases or missing acknowledgements fail the run. These windows measure observed traffic rather than proving global kernel quiescence; delayed packets can conservatively fail a later phase.

A removed-control phase temporarily enables namespace forwarding, adds fixture-only routes and removes the guarding tables. It requires successful IPv4/IPv6 direct TCP/UDP/DNS replies plus positive receiver counters, then restores the controls and repeats denial tests. Two deliberate negative controls must also be detected: one-way leaks whose replies are blocked, and a dead UDP responder after controls are removed. Unrelated failures cannot count as detected defects.

Successful results apply to this topology and tested source. Production integration needs equivalent routing/firewall constraints, zero workload capabilities, isolated keys/admin state and no host credential mounts or alternate interfaces. Proxy settings alone do not provide containment. See [the threat model](../THREAT_MODEL.md) and [operations guide](../DEPLOYMENT_AND_OPERATIONS.md).
