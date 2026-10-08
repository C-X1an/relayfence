# API and configuration v1

## Gateway

TLS 1.3, verified client certificates and HTTP/1.1 are required. The verified leaf must have exactly one URI SAN matching `urn:relayfence:workload:[a-z0-9][a-z0-9-]{0,62}`. Common Name and HTTP headers never select identity.

Only CONNECT is supported. Its request-target is the routing authority; Go normalizes `Request.Host` from that target and discards a contradictory raw Host header. Positive Content-Length or Transfer-Encoding is rejected. Bytes buffered after the headers belong to the tunnel and count against its budget.

Authority syntax is ASCII `hostname:port`. Hostnames normalize to lowercase and lose one terminal root dot. Labels contain 1–63 ASCII letters, digits or hyphens with no leading/trailing hyphen; normalized host length is at most 253 and raw authority length at most 260. Reject IP literals, numeric-only names, names starting `0x`, brackets, Unicode, userinfo, escaping, whitespace and empty labels. Ports are decimal 1–65535 without leading zeroes. Rules match the complete canonical hostname and port.

Before DNS the gateway checks policy and reserves capacity. DNS returns 1–16 addresses **before deduplication**. All must pass the address gate; empty, oversized or mixed prohibited sets are denied. After deduplication and sorting, one literal IP is dialed without retries. Default DNS and dial timeouts are each 3 seconds; HTTP header/handshake timeouts are 5 seconds. `MaxHeaderBytes` is 8 KiB, subject to Go's HTTP parsing-buffer allowance.

Errors before hijack use `{"error":{"code":"policy_denied"}}` with `Connection: close`. TLS authentication failures can occur before any HTTP response.

| Outcome | HTTP status | Code |
|---|---:|---|
| Invalid request | 400 | `bad_request` |
| Invalid verified identity | 403 | `identity_denied` |
| Destination unauthorized | 403 | `policy_denied` |
| Unsupported method | 405 | `method_not_allowed` |
| Capacity full | 429 | `capacity_exceeded` |
| Address set prohibited | 403 | `address_denied` |
| Resolver or dial failed | 502 | `upstream_failed` |
| Stale attachment | 409 | `stale_session` |
| Poisoned/unavailable store or audit | 503 | `unavailable` |

`200 Connection Established` follows identity, policy, address, dial, revision and audit checks. After hijack, failures close sockets; an HTTP error cannot be inserted into an opaque tunnel. Do not blindly retry after uncertain remote side effects.

## Policy

All limits are explicit; this example supplies values rather than relying on implicit defaults:

```json
{
  "schema_version": 1,
  "revision": 1,
  "global_max_active": 64,
  "rules": [{
    "identity": "urn:relayfence:workload:demo",
    "destinations": ["example.com:443"],
    "max_active": 4,
    "max_bytes": 1048576,
    "max_duration_ms": 30000,
    "idle_timeout_ms": 3000
  }]
}
```

| Field/collection | Accepted bound |
|---|---|
| `schema_version` | Exactly 1 |
| `revision` | Positive uint64 |
| `global_max_active` | 1–1024 |
| Rules | At most 1024 unique identities; empty rules deny all |
| Destinations per rule | 1–256 unique canonical authorities |
| `max_active` | 1–256 |
| `max_bytes` | 1–1073741824, shared across both directions |
| `max_duration_ms` | 1–3600000, measured from reservation |
| `idle_timeout_ms` | 1–60000 and no greater than duration |

Policy JSON and update bodies are at most 1 MiB. Installed compact policy plus its terminating newline must also fit 1 MiB. Invalid UTF-8, unknown fields, case aliases, duplicate keys, trailing values and excessive nesting are rejected. Policy validation deep-copies canonical snapshots.

## Local administration

The admin listener is a Unix socket with mode `0600` inside a `0700` directory. Socket access is the authority; it must never be shared with the workload or exposed on a network listener.

`GET /v1/status` returns `{"revision":1,"active":0,"poisoned":false}`. Active includes reserved/pending sessions until release.

`PUT /v1/policy` requires exact `Content-Type: application/json` and a full replacement:

```json
{"expected_revision":1,"policy":{"schema_version":1,"revision":2,"global_max_active":64,"rules":[]}}
```

The next revision must equal expected revision + 1. Success returns status. Stale comparison returns 409/`stale_session`, invalid input 400/`bad_request`, and poison 503/`unavailable`. Unknown routes/methods return 404/`not_found`. Any replacement cancels all sessions. Repeating a successful compare-and-swap returns conflict; read status before preparing another update.

## Audit and CLI

JSONL envelopes contain `event`, `prev` and `hash`. Events contain sequence, UTC RFC3339Nano time, kind and optional session, identity, destination, IP, revision, byte count and reason. Allowed kinds are `allowed`, `denied`, `closed` and `policy`; the current admin handler does not emit policy events. SHA-256 hashes `prev + "\n" + compact_event_json`; the first previous digest is 64 zeroes. Files are capped at 16 MiB. Payloads, certificates and keys are not recorded.

```sh
bin/relayfence serve --listen 127.0.0.1:8443 --cert PATH --key PATH --ca PATH --policy PATH --audit PATH --admin PATH
bin/relayfence demo --out verification/my-fresh-demo
bin/relayfence inspect --audit PATH --out PATH.html
bin/relayfence status --admin PATH
bin/relayfence policy --admin PATH --file update.json
```

The daemon requires certificate, private key and client CA paths. Its default policy/audit/socket paths are `.state/policy.json`, `.state/audit.jsonl` and `.state/admin.sock`. The private key must not be accessible to group/other users. Demo and inspector output must be fresh; existing outputs are not silently overwritten. No API key is needed.
