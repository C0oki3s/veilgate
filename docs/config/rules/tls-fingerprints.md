# `rules/tls_fingerprints.yaml`

> **File:** `/etc/veilgate/rules/tls_fingerprints.yaml`
> **Reload:** hot-reload (~500 ms).
>
> Database of known JA3 / JA4 fingerprints. Read by the
> `tls_agent` / `tls_bot` / `tls_non_browser` signals. Active only
> when [`tls.enabled: true`](../tls.md) - VeilGate must terminate TLS
> to compute the fingerprints.

**On this page:**

- [`ja4_exact:`](#ja4_exact)
- [`ja4_prefix:`](#ja4_prefix)
- [`ja3_exact:`](#ja3_exact)
- [Confidence and category mapping](#confidence-and-category-mapping)
- [Maintaining the database](#maintaining-the-database)
- [Related](#related)

## File shape

Three lists. Each entry has the same fields apart from the hash type.

```yaml
ja4_exact:
  - hash: t13d1517h2_8daaf6152771_b186095e22b6
    label: python-httpx
    category: agent
    confidence: 95
ja4_prefix:
  - prefix: t13d1517h2
    label: python-stdlib
    category: agent
    confidence: 70
ja3_exact:
  - hash: e7d705a3286e19ea42f587b344ee6865
    label: curl-7.85
    category: agent
    confidence: 90
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `hash` (in `*_exact`) | string | yes | full JA3 MD5 / JA4 string |
| `prefix` (in `ja4_prefix`) | string | yes | first N chars of a JA4 hash, conventionally 10 |
| `label` | string | yes | human-readable identifier |
| `category` | string (enum) | yes | one of `browser`, `agent`, `scanner`, `bot`, `unknown` |
| `confidence` | int | no | 0-100; default 100 if omitted |

## `ja4_exact:`

Full JA4 hashes. Highest-confidence single match. Use for libraries
whose JA4 is stable across versions (Python `requests`, Go
`net/http`, Node `undici`).

## `ja4_prefix:`

First 10 characters of the JA4. The JA4 prefix is far more stable
across library versions than the full hash, so prefix matching is
the right tool for "this client is a Python HTTP library", even when
the exact version drifts.

Empty `prefix` is treated as a wildcard catch-all by the matcher;
don't use it.

## `ja3_exact:`

Legacy JA3 MD5 fingerprints. Less discriminating than JA4 - JA3
hashes the *set* of TLS extensions, JA4 hashes the *prefix*. Keep
`ja3_exact` for older agents and exotic clients that haven't been
fingerprinted in JA4 yet.

## Confidence and category mapping

The detector maps `(category, confidence)` to scoring points
(see [`internal/detector/scorer.go`](../../../internal/detector/scorer.go)):

| Category | Confidence | Signal name | Points |
| --- | --- | --- | --- |
| `agent` / `scanner` | >= 80 | `tls_agent` | 45 |
| `agent` / `scanner` | < 80 | `tls_agent` | 30 |
| `bot` | any | `tls_bot` | 25 |
| `unknown` | any | `tls_non_browser` | 20 |
| `browser` | any | (no signal - these classify as legitimate) | 0 |

> **Note on accuracy.** The shipped database covers the common
> Python / Go / Node / curl / OpenSSL libraries. JA4 hashes drift
> across library versions; the prefix classification is far more
> stable. Best practice is to run in `observe` mode for a week,
> collect real samples from your traffic, and extend the database
> with what you actually see.

## Maintaining the database

Capture a JA4 from production traffic via the live event store:

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT ja4, user_agent, COUNT(*) AS n
     FROM events
     WHERE ja4 != ''
     GROUP BY ja4
     ORDER BY n DESC
     LIMIT 30"
```

For each high-volume JA4 you do not recognize:

1. Look up the User-Agent in the same row to identify the client.
2. Decide the category (`browser` if it's a real browser drift,
   `agent` if it's a library, `scanner` if it's a known scanning
   tool).
3. Append to the appropriate section in the YAML and let the
   hot-reload pick it up.

## Example

```yaml
ja4_prefix:
  - prefix: t13d1715h2
    label: chrome-stable
    category: browser
    confidence: 95
  - prefix: t13d1517h2
    label: python-httpx
    category: agent
    confidence: 90
  - prefix: t13d301h2
    label: go-net-http
    category: agent
    confidence: 85
ja4_exact:
  - hash: t13d1715h2_acb858a92679_5e10d2a5810e
    label: chrome-130
    category: browser
    confidence: 100
ja3_exact:
  - hash: 19e29534fd49dd27d09234e639c4057e
    label: nikto
    category: scanner
    confidence: 95
```

## Related

- [`tls:`](../tls.md) - TLS termination at the proxy
- [`rules/detector.yaml` -> suspicious_user_agents](detector.md#suspicious_user_agents)
  - paired UA-based detection
- [Use case: LLM-agent defense](../../usecases/llm-agent-defense.md)

---

*Previous: [`rules/injection_strategy.yaml`](injection-strategy.md) | Next: [`rules/ip_reputation.yaml`](ip-reputation.md)*
