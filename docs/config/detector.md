# `detector:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `detector:`
> **Reload:** restart required.
>
> The detector's *rule* logic (UA substrings, header tiers, timing,
> toolchain, injection markers) lives in
> [`rules/detector.yaml`](rules/detector.md). This page documents only
> the top-level keys - thresholds, honeypot paths, and trust lists.

**On this page:**

- [`score_tarpit_threshold`](#score_tarpit_threshold)
- [`score_challenge_threshold`](#score_challenge_threshold)
- [`window_seconds`](#window_seconds)
- [`probe_paths`](#probe_paths)
- [`trusted_ips`](#trusted_ips)
- [`trusted_proxies`](#trusted_proxies)
- [Example](#example)
- [Related](#related)

## Parameters

### `score_tarpit_threshold`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `70` |

Score at which a request is diverted to the tarpit (only when `mode:
"tarpit"`). Range `0-100`.

---

### `score_challenge_threshold`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `40` |

Score at which a JS proof-of-work challenge is served (in `challenge`
or `tarpit` mode). Must be <= `score_tarpit_threshold`.

> **Tuning.** See the [observe-and-tune how-to](../how-to/observe-and-tune.md).
> Defaults are calibrated against a synthetic agent corpus and should
> always be re-checked against your real traffic.

---

### `window_seconds`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `90` |

Rolling per-client window the detector uses for history-aware signals
(timing variance, toolchain, path-bruteforce, UA rotation). Larger
windows give more evidence per signal but slow down detection of
fresh attackers.

Common values:

- `60`-`90` - default. Fast detection on a busy site.
- `120`-`300` - for low-volume APIs where the per-client request rate
  is low.

---

### `probe_paths`

| Type | Required | Default |
| --- | --- | --- |
| list of strings | no | a curated set (see below) |

Paths that, when requested, immediately add `+50` (first hit) or `+80`
(repeated hits) to the score. These are the highest-confidence single
signal in the system: real users never request them.

Default list (fallback when omitted):

```yaml
probe_paths:
  - /admin-panel-v2
  - /api/internal/debug
  - /.git/config
  - /.env.backup
  - /wp-admin-old
  - /phpmyadmin-backup
```

Add app-specific paths an attacker would expect to find:

```yaml
probe_paths:
  - /admin-panel-v2
  - /api/internal/debug
  - /api/v1/internal/keys
  - /backups/db.sql
  - /.git/config
```

> **Important.** Never list a path that your real app actually serves
> - every request to a honeypot triggers the highest-priority signal.

---

### `trusted_ips`

| Type | Required | Default |
| --- | --- | --- |
| list of strings | no | `[]` |

Client identifiers (typically resolved IPs) that bypass scoring
entirely. Use for your own scanners, monitoring, CI/CD, internal
status pinger, and any partner whose traffic looks library-shaped but
is legitimate.

```yaml
trusted_ips:
  - 192.0.2.10        # internal monitoring
  - 198.51.100.5      # CI runner
  - 203.0.113.0/24    # not yet supported as CIDR - listed individually for now
```

> **Format.** Today the matcher does exact-string compare against the
> resolved client identifier. CIDR support is a roadmap item; until
> then, list addresses one by one.

---

### `trusted_proxies`

| Type | Required | Default |
| --- | --- | --- |
| list of strings (CIDR or IP) | no | `[]` |

CIDRs (or exact IPs) whose `X-Forwarded-For` header VeilGate honors.
**Without this list, VeilGate refuses to read XFF.** That is a
deliberate Log4Shell-injection defense - an attacker who can write
into XFF can otherwise spoof themselves onto the trusted-IP allowlist
or pollute tracker state.

```yaml
trusted_proxies:
  - 10.0.0.0/8           # CNI pod CIDR if you front VeilGate from inside K8s
  - 192.168.0.0/16
  - 172.16.0.0/12
```

When XFF is present and the *direct* peer is inside one of these
CIDRs, VeilGate walks the XFF chain right-to-left and picks the first
hop that is **not** itself a trusted proxy. That's the standards-compliant
RFC 7239 behavior.

## Example

```yaml
detector:
  score_tarpit_threshold: 70
  score_challenge_threshold: 40
  window_seconds: 90
  probe_paths:
    - /admin-panel-v2
    - /api/internal/debug
    - /.git/config
  trusted_ips:
    - 198.51.100.5
  trusted_proxies:
    - 10.0.0.0/8
```

## Related

- [`rules/detector.yaml`](rules/detector.md) - actual signal definitions
- [`rules/ip_reputation.yaml`](rules/ip-reputation.md) - CIDR categories
- [`rules/ml.yaml`](rules/ml.md) - ML signal that contributes to the score
- [How-to: Observe-mode rollout](../how-to/observe-and-tune.md)

---

*Previous: [`tls:`](tls.md) | Next: [`tarpit:`](tarpit.md)*
