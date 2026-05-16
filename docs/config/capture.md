# `capture:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `capture:`
> **Reload:** restart required.

Optional JSONL capture of every request - score, decision, signals.
Distinct from [`persist:`](persist.md), which is the structured SQLite
store. Capture is intended for offline ML research; **default is off.**

**On this page:**

- [`enabled`](#enabled)
- [`path`](#path)
- [`max_mb`](#max_mb)
- [`retention_hours`](#retention_hours)
- [`janitor_every`](#janitor_every)
- [`file_mode`](#file_mode)
- [`scrub`](#scrub)
- [Privacy considerations](#privacy-considerations)
- [Example](#example)
- [Related](#related)

## Parameters

### `enabled`

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

When `true`, the proxy writes one JSONL line per request to `path`.
Default is **off** - turning capture on creates a new data store with
its own privacy considerations.

---

### `path`

| Type | Required if enabled | Default |
| --- | --- | --- |
| string (file path) | yes | - |

JSONL file path. Parent directory is created at 0700; the file at
0600 (configurable via `file_mode`). Recommended:
`/var/lib/veilgate/requests.jsonl`.

---

### `max_mb`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `100` |

Rotate the file when it exceeds this size in megabytes. The current
file is renamed to `<path>.1`; a fresh file is created at `path`. Only
one rotated copy is kept - the next rotation overwrites it.

---

### `retention_hours`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `0` (disabled) |

When non-zero, the janitor goroutine deletes rotated capture files
older than this many hours, and truncates the live file once it would
otherwise outlive retention.

`0` disables time-based pruning; only size-based rotation remains.

For any deployment that handles real production traffic, set this.
Common values: `168` (7 days), `720` (30 days), `24` (1 day for
research environments).

---

### `janitor_every`

| Type | Required | Default |
| --- | --- | --- |
| string (Go duration) | no | `1h` when retention is set |

How often the janitor sweeps. Accepts Go-style duration strings:
`30m`, `1h`, `6h`, `24h`. Empty defaults to one hour when
`retention_hours` is non-zero.

---

### `file_mode`

| Type | Required | Default |
| --- | --- | --- |
| int (octal) | no | `0600` |

POSIX file mode applied to the live and rotated capture files. Default
is `0o600` (owner read/write only). Set to `0o644` only if you need a
log-shipping agent running under a different UID to read the file.

```yaml
capture:
  file_mode: 0o600
```

---

### `scrub`

| Type | Required | Default |
| --- | --- | --- |
| list of `{regex, replace}` | no | `[]` |

A list of regex / replacement pairs applied to each JSONL line *before
write*. Use this for obvious-PII shapes that you don't want on disk:
Bearer tokens in the `Authorization` header, `password=` query
parameters, etc.

```yaml
capture:
  scrub:
    - regex: "(?i)bearer [a-z0-9._\\-]+"
      replace: "bearer <redacted>"
    - regex: "(?i)password=[^&\"]+"
      replace: "password=<redacted>"
    - regex: "(?i)\"authorization\":\"[^\"]+\""
      replace: "\"authorization\":\"<redacted>\""
```

Bad regexes are silently dropped at startup - a typo doesn't take the
proxy down. Verify with the journal log immediately after a config
change.

## Privacy considerations

Capture is opt-in for a reason. When enabled, each line carries:

- timestamp, client identifier
- HTTP method, raw URL path (after the proxy's view, before redaction)
- User-Agent, Referer, Accept-* headers
- JA3, JA4 when TLS is on
- score + signal names + decision

The line **does not** carry request bodies, query values (only
presence), header values beyond the named fields, or response payloads.

For deployments under GDPR / HIPAA / similar:

- Keep capture **off** in production.
- Enable it only in a quarantined research environment that mirrors
  prod traffic with the same data classification.
- Always set `retention_hours` and `scrub` rules.
- Pair with the [`veilgate forget` how-to](../how-to/handle-rtbf.md)
  for deletion requests.

## Example

```yaml
capture:
  enabled: false                    # production default

# Research / ML-training environment:
# capture:
#   enabled: true
#   path: /var/lib/veilgate/requests.jsonl
#   max_mb: 500
#   retention_hours: 168              # 7 days
#   janitor_every: 1h
#   file_mode: 0o600
#   scrub:
#     - { regex: "(?i)bearer [a-z0-9._\\-]+", replace: "bearer <redacted>" }
#     - { regex: "(?i)password=[^&\"]+",       replace: "password=<redacted>" }
```

## Related

- [`persist:`](persist.md) - structured SQLite store (different surface)
- [Use case: Compliance & audit evidence](../usecases/compliance-evidence.md)
- [How-to: Handle a Right-to-Erasure (RTBF) request](../how-to/handle-rtbf.md)
- [Model card](../model/README.md) - what features the ML actually trains on

---

*Previous: [`persist:`](persist.md) | Next: [Rules: `detector.yaml`](rules/detector.md)*
