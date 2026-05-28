# `rules/signals.yaml`

> **File:** `<rules_dir>/signals.yaml`  
> **Reload:** hot-reload via fsnotify (~500 ms debounce).
>
> Controls which detection signals are active, how many points they contribute,
> and lets you define entirely new detection rules without writing Go code.
> A missing file is not an error — VeilGate treats it as an empty registry
> (all signals enabled, all using config.yaml default points).

**On this page:**

- [File structure](#file-structure)
- [Turning signals on and off](#turning-signals-on-and-off)
- [Overriding signal points](#overriding-signal-points)
- [Writing custom signals](#writing-custom-signals)
  - [Condition types](#condition-types)
  - [AND logic](#and-logic)
  - [Case sensitivity](#case-sensitivity)
- [How signals flow into the score](#how-signals-flow-into-the-score)
- [Built-in signal reference](#built-in-signal-reference)
- [Validation](#validation)
- [Related](#related)

---

## File structure

`signals.yaml` has two top-level keys:

```yaml
signals:          # built-in signal registry
  <signal_name>:
    enabled: true
    points: 0     # 0 = keep config.yaml default
    description: "..."

custom_signals:   # operator-defined detection rules
  - name: my_rule
    ...
```

Both keys are optional. A completely empty file is valid and equivalent to
the defaults (all built-in signals enabled, no custom signals).

---

## Turning signals on and off

Add an entry under `signals:` with `enabled: false`. The signal stops
contributing to the score immediately after the hot-reload; no restart needed.

```yaml
signals:

  # Suppress the ML signal while you retrain the model.
  ml_agent_score:
    enabled: false

  # Suppress Brotli check — your CDN strips the br hint before the request
  # reaches VeilGate, causing false positives.
  ae_browser_no_br:
    enabled: false
```

**Default behavior when a signal is not listed:**  
Signals absent from the registry are treated as `enabled: true` with
config.yaml default points. You only need to list signals you want to change.

**Re-enabling a signal** is done by either removing the entry or setting
`enabled: true`. Both are equivalent.

---

## Overriding signal points

Set `points: N` on any entry. This replaces the default weight loaded from
`config.yaml` for that signal only. All other signals keep their defaults.

```yaml
signals:

  # Treat honeypot hits as an instant tarpit trigger (score typically
  # reaches 80 on first hit + other signals).
  honeypot_hit:
    enabled: true
    points: 100

  # Reduce empty_ua weight — your internal health-check client omits UA
  # and generates constant low-level noise.
  empty_ua:
    enabled: true
    points: 5

  # Raise injection_marker — your app's tarpit threshold is 60 and a
  # single SQLi attempt should be enough to route to tarpit.
  injection_marker:
    enabled: true
    points: 65
```

Setting `points: 0` (or omitting the key) means "keep the config.yaml
default." You cannot use `signals.yaml` to set a signal to zero points and
still have it fire — use `enabled: false` to silence it instead.

---

## Writing custom signals

Custom signals let you add detection rules that are specific to your
deployment without recompiling VeilGate. They live under `custom_signals:`
as a YAML list. Each entry fires when **all** of its conditions match.

### Minimal example

```yaml
custom_signals:
  - name: php_ext_probe
    description: "PHP extension requested on a Node.js service"
    enabled: true
    points: 10
    conditions:
      - type: path_suffix
        value: .php
```

### Required fields

| Field | Type | Notes |
| --- | --- | --- |
| `name` | string | Unique identifier. Appears in logs, metrics, and API response. |
| `enabled` | bool | `false` silences the signal without removing it. |
| `points` | int | Must be ≥ 1. A value of 0 is treated as disabled. |
| `conditions` | list | At least one condition required. Empty list never fires. |

`description` is optional but recommended — it becomes the `reason` field
in score output and appears in audit logs.

---

### Condition types

Every condition has a `type` and either a `value`, a `name`, or both,
depending on the type.

#### `path_prefix`

Fires when the request path starts with `value`.

```yaml
- type: path_prefix
  value: /internal/
```

Matches `/internal/debug`, `/internal/metrics`, etc.

---

#### `path_contains`

Fires when the request path contains `value` as a substring.

```yaml
- type: path_contains
  value: backup
```

Matches `/files/backup.sql`, `/db/backup-2024.tar.gz`, etc.

---

#### `path_suffix`

Fires when the request path ends with `value`.

```yaml
- type: path_suffix
  value: .php
```

Matches `/wp-login.php`, `/admin/setup.php`, etc.

---

#### `path_regex`

Fires when the request path matches the Go regular expression in `value`.
This is the only condition type that is **case-sensitive by default**. Add
`(?i)` at the start of the pattern for case-insensitive matching.

```yaml
- type: path_regex
  value: ^/v[0-9]+/admin
```

Matches `/v1/admin`, `/v12/admin/users`, etc. Does not match `/api/admin`.

```yaml
- type: path_regex
  value: (?i)^/api/.+/export$
```

Invalid patterns are silently ignored — the condition never matches and
the signal does not fire. Validate your patterns with `go tool regexp` or
the [Go playground](https://go.dev/play) before deploying.

---

#### `ua_contains`

Fires when the `User-Agent` header contains `value`.

```yaml
- type: ua_contains
  value: python-requests
```

Matches `python-requests/2.31.0` and similar.

---

#### `header_present`

Fires when the named header is present in the request, regardless of value.
Use `name:` (not `value:`).

```yaml
- type: header_present
  name: X-Debug-Token
```

Header name matching follows Go's canonical form (`X-Debug-Token` is the
same as `x-debug-token`).

---

#### `header_value`

Fires when the named header contains `value` as a substring.
Both `name:` and `value:` are required.

```yaml
- type: header_value
  name: Content-Type
  value: multipart
```

Matches `multipart/form-data; boundary=----WebKit`, etc.

---

#### `query_contains`

Fires when the raw query string contains `value` as a substring.

```yaml
- type: query_contains
  value: debug=1
```

Matches `/api/data?debug=1&page=2`.

---

#### `method`

Fires when the HTTP method equals `value`. Case-insensitive.

```yaml
- type: method
  value: DELETE
```

Matches `DELETE` and `delete`.

---

### AND logic

All conditions in a single custom signal must match simultaneously for the
signal to fire. To model OR logic, define multiple custom signals with the
same `points` value.

```yaml
custom_signals:

  # Flag PHP probing OR ASP.NET probing (two separate signals, OR effect)
  - name: php_probe
    enabled: true
    points: 10
    conditions:
      - type: path_suffix
        value: .php

  - name: aspnet_probe
    enabled: true
    points: 10
    conditions:
      - type: path_suffix
        value: .aspx

  # Flag non-GET to a read-only API (AND: both conditions must match)
  - name: api_write_attempt
    description: "Non-GET to read-only public API"
    enabled: true
    points: 15
    conditions:
      - type: path_prefix
        value: /api/v1/public/
      - type: method
        value: POST
```

---

### Case sensitivity

| Condition type | Case handling |
| --- | --- |
| `path_prefix`, `path_contains`, `path_suffix` | case-insensitive |
| `path_regex` | case-sensitive (add `(?i)` for insensitive) |
| `ua_contains` | case-insensitive |
| `header_present` | case-insensitive (canonical header form) |
| `header_value` | case-insensitive |
| `query_contains` | case-insensitive |
| `method` | case-insensitive |

---

## How signals flow into the score

Understanding the pipeline helps when writing and debugging rules.

```
HTTP request
     │
     ▼
 Built-in signals evaluated
 (header shape, timing, toolchain, TLS, ML, honeypot, etc.)
     │
     ▼
 Custom signals evaluated  ← scoreCustomSignals()
 (all entries in custom_signals:, AND logic per entry)
     │
     ▼
 applySignalConfig()
 ├── Drop signals with enabled: false in signals.yaml
 └── Replace points for signals with points: N override
     │
     ▼
 Total = sum of remaining signal points, capped at 100
     │
     ▼
 Score returned to proxy routing logic
```

**Hot-reload behavior:**  
When `signals.yaml` changes on disk, the watcher re-parses the file and
calls `scorer.SetSignals(newRegistry)` atomically. Requests already
in-flight complete with the old registry. Requests arriving after the
swap use the new registry. If parsing fails, the old registry remains
active and VeilGate logs a warning — it never drops to an unconfigured
state.

**Regex precompilation:**  
`path_regex` patterns are compiled once when `SetSignals` is called, not
on every request. Invalid patterns are silently dropped at that point.
After a hot-reload with a corrected pattern the compiled regex replaces
the broken one.

---

## Built-in signal reference

All built-in signal names valid for use under `signals:`.

| Signal | Group | What it detects |
| --- | --- | --- |
| `empty_ua` | Header shape | No User-Agent header |
| `suspicious_ua` | Header shape | Known tool/scanner/library UA substring |
| `sparse_headers` | Header shape | Missing browser-typical headers (Accept-Language, Sec-Fetch-*, Sec-Ch-Ua) |
| `sec_fetch_absent` | Browser consistency | Browser-shaped UA but all three Sec-Fetch-* headers absent |
| `sec_fetch_partial` | Browser consistency | Browser-shaped UA but only 1–2 of the Sec-Fetch-* triple present |
| `ae_browser_empty` | Browser consistency | Browser-shaped UA but no Accept-Encoding at all |
| `ae_browser_no_br` | Browser consistency | Browser-shaped UA but Accept-Encoding lacks `br` (brotli) |
| `h3_mismatch` | Browser consistency | Browser-shaped UA but never upgraded to HTTP/3 after Alt-Svc hints |
| `regular_timing` | Timing | Suspiciously uniform inter-request gaps (LLM/test-harness cadence) |
| `toolchain_full` | Toolchain | All three pentest stages observed: recon + probe + exploit |
| `toolchain_partial` | Toolchain | Two pentest stages observed |
| `toolchain_hmm` | Toolchain | Ordered recon→probe→exploit sequence observed |
| `toolchain_hmm_partial` | Toolchain | Ordered two-stage subsequence observed |
| `path_bruteforce` | Path/payload | Many distinct paths hit inside the rolling window |
| `wordlist_path` | Path/payload | Path matches a known scanner wordlist entry |
| `injection_marker` | Path/payload | SQLi, XSS, SSRF, RCE, Log4Shell, path traversal payload in request |
| `oob_interaction` | Path/payload | Out-of-band callback host referenced (Burp Collaborator, interactsh, etc.) |
| `encoding_chain` | Path/payload | Double or triple URL-encoding (`%25XX`) — WAF bypass technique |
| `ip_reputation` | IP/rotation | Client IP in known-bad CIDR (cloud egress, Tor, datacenter range) |
| `ip_rotation_fleet` | IP/rotation | Multiple IPs sharing same behavioral fingerprint — proxy pool rotation |
| `ua_rotation` | IP/rotation | One IP sent requests under many distinct User-Agent strings |
| `tls_agent` | TLS/H2 | JA4/JA3 TLS fingerprint matches known HTTP library or scanner |
| `tls_bot` | TLS/H2 | JA4/JA3 fingerprint matches known crawler/monitoring bot |
| `tls_non_browser` | TLS/H2 | TLS fingerprint looks library-shaped without a named match |
| `h2_agent` | TLS/H2 | HTTP/2 SETTINGS fingerprint matches known agent library |
| `h2_bot` | TLS/H2 | HTTP/2 SETTINGS fingerprint matches known bot |
| `h2_non_browser` | TLS/H2 | HTTP/2 SETTINGS looks library-shaped |
| `graph_flat` | Session/behavioral | Many requests but zero subresource Sec-Fetch-Dest values (flat crawler topology) |
| `graph_doc_heavy` | Session/behavioral | Document fetches outnumber subresource fetches 4:1 or more |
| `cookie_stateless` | Session/behavioral | 10+ requests with no Cookie header despite Set-Cookie responses |
| `fanout_high` | Session/behavioral | 60+ distinct paths in the last 60 seconds |
| `fanout_extreme` | Session/behavioral | 200+ distinct paths in the last 60 seconds |
| `recovery_pivot` | Session/behavioral | Previous response was 4xx and next request changed both path and method |
| `bundle_mining` | Session/behavioral | JS bundle fetched then multiple /api/* requests with no HTML navigation |
| `canary_replay` | Deception feedback | Tarpit-served canary token resubmitted in a later request |
| `header_mutation` | Session/behavioral | Stable-header presence bitmap changed multiple times during the session |
| `schema_first` | Session/behavioral | Non-browser client's first requests targeted an API schema endpoint |
| `cache_miss_anomaly` | Session/behavioral | Same path fetched 5+ times in 3 min with no conditional headers |
| `no_cookie_return` | Session/behavioral | Tarpit set a cookie but client never returned it (suppressed for cross-origin requests) |
| `auth_probe_sequence` | Session/behavioral | 4+ distinct auth endpoint categories probed within 5 minutes |
| `ml_agent_score` | ML | Combined Isolation Forest + Naive Bayes score above confidence threshold |
| `honeypot_hit` | Honeypot | Client requested a path listed as a honeypot in `probe_paths` |

---

## Validation

**Check the file loaded cleanly:**

```bash
journalctl -u veilgate -n 100 | grep -i signals
# Expected: "signals.yaml loaded" or no mention at all.
# If you see "load signals.yaml failed", the YAML is malformed.
```

**Confirm a signal fires (observe mode):**

```bash
# Trigger empty_ua
curl -A "" http://localhost:8080/

# Check score metrics
curl -sS http://127.0.0.1:9090/metrics | grep 'veilgate_signal_hits_total{signal="empty_ua"}'
```

**Confirm a signal is suppressed:**

```bash
# In signals.yaml: empty_ua: {enabled: false}
# After hot-reload:
curl -A "" http://localhost:8080/
curl -sS http://127.0.0.1:9090/metrics | grep 'signal="empty_ua"'
# Counter should not increment.
```

**Confirm a custom signal fires end-to-end:**

```bash
# Add to signals.yaml:
#   custom_signals:
#     - name: php_probe
#       enabled: true
#       points: 10
#       conditions:
#         - type: path_suffix
#           value: .php
# After hot-reload:
curl http://localhost:8080/setup.php
curl -sS http://127.0.0.1:9090/metrics | grep 'signal="php_probe"'
```

**Validate a path_regex before deploying:**

```bash
echo '/v3/admin/users' | grep -P '^/v[0-9]+/admin'
# or use the Go playground to test your regexp against sample paths
```

**Check what the scorer is returning for a specific request (observe mode):**

```bash
curl -sS http://127.0.0.1:9090/metrics \
  | grep veilgate_signal_hits_total \
  | sort -t= -k2 -rn
```

---

## Related

- [`rules/detector.yaml`](detector.md) — scoring weights and detection rule substrings
- [`detector:`](../detector.md) — tarpit/challenge thresholds and trust lists
- [Rule customization guide](customization.md)
- [Module veilgate_rules](../../modules/veilgate_rules.md)
- [Detection signals overview](../../functionalities/detection-signals.md)

---

*Previous: [`rules/learned.yaml`](learned.md) | Next: [`rules/detector.yaml`](detector.md)*
