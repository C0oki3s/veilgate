# `rules/detector.yaml`

> **File:** `/etc/veilgate/rules/detector.yaml` &nbsp;·&nbsp;
> **Reload:** hot-reload via fsnotify (~500 ms debounce).
>
> The rule definitions for every signal in the rule-based scorer.
> Top-level thresholds and trust lists live in
> [`detector:`](../detector.md) on the proxy config.

**On this page:**

- [`suspicious_user_agents`](#suspicious_user_agents)
- [`browser_headers`](#browser_headers)
- [`empty_user_agent`](#empty_user_agent)
- [`toolchain`](#toolchain)
- [`timing`](#timing)
- [`path_bruteforce`](#path_bruteforce)
- [`wordlist_paths`](#wordlist_paths)
- [`injection_markers`](#injection_markers)
- [`oob_interaction`](#oob_interaction)
- [Related](#related)

## Sections

### `suspicious_user_agents`

Tier-1 substring match against the User-Agent header. The first
matching substring wins; comparison is case-insensitive.

| Field | Type | Default |
| --- | --- | --- |
| `points` | int | `35` |
| `substrings` | list of strings | curated set of HTTP libraries, scanners, exploit frameworks |

Examples of high-value entries:

```yaml
suspicious_user_agents:
  points: 35
  substrings:
    - python-requests
    - python-httpx
    - aiohttp
    - go-http-client
    - okhttp
    - curl/
    - sqlmap
    - nuclei
    - nikto
    - hexstrike
    - pentestgpt
    - strix
```

The shipped default is extensive (~80 entries). See
[`internal/rules/defaults/detector.yaml`](../../../internal/rules/defaults/detector.yaml)
for the full list. Add agent identifiers as you discover them in
production traffic.

---

### `browser_headers`

Counts how many "browser-typical" headers a request is missing.
A request that misses several is library-shaped.

| Field | Type | Default |
| --- | --- | --- |
| `hints` | list of header names | Accept-Language, Accept-Encoding, Sec-Fetch-Site, Sec-Fetch-Mode |
| `tiers` | list of `{missing: int, points: int}` | see below |

```yaml
browser_headers:
  hints:
    - Accept-Language
    - Accept-Encoding
    - Sec-Fetch-Site
    - Sec-Fetch-Mode
  tiers:
    - missing: 3
      points: 15
    - missing: 2
      points: 8
```

Tiers are evaluated top-down — list them in descending `missing`.
A request with 3 missing hits the first tier; a request with 2
missing hits the second.

> **Note.** When a browser-shaped UA is present *and* at least one
> hint is also present, this signal is suppressed entirely — that
> avoids the "legit page-load scores 14 pts from subresource fetches"
> false positive.

---

### `empty_user_agent`

Single-key tier for the empty-UA case. Almost always a library
default or a misconfigured client.

| Field | Type | Default |
| --- | --- | --- |
| `points` | int | `20` |

---

### `toolchain`

Detects the canonical pentest pipeline by looking for path / query
substrings in the rolling event window.

| Field | Type | Default |
| --- | --- | --- |
| `recon_paths` | list of substrings | `/robots.txt`, `/sitemap.xml`, `/.well-known/` |
| `probe_paths` | list of substrings | `/admin`, `/login`, `/api/`, `/.git`, `/.env`, `/wp-` |
| `exploit_markers` | list of substrings | `'`, `"`, `--`, `<script`, `../`, `union`, `select`, ... |
| `points.full` | int | `30` (all three stages observed) |
| `points.partial` | int | `15` (two stages observed) |

The signal looks at *both* the path and the raw query string —
exploit markers usually live in the query (`?q=' or 1=1--`).

---

### `timing`

Detects suspiciously regular inter-request gaps — the classic LLM
or crawler cadence.

| Field | Type | Default |
| --- | --- | --- |
| `min_events` | int | `6` (need this much history to fire) |
| `min_mean_seconds` | float | `1.5` |
| `max_mean_seconds` | float | `10.0` |
| `strict_cv_max` | float | `0.35` (coefficient of variation) |
| `strict_points` | int | `25` |
| `loose_cv_max` | float | `0.55` |
| `loose_points` | int | `12` |

A client whose mean inter-request gap sits in `[min_mean, max_mean]`
*and* whose CV is below `strict_cv_max` scores `strict_points`. CV
between `strict_cv_max` and `loose_cv_max` scores `loose_points`.

---

### `path_bruteforce`

Counts distinct paths a client hits inside the rolling window.
Catches dirsearch / ffuf / feroxbuster / nikto even when they rotate
UA pools.

| Field | Type |
| --- | --- |
| `tiers` | list of `{distinct_paths: int, points: int}`, descending |

```yaml
path_bruteforce:
  tiers:
    - distinct_paths: 200
      points: 40
    - distinct_paths: 50
      points: 25
    - distinct_paths: 15
      points: 10
```

First match wins. Tune downward for low-traffic APIs (see the
[API recon-blocking use case](../../usecases/api-recon-blocking.md)).

---

### `wordlist_paths`

Flat list of substrings that show up in standard scanner wordlists
(SecLists, dirsearch defaults, nikto db_tests.db). One hit per
request.

| Field | Type | Default |
| --- | --- | --- |
| `points` | int | `25` |
| `substrings` | list of strings | ~80 curated entries |

Examples: `/wp-admin/`, `/.git/`, `/phpinfo.php`, `/actuator`,
`/manager/html`, `/struts2-showcase`. See the embedded default for
the full list.

---

### `injection_markers`

Substrings indicating an attack payload landed somewhere in the
request: SQLi, XSS, path traversal, Log4Shell, SSRF callbacks. One
hit scores once per request, regardless of how many substrings hit.

| Field | Type | Default |
| --- | --- | --- |
| `points` | int | `45` |
| `headers` | list of header names | UA, Referer, X-Forwarded-*, Host, Cookie |
| `substrings` | list of strings | curated payload markers |

The scanner looks at path + query unconditionally; the `headers`
field controls *which* request headers are also scanned.

---

### `oob_interaction`

Out-of-band callback hosts: Burp Collaborator, interactsh,
webhook.site, ngrok. A request mentioning one is almost certainly
part of a blind-SSRF / blind-XXE template.

| Field | Type | Default |
| --- | --- | --- |
| `points` | int | `50` |
| `substrings` | list of strings | `.oast.me`, `.burpcollaborator.net`, `.interact.sh`, ... |

## Related

- [`detector:`](../detector.md) — thresholds and trust lists
- [`rules/ml.yaml`](ml.md) — additive ML signal
- [`rules/ip_reputation.yaml`](ip-reputation.md) — CIDR categories +
  fleet rotation

---

*Previous: [`capture:`](../capture.md) · Next: [`rules/ml.yaml`](ml.md)*
