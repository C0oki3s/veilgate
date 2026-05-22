# Request Classification: SPA, Browser Page, and Server-to-Server

VeilGate does not make a single binary "is this a browser?" decision. Instead it
uses two independent classification systems that operate on the same request in
parallel:

- **Challenge routing** — decides *which error response format* to serve if the
  request is blocked (HTML PoW page vs JSON 401).
- **Detector scoring** — decides *how suspicious* the request is, regardless of
  its origin type.

These two systems are intentionally decoupled. A server-to-server caller with a
valid bearer token scores zero and is never blocked. A bot that spoofs browser
headers still accumulates score from other signals. Classification affects how
VeilGate communicates a block, not whether it blocks.

---

## Classification used for challenge routing

Source: `internal/challenge/challenge.go` — `isXHROrFetch()`

When a request is scored into the challenge band, the challenge handler needs
to decide whether to serve an HTML proof-of-work page or a machine-readable
JSON `401`. Serving an HTML page to a `fetch()` call or an API client is
useless — the browser's JS gets raw HTML it cannot execute.

`isXHROrFetch()` answers the question "is this a JS-originated API call?".
Three signals are checked in priority order; any one is sufficient.

### Signal 1 — `Sec-Fetch-Dest` (primary, most reliable)

Browsers set this header on every request since 2020. The `Dest` value
describes what the browser intends to do with the response:

| `Sec-Fetch-Dest` value | Request type | `isXHROrFetch` result |
|---|---|---|
| `empty` | `fetch()` or `XMLHttpRequest` from JS | **true** (SPA API call) |
| `object`, `embed` | JS-embedded resource | **true** |
| `document` | Top-level page navigation | false |
| `iframe`, `frame` | Embedded frame | false |
| `image`, `script`, `style`, `font` | Subresource load | false (falls through) |
| *(absent)* | Non-browser caller | false (falls through) |

### Signal 2 — `X-Requested-With: XMLHttpRequest` (legacy SPA frameworks)

jQuery and many older SPA frameworks set this header on XHR calls.
Modern `fetch()` does not set it. VeilGate checks it as a fallback for
legacy stacks that predate `Sec-Fetch-*`.

### Signal 3 — `Accept` header sniff (weak fallback)

If neither `Sec-Fetch-Dest` nor `X-Requested-With` is present, VeilGate
checks whether the `Accept` header lists JSON or XML but **not** `text/html`.
A caller that explicitly says "I want JSON, not HTML" is almost certainly an
API consumer.

`Accept: */*` is treated as ambiguous and does **not** trigger this path — a
browser page load often sends `*/*`.

### What happens next

| `isXHROrFetch` | `spa_aware_response` | Response served |
|---|---|---|
| true | true | JSON `401` with `WWW-Authenticate` hint + CORS headers |
| true | false | HTML PoW page (with CORS headers so the browser can at least read the error) |
| false | — | HTML PoW page (top-level navigation, CORS not needed) |

`spa_aware_response` is set in `rules/challenge.yaml`. It defaults to `false`.
Enable it for any deployment where the frontend and backend are on different
origins.

### Server-to-server and this path

A server calling the API sends no `Sec-Fetch-*` headers and no
`X-Requested-With`. `isXHROrFetch` returns `false`, so a challenged
server-to-server request gets an HTML page — which is useless. The correct
solution for server-to-server traffic is to bypass the challenge entirely using
a **bearer token** or **HMAC verifier** (see [How-to: server-to-server
HMAC](../how-to/server-to-server-hmac.md)), not to rely on challenge routing.

---

## Classification used for detector scoring

Source: `internal/detector/scorer.go` — `scoreSecFetch()`,
`internal/ml/features.go` — `secFetchCoherence()`

The detector uses `Sec-Fetch-*` as a **browser consistency check**, not as a
classification label. A client claiming to be a browser via its User-Agent but
sending no browser metadata is a contradiction that adds score.

### `scoreSecFetch` — the consistency check

Fires only when the User-Agent *looks like* a real browser (contains
`chrome/`, `firefox/`, `safari/`, `edg/`, `edge/`, `opera/`, or `opr/`).
`HeadlessChrome` is explicitly excluded.

| Condition | Signal name | Points |
|---|---|---|
| Browser UA + all three `Sec-Fetch-*` headers present | *(none)* | 0 |
| Browser UA + `Sec-Fetch-*` entirely absent | `sec_fetch_absent` | +12 |
| Browser UA + only 1–2 of the 3 headers present | `sec_fetch_partial` | +6 |
| Non-browser UA, any `Sec-Fetch-*` state | *(none, `sparse_headers` handles it)* | — |

The reason library tools don't double-fire: `sparse_headers` charges for missing
headers on non-browser UAs, and `scoreSecFetch` charges for missing headers on
claimed-browser UAs. The two signals are mutually exclusive.

### `secFetchCoherence` — the ML feature

The ML extractor (`internal/ml/features.go`) converts the
`(Sec-Fetch-Site, Sec-Fetch-Mode, Sec-Fetch-Dest)` triple into a categorical
bucket that the Bayes classifier and Isolation Forest use as a feature:

| Bucket | What it means |
|---|---|
| `navigate` | Top-level page navigation (`Dest=document`, `Mode=navigate`) |
| `subresource` | CSS / JS / image fetch from a page (`Mode=no-cors`, asset Dest) |
| `cors_xhr` | Cross-origin `fetch()` / XHR from JS (`Mode=cors`, `Dest=empty` or `json`) |
| `partial` | 1–2 of the 3 headers present — unusual |
| `absent` | No `Sec-Fetch-*` at all — server-to-server, CLI tools, scanners |
| `incoherent` | All 3 present but not a recognised combination — possibly spoofed |

The ML layer uses this bucket as one of many features. `absent` is the
canonical signature of server-to-server and bot traffic.

### `sparse_headers` — the missing-header penalty

Source: `internal/detector/scorer.go` — `scoreHeaders()`

Real browsers send a consistent set of headers that HTTP libraries omit.
VeilGate tracks a configurable list of "browser-typical" headers
(`Accept-Language`, `Sec-Ch-Ua`, `Upgrade-Insecure-Requests`,
`Sec-Fetch-*`, etc.). Missing too many adds score.

One exception: if the User-Agent looks like a real browser **and at least one**
browser-hint header is present, sparse-header scoring is suppressed. This
prevents false positives on same-origin subresource loads (CSS, images) that
browsers legitimately send without the full header set.

---

## The `headerBitmap` fingerprint

Source: `internal/detector/scorer.go` — `headerBitmap()`

Independently of scoring, VeilGate computes a 32-bit bitmask of 15 interesting
headers for every request. Two requests with the same header set produce the
same bitmap. This lets the fleet-rotation signal group a proxy-rotating attacker
whose IP changes but whose HTTP client library stays the same — every `curl` or
`requests` invocation produces a predictable bitmap regardless of source IP.

The bitmap includes `Sec-Fetch-Site/Mode/Dest` as three of the 15 bits, so
server-to-server and browser traffic produce structurally different fingerprints.

---

## Decision flow summary

```
Request arrives at proxy.serve()
│
├── OPTIONS + Origin + Access-Control-Request-Method?
│   └── CORS preflight — bypass all classification, proxy to upstream
│
├── Path == /__veilgate/*?
│   └── Internal endpoint — bypass scoring, serve directly
│
├── Scoring pipeline runs
│   ├── scoreSecFetch():  Browser UA + no Sec-Fetch-*?  → +12 pts
│   ├── scoreHeaders():   Missing browser-typical headers? → +pts
│   ├── secFetchCoherence() fed to ML extractor
│   └── ... ~20 other signals ...
│
├── decision = challenge?
│   │
│   ├── isXHROrFetch() = true  AND  spa_aware_response = true
│   │   └── JSON 401 + CORS headers  (SPA API call)
│   │
│   ├── isXHROrFetch() = true  AND  spa_aware_response = false
│   │   └── HTML PoW page + CORS headers  (legacy: cross-origin but no SPA mode)
│   │
│   └── isXHROrFetch() = false
│       └── HTML PoW page  (page navigation)
│
└── decision = tarpit?
    └── Fake application response + CORS headers
        (no isXHROrFetch check — tarpit always responds, regardless of origin)
```

---

## Recommended configuration by deployment type

### Single-origin web application

The frontend and API share one domain. Browser navigation and XHR/fetch are all
same-origin. Default settings work.

```yaml
# challenge.yaml
spa_aware_response: false   # default, HTML challenge page is fine
cookie_same_site: strict
```

### SPA + API on different subdomains (`app.example.com` + `api.example.com`)

The API receives cross-origin `fetch()` calls. Enable SPA-aware response so
fetch calls get JSON instead of HTML. Set a shared cookie domain and `lax`
SameSite so the challenge cookie travels across subdomains.

```yaml
# challenge.yaml
spa_aware_response: true
cookie_domain: ".example.com"
cookie_same_site: lax
token_header_name: "X-Veilgate-Token"
```

Use the `/__veilgate/start` iframe interstitial to solve the challenge on the
API origin before the SPA makes its first authenticated request. See
[`/__veilgate/start` endpoint reference](../reference/endpoints/start.md).

### Server-to-server / backend callers

These callers send no `Sec-Fetch-*` headers. `isXHROrFetch` returns false.
They will be challenged if their score reaches the challenge threshold. The
correct approach is to issue them a verifier credential so they bypass the
challenge pipeline entirely.

```yaml
# veilgate.yaml — enable a bearer or HMAC verifier
verifiers:
  bearer:
    enabled: true
    tokens_dir: "/etc/veilgate/tokens"
```

See [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md) and
the [Bearer verifier reference](../reference/verifiers/bearer.md).

---

## Code map

| Concern | File | Function |
|---|---|---|
| SPA vs page navigation routing | `internal/challenge/challenge.go` | `isXHROrFetch()` |
| Sec-Fetch consistency scoring | `internal/detector/scorer.go` | `scoreSecFetch()` |
| Sec-Fetch ML feature bucket | `internal/ml/features.go` | `secFetchCoherence()` |
| Header sparsity scoring | `internal/detector/scorer.go` | `scoreHeaders()` |
| Header bitmap fingerprint | `internal/detector/scorer.go` | `headerBitmap()` |
| SPA challenge JSON response | `internal/challenge/challenge.go` | `serveSPAChallenge()` |
| CORS headers on blocked responses | `internal/proxy/proxy.go` | `applyCORSHeaders()` |
| CORS preflight bypass | `internal/proxy/proxy.go` | `serve()` |

---

## Related

- [Challenge handler](./challenge-handler.md)
- [Detection signals](./detection-signals.md)
- [Upload policies](./upload-policies.md)
- [WebSocket and gRPC proxying](./websocket-grpc-proxy.md)
- [`/__veilgate/start` endpoint](../reference/endpoints/start.md)
- [How-to: protect a multi-origin deployment](../how-to/protect-multi-origin.md)
- [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md)
- [Bearer verifier](../reference/verifiers/bearer.md)
