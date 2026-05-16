# Tarpit Rendering Flow

This page documents the internal pipeline that transforms an inbound
high-confidence request into a deterministic fake application response. The
pipeline is implemented by `internal/tarpit` and is invoked when the proxy
decision is `DecisionTarpit`.

## Entry Point

```
internal/proxy.Server.serve()
  └─ switch decision:
       case DecisionTarpit:
           s.tarpitHandler.ServeHTTP(rec, r)
```

`s.tarpitHandler` is a `*tarpit.Handler` constructed in `cmd/veilgate/main.go`
and set on the proxy server.

---

## Full Pipeline

```
tarpit.Handler.ServeHTTP(w, r)
  │
  ├─ 1. Resolve client ID
  │      clientIP(r) → RemoteAddr host (no XFF trust here)
  │
  ├─ 2. Load or create fake profile
  │      ProfileStore.Get(clientID)
  │        └─ ProfileStore.create(clientID) if new
  │             ├─ sha256(clientID) → deterministic seed
  │             ├─ rand.New(rand.NewSource(seed))
  │             └─ pick(fd.Companies, r) → FakeCompany, Slug, ...
  │
  ├─ 3. Apply artificial delay
  │      delay = randBetween(cfg.MinLatencyMs, cfg.MaxLatencyMs)
  │      time.Sleep(delay * ms)
  │      telemetry.TarpitLatencyMs.Add(float64(delay))
  │
  ├─ 4. Route the request
  │      handler.route(r, profile)
  │        └─ load strategy = h.strategy.Load()
  │           load vuln    = h.vuln.Load()
  │           for each rt in strat.Routes:
  │             if routeMatches(rt, path, query, vuln) → first match wins
  │               └─ renderer.Render(rt.Template, profile, extra)
  │           fallback: renderer.Render("generic_not_found", profile, extra)
  │
  ├─ 5. Inject payloads
  │      h.injector.Inject(resp.ContentType, resp.Body, InjectionContext{...})
  │        └─ internal/payloads.Injector — inserts decoy + prompt-injection text
  │
  ├─ 6. Enforce body size cap
  │      if len(resp.Body) > cfg.MaxBodyBytes:
  │          resp.Body = resp.Body[:cfg.MaxBodyBytes]
  │
  ├─ 7. Write response
  │      set resp.Headers, Content-Type, StatusCode
  │      w.Write([]byte(resp.Body))
  │      telemetry.TarpitBytesServed.Add(float64(n))
  │
  └─ 8. Record attacker cost estimate
         telemetry.EstimatedAttackerCostUSD.Add(float64(n) / 1024.0 * 0.003)
```

---

## Stage 1: Client Identity in the Tarpit

The tarpit resolves the client IP using `clientIP(r)`, which calls
`resolveClientIP(r, nil)` — with **no trusted-proxy list**. This is intentional:
the tarpit does not need XFF resolution because the fake profile stability
depends only on a stable identity string. Using the direct remote address
avoids the risk of an attacker varying the XFF header to receive different
profiles.

```go
// internal/tarpit/handler.go
clientID := clientIP(r)
```

---

## Stage 2: Fake Profile (ProfileStore)

**Package:** `internal/tarpit/profile.go`

The `ProfileStore` maps client IDs to `ShadowProfile` structs. Profiles are
created once and cached for the lifetime of the process.

### Deterministic seed

Profile data is generated from a deterministic seed derived from the client ID:

```go
// internal/tarpit/profile.go
h := sha256.Sum256([]byte(clientID))
seed := int64(binary.BigEndian.Uint64(h[:8]))
r := rand.New(rand.NewSource(seed))
```

This means:

- The same client IP always gets the same fake company, stack, credentials, and
  user names.
- Process restarts do not reset the illusion.
- Different clients get different fake profiles with high probability.

### Profile fields

| Field | Description | Example |
| --- | --- | --- |
| `FakeVersion` | Fake server version token | `nginx/1.20.2` |
| `FakeStack` | Fake application stack | `node-express` |
| `FakeAdminUser` | Fake admin username | `admin` |
| `FakeAdminPass` | Fake admin password | `P@ssw0rd123!` |
| `FakeCompany` | Fake company name | `Acme Corp` |
| `Slug` | URL-safe company slug | `acme` |

All values are drawn from pools defined in `rules/fake_data.yaml`. The
`ProfileStore.SetFakeData()` method swaps in a hot-reloadable holder; existing
profiles retain their previously drawn values (determinism over freshness).

### Visit tracking

Each `ProfileStore.Get()` call increments `profile.Visits` and updates
`profile.LastSeen`. Templates can use `{{.Visits}}` to vary responses based
on how many times an attacker has visited.

---

## Stage 3: Artificial Delay

```go
// internal/tarpit/handler.go
delay := randBetween(h.cfg.MinLatencyMs, h.cfg.MaxLatencyMs)
time.Sleep(time.Duration(delay) * time.Millisecond)
telemetry.TarpitLatencyMs.Add(float64(delay))
```

The delay is uniform-random between `tarpit.min_latency_ms` and
`tarpit.max_latency_ms`. This serves two purposes:

1. **Resource cost:** keeps the attacker's connection and worker thread occupied.
2. **Timing uncertainty:** prevents the attacker from timing the response to
   infer it is artificial.

The total added latency is recorded in `veilgate_tarpit_latency_ms_total`.

---

## Stage 4: Route Selection

**Package:** `internal/tarpit/handler.go → route()`  
**Rule file:** `rules/injection_strategy.yaml`

The route function iterates `strat.Routes` in order and returns the first
matching route's template name. If no route matches, it falls back to
`"generic_not_found"`.

### Match types

| Match type | Behavior |
| --- | --- |
| `exact` | `path == value` (case-insensitive) |
| `prefix` | `strings.HasPrefix(path, value)` |
| `contains` | `strings.Contains(path, value)` |
| `regex` | compiled regexp match against path |
| `sqli` | SQLi pattern detection (uses `vulnerabilities.yaml`) |
| `list` | path matches any entry in a named list from `vulnerabilities.yaml` |
| `any` | always matches (wildcard catch-all) |

```go
// internal/tarpit/handler.go
func (h *Handler) route(r *http.Request, p *ShadowProfile) Response {
    path := strings.ToLower(r.URL.Path)
    ...
    for _, rt := range strat.Routes {
        if h.routeMatches(rt, path, query, vuln) {
            return h.renderer.Render(rt.Template, p, extra)
        }
    }
    return h.renderer.Render("generic_not_found", p, extra)
}
```

**Route ordering matters.** More specific matchers (exact, prefix) should
appear before broad matchers (contains, any) to avoid a catch-all template
shadowing targeted responses.

### Regex caching

Compiled regex objects are cached in `handler.regexes` (keyed by pattern
string). The cache is invalidated via `invalidateRegexCache()` whenever the
strategy holder is swapped during hot reload. A `sync.RWMutex` guards the
cache for concurrent requests.

---

## Stage 5: Template Rendering

**Package:** `internal/tarpit/renderer.go`  
**Rule file:** `rules/templates.yaml`

`Renderer.Render(templateName, profile, extra)` looks up the named template
from the loaded `rules.Templates` holder, then executes it as a Go
`text/template` with the following data:

```go
data := map[string]any{
    "Profile": profile,   // *ShadowProfile
    "Path":    extra["Path"],
    "Query":   extra["Query"],
    // ... other extras from the route
}
```

Template functions and the `ShadowProfile` fields allow templates to produce
responses like:

```html
<!-- fake git config -->
[core]
    repositoryformatversion = 0
[remote "origin"]
    url = https://git.{{.Profile.Slug}}.internal/webapp.git
```

or:

```json
{"error": "invalid token", "admin": "{{.Profile.FakeAdminUser}}"}
```

**Hot reload:** `Renderer.SetTemplates()` swaps in a new holder atomically.
In-flight renders complete against the old template set; subsequent renders
use the new set.

---

## Stage 6: Payload Injection

**Package:** `internal/payloads`  
**Interface:** `tarpit.PayloadInjector`  
**Rule file:** `rules/payloads.yaml`

After the template is rendered, `h.injector.Inject()` is called with the
response `ContentType`, rendered body, and an `InjectionContext`:

```go
resp.Body = h.injector.Inject(resp.ContentType, resp.Body, InjectionContext{
    Path:     r.URL.Path,
    ClientID: clientID,
    Visits:   profile.Visits,
})
```

The injector selects payloads from `rules/payloads.yaml` appropriate for the
content type and inserts them into the response. Payload categories include:

- **Decoy payloads:** fake credentials, API keys, internal hostnames, database
  connection strings — designed to waste automated credential-harvesting time.
- **Prompt-injection text:** content targeted at LLM-based agents that parse
  HTML or JSON to extract instructions, designed to misdirect the agent.
- **Canary tokens:** unique strings recorded in the persistence store. If the
  same token appears in a later request, the `canary_replay` detector signal
  fires.

When no injector is configured, `noopInjector` is used and the body is
returned unchanged.

---

## Stage 7: Body Size Cap

```go
if len(resp.Body) > h.cfg.MaxBodyBytes {
    resp.Body = resp.Body[:h.cfg.MaxBodyBytes]
}
```

The cap is applied after template rendering and payload injection, so the final
response body is always bounded. Large templates or aggressive payload injection
cannot cause unbounded memory or bandwidth usage. The default cap is `102400`
bytes (100 KB).

---

## Stage 8: Response Write and Telemetry

```go
for k, v := range resp.Headers { w.Header().Set(k, v) }
w.Header().Set("Content-Type", resp.ContentType)
w.WriteHeader(resp.Status)
n, _ := w.Write([]byte(resp.Body))
telemetry.TarpitBytesServed.Add(float64(n))
telemetry.EstimatedAttackerCostUSD.Add(float64(n) / 1024.0 * 0.003)
```

`TarpitBytesServed` counts total bytes served to tarpitted clients.
`EstimatedAttackerCostUSD` is a rough approximation of bandwidth cost at
typical cloud egress rates, useful as a dashboard vanity metric.

---

## Rule File Relationships

| Rule file | Read by | Purpose |
| --- | --- | --- |
| `rules/injection_strategy.yaml` | `tarpit.Handler.route()` | Route → template mapping |
| `rules/templates.yaml` | `tarpit.Renderer` | Named response templates |
| `rules/fake_data.yaml` | `tarpit.ProfileStore` | Fake company/stack/user pools |
| `rules/payloads.yaml` | `internal/payloads.Injector` | Decoy and prompt-injection payloads |
| `rules/vulnerabilities.yaml` | `tarpit.Handler.routeMatches()` | SQLi patterns and path lists |

All rule holders support hot reload. The `Holder[T]` type uses `atomic.Pointer`
so swaps are safe under concurrent request handling.

---

## Canary Token Lifecycle

1. The tarpit serves a response containing a unique canary token (embedded via
   template or payload injection).
2. `persist.Store` records the token mapped to the client ID that received it.
3. A later request from any client includes the canary in its path, query, or
   headers.
4. `detector.Scorer.scoreCanaryReplay()` calls `persist.Store.HitCanary()`.
5. If the token is found, `canary_replay` fires as a high-confidence signal.

For this to work, `persist.enabled` must be `true` and the store must be wired
as the `CanaryLookup` in `cmd/veilgate/main.go`.

---

## Operational Notes

- The tarpit handler does not bypass the body size cap even for high-visit
  clients.
- Profile data is held in memory for the process lifetime. Under sustained
  attack from many distinct IPs, `ProfileStore` grows without bound. Monitor
  memory usage.
- Templates should be plausible but must not contain real secrets, real
  credentials, or sensitive operational data.
- Do not configure payloads that could cause harm if replayed against a third
  party system.
- The attacker cost metric is an approximation; do not use it for financial
  reporting.

---

## Related

- [Module veilgate_tarpit](../modules/veilgate_tarpit.md)
- [Module veilgate_rules](../modules/veilgate_rules.md)
- [Detector Signal Flow](detector_signal_flow.md) — `canary_replay` signal
- [`rules/injection_strategy.yaml`](../config/rules/injection-strategy.md)
- [`rules/templates.yaml`](../config/rules/templates.md)
- [`rules/fake_data.yaml`](../config/rules/fake-data.md)
- [`rules/payloads.yaml`](../config/rules/payloads.md)
