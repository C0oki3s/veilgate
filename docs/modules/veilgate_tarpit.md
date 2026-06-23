# Module veilgate_tarpit

The `veilgate_tarpit` module serves deterministic fake application responses
to requests that cross the tarpit threshold. It combines per-client fake
profiles, route strategy, response templates, and payload injection.

The tarpit is not a block page. It is a controlled fake application intended to
consume attacker time and create deception feedback such as canary replay.

## Example Configuration

```yaml
mode: "auto"

tarpit:
  min_latency_ms: 500
  max_latency_ms: 3000
  max_body_bytes: 102400
```

Rule files used by the tarpit:

```text
rules/templates.yaml
rules/injection_strategy.yaml
rules/payloads.yaml
rules/fake_data.yaml
rules/vulnerabilities.yaml
```

## Directives

- `tarpit.min_latency_ms`
- `tarpit.max_latency_ms`
- `tarpit.max_body_bytes`
- `rules/templates.yaml`
- `rules/injection_strategy.yaml`
- `rules/payloads.yaml`
- `rules/fake_data.yaml`

## `tarpit.min_latency_ms`

Syntax:  `min_latency_ms: <milliseconds>`  
Default: `500`  
Context: `tarpit`

Sets the lower bound for artificial delay added to tarpit responses.

### Code path

- [`internal/tarpit/handler.go#L96`](../../internal/tarpit/handler.go#L96)
- [`internal/telemetry/metrics.go`](../../internal/telemetry/metrics.go) records tarpit latency.

### Operational notes

- Higher latency burns more attacker time.
- Higher latency also keeps connections open longer.
- Keep values conservative until traffic volume is understood.

### Validation

```bash
curl -w "%{time_total}\n" -A "sqlmap/1.7" http://localhost:8080/.git/config
```

## `tarpit.max_latency_ms`

Syntax:  `max_latency_ms: <milliseconds>`  
Default: `3000`  
Context: `tarpit`

Sets the upper bound for artificial delay. If the maximum is less than or equal
to the minimum, the minimum is used.

### Code path

- [`internal/tarpit/handler.go`](../../internal/tarpit/handler.go)
- `randBetween()`

### Operational notes

- A broad delay range makes automated timing assumptions less reliable.
- Excessive delay can increase resource usage under sustained attack.

## `tarpit.max_body_bytes`

Syntax:  `max_body_bytes: <bytes>`  
Default: `102400`  
Context: `tarpit`

Caps the response body after template rendering and payload injection.

### Code path

- [`internal/tarpit/handler.go#L96`](../../internal/tarpit/handler.go#L96)
- [`internal/tarpit/renderer.go`](../../internal/tarpit/renderer.go)
- [`internal/payloads/injector.go`](../../internal/payloads/injector.go)

### Operational notes

- Prevents unusually large fake templates or payload injection output from
  creating large responses.
- The cap is applied to the rendered body string.

## `rules/templates.yaml`

Syntax:  template response map  
Default: embedded templates  
Context: `rules_dir`

Defines named tarpit responses: HTTP status, content type, headers, and body.
Bodies are rendered as Go `text/template` values with data from the shadow
profile and request.

### Code path

- [`internal/tarpit/renderer.go`](../../internal/tarpit/renderer.go)
- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go)

### Operational notes

- Templates should be plausible but must not contain real secrets.
- Treat template files as deception policy and review them.

## `rules/injection_strategy.yaml`

Syntax:  route and injector strategy file  
Default: embedded strategy  
Context: `rules_dir`

Maps inbound paths to templates using match types such as `exact`, `prefix`,
`contains`, `regex`, `sqli`, `list`, and `any`. First match wins.

### Code path

- [`internal/tarpit/handler.go#L129`](../../internal/tarpit/handler.go#L129)
- [`internal/tarpit/handler.go#L148`](../../internal/tarpit/handler.go#L148)

### Operational notes

- Invalid regex entries compile to a regex that matches nothing.
- Prefer explicit routes for high-value fake resources.

## `rules/payloads.yaml`

Syntax:  payload library file  
Default: embedded payloads  
Context: `rules_dir`

Defines decoy and prompt-injection payloads inserted into responses by
`internal/payloads.Injector`.

### Code path

- [`internal/payloads/library.go`](../../internal/payloads/library.go)
- [`internal/payloads/injector.go`](../../internal/payloads/injector.go)

### Operational notes

- Payloads should be designed for defensive deception in environments you own.
- Do not include real credentials or sensitive operational details.

## Fake Profile (ShadowProfile)

**Package:** [`internal/tarpit/profile.go`](../../internal/tarpit/profile.go)

Every client receives a deterministic fake application identity. The profile
is created once and cached for the process lifetime. The same client IP always
gets the same fake data, so the illusion is stable across multiple requests.

### Seed derivation

```go
// internal/tarpit/profile.go
h := sha256.Sum256([]byte(clientID))
seed := int64(binary.BigEndian.Uint64(h[:8]))
r := rand.New(rand.NewSource(seed))
```

`sha256(clientID)` produces a deterministic seed. Process restarts do not
reset the profile for a client that has already been seen.

### Profile fields

| Field | Template variable | Example |
| --- | --- | --- |
| `FakeCompany` | `{{.Profile.FakeCompany}}` | `Acme Corp` |
| `Slug` | `{{.Profile.Slug}}` | `acme` |
| `FakeStack` | `{{.Profile.FakeStack}}` | `node-express` |
| `FakeVersion` | `{{.Profile.FakeVersion}}` | `nginx/1.20.2` |
| `FakeAdminUser` | `{{.Profile.FakeAdminUser}}` | `admin` |
| `FakeAdminPass` | `{{.Profile.FakeAdminPass}}` | `P@ssw0rd123!` |
| `Visits` | `{{.Profile.Visits}}` | `3` |

All values are drawn from pools in `rules/fake_data.yaml`. The `Slug` is a
URL-safe identifier derived from `FakeCompany`, used by templates that need a
filesystem-safe token (`/.git/config`, `/.env.backup`).

The `Visits` counter increments on every `ProfileStore.Get()` call, allowing
templates to vary responses based on how many times the attacker has visited.

### Rule file

```yaml
# rules/fake_data.yaml (example structure)
companies:
  - "Acme Corp"
  - "Initech"
stacks:
  - "node-express"
  - "rails"
admin_users:
  - "admin"
  - "administrator"
admin_passes:
  - "P@ssw0rd123!"
  - "SuperSecret2024!"
versions:
  - "nginx/1.20.2"
  - "Apache/2.4.57"
```

## Route Strategy

**Package:** [`internal/tarpit/handler.go`](../../internal/tarpit/handler.go)  
**Rule file:** `rules/injection_strategy.yaml`

The tarpit handler iterates `injection_strategy.yaml → routes[]` and returns
the first matching route's template name. If no route matches, it falls back
to `"generic_not_found"`.

### Match types

| Match type | Evaluation |
| --- | --- |
| `exact` | `path == value` (case-insensitive) |
| `prefix` | `strings.HasPrefix(path, value)` |
| `contains` | `strings.Contains(path, value)` |
| `regex` | compiled regexp match against path |
| `sqli` | SQL injection pattern using `vulnerabilities.yaml` |
| `list` | path matches any entry in a named list from `vulnerabilities.yaml` |
| `any` | always matches (catch-all) |

Route ordering matters. More specific matchers should appear before `any`.

Example:

```yaml
# rules/injection_strategy.yaml (example)
routes:
  - match: exact
    values: ["/.git/config"]
    template: git_config
  - match: prefix
    values: ["/api/v1/admin"]
    template: fake_admin_api
  - match: sqli
    template: sqli_response
  - match: any
    template: generic_not_found
```

### Regex caching

Regex patterns from `injection_strategy.yaml` are compiled and cached on first
use. The cache is flushed automatically when the strategy rule file is
hot-reloaded.

## Template Rendering

**Package:** [`internal/tarpit/renderer.go`](../../internal/tarpit/renderer.go)  
**Rule file:** `rules/templates.yaml`

Templates are Go `text/template` strings. Available data:

```
{{.Profile}}  — *ShadowProfile (FakeCompany, Slug, FakeStack, etc.)
{{.Path}}     — request path string
{{.Query}}    — raw query string
```

Example template:

```
# rules/templates.yaml (example entry)
git_config:
  status: 200
  content_type: "text/plain"
  headers:
    Server: "{{.Profile.FakeVersion}}"
  body: |
    [core]
        repositoryformatversion = 0
    [remote "origin"]
        url = https://git.{{.Profile.Slug}}.internal/webapp.git
        fetch = +refs/heads/*:refs/remotes/origin/*
    [branch "main"]
        remote = origin
        merge = refs/heads/main
```

**Hot reload:** `Renderer.SetTemplates()` swaps the holder atomically.
In-flight renders complete against the previous template set.

## Payload Injection

**Package:** [`internal/payloads`](../../internal/payloads)  
**Interface:** `tarpit.PayloadInjector`  
**Rule file:** `rules/payloads.yaml`

After rendering, `h.injector.Inject()` inserts payloads into the response body:

```go
// internal/tarpit/handler.go
resp.Body = h.injector.Inject(resp.ContentType, resp.Body, InjectionContext{
    Path:     r.URL.Path,
    ClientID: clientID,
    Visits:   profile.Visits,
})
```

Payload categories:

| Category | Purpose |
| --- | --- |
| `rabbit_hole` | Fake findings, dead-end escalation paths, high-risk breadcrumbs |
| `cost_bomb` | Long decoy content (log bursts) that inflates attacker token spend |
| `termination` | Directives telling the LLM agent to stop the task |
| `confusion` | Contradictory information that degrades the agent's plan |
| `moral_appeal` | Safety-training appeals (unauthorized access warnings) |
| `prompt_injection` | Direct prompt-injection payloads. **Empty by default since v1.1.5.** |
| Canary tokens | Unique strings recorded in `persist.Store`; fire `canary_replay` when replayed |

If `tarpit.PayloadInjector` is nil (no injector configured), `noopInjector`
is used and the body is returned unchanged.

## Canary Token Lifecycle

1. The injector embeds a unique canary token in a tarpit response.
2. `persist.Store` records the token → client ID mapping in the `canaries`
   table.
3. A later request from any client includes the token in its path, query, or
   headers.
4. `detector.Scorer.scoreCanaryReplay()` calls `persist.Store.HitCanary()`.
5. `canary_replay` fires as a high-confidence signal.

For canary replay to function:
- `persist.enabled: true`
- The persist store must be wired as `CanaryLookup` (done in `cmd/veilgate/main.go`)

## Tarpit Response Pipeline

```
ServeHTTP(w, r)
  1. clientIP(r)                        — direct RemoteAddr (no XFF trust)
  2. ProfileStore.Get(clientID)         — load or create fake profile
  3. time.Sleep(randBetween(min, max))  — artificial delay
  4. handler.route(r, profile)          — select template from injection_strategy.yaml
  5. renderer.Render(template, profile) — render Go text/template
  6. injector.Inject(ct, body, ctx)     — insert decoy/prompt-injection/canary payloads
  7. body[:MaxBodyBytes]                — enforce size cap
  8. w.Write(body)                      — send to client
  9. telemetry.TarpitBytesServed.Add()  — Prometheus counter
 10. DefaultBus.Emit(KindTarpit)        — async fan-out to OTelSink + dashboard
```

For the full pipeline detail, see
[Tarpit Rendering Flow](../internals/tarpit_rendering_flow.md).

## Metrics

| Prometheus | OTel | Description |
| --- | --- | --- |
| `veilgate_tarpit_bytes_served_total` | `veilgate.tarpit.bytes_served.total` | Total bytes served to tarpitted clients |
| `veilgate_tarpit_latency_ms_total` | `veilgate.tarpit.latency_ms.total` | Total artificial delay added (milliseconds) |
| `veilgate_tarpit_active_sessions` | `veilgate.tarpit.active_sessions` | Gauge of in-flight `ServeHTTP` calls |
| `veilgate_tarpit_template_type_total` | `veilgate.tarpit.template_type.total` | Responses by content-type (json/html/graphql/text/other) |
| `veilgate_attacker_cost_usd_total` | `veilgate.tarpit.cost_usd.total` | Estimated attacker LLM API cost burned, USD |

```promql
rate(veilgate_tarpit_bytes_served_total[5m])
veilgate_tarpit_active_sessions   # gauge: in-flight tarpit connections
```

## Limitations

- False positives in tarpit mode receive fake application content. Enable
  tarpit only after observe-mode review and threshold tuning.
- `ProfileStore` holds per-client data in memory indefinitely. Under sustained
  attack from many distinct IPs, memory use will grow.
- The tarpit does not simulate state changes across sessions; it is
  deterministic based on the profile seed, not a stateful application
  simulation.
- Canary replay requires persistence to be enabled. Without it, the tarpit
  still serves fake content but provides no deception feedback signal.

## Related

- [Tarpit Rendering Flow](../internals/tarpit_rendering_flow.md)
- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_rules](veilgate_rules.md)
- [Module veilgate_persistence](veilgate_persistence.md)
- [`rules/injection_strategy.yaml`](../config/rules/injection-strategy.md)
- [`rules/templates.yaml`](../config/rules/templates.md)
- [`rules/fake_data.yaml`](../config/rules/fake-data.md)
- [`rules/payloads.yaml`](../config/rules/payloads.md)

