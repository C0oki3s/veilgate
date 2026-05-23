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
rules/decoy_paths.yaml          # bait endpoints published via .well-known
```

## Directives

- `tarpit.min_latency_ms`
- `tarpit.max_latency_ms`
- `tarpit.max_body_bytes`
- `rules/templates.yaml`
- `rules/injection_strategy.yaml`
- `rules/payloads.yaml`
- `rules/fake_data.yaml`
- `rules/decoy_paths.yaml`

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

## `rules/decoy_paths.yaml`

Syntax:  list of `{ path, service }` entries  
Default: none — add entries to expose bait endpoints  
Context: `rules_dir`

Defines operator-configurable bait endpoints that are:

1. **Published in `/__veilgate/.well-known`** under a `tarpit.paths` array so
   both SDKs always inject paths the proxy is actively tarpitting.
2. **Injected as DOM breadcrumbs** by `@veilgate/client` (random subset per
   page load as `<script type="application/json">` and `<meta>` in
   `document.head`).
3. **Added to API response headers** by `@veilgate/node` `decoyMiddleware()`
   as `Link`, `X-Api-Documentation`, and `X-Debug-Endpoint` headers.

Every path listed here should also have a matching route in
`injection_strategy.yaml` so agents that follow a breadcrumb receive a
convincing fake response rather than a generic 404.

```yaml
paths:
  - path: "/actuator/env"
    service: "spring-actuator"
  - path: "/v1/secret/data/prod"
    service: "vault"
  - path: "/.env.local"
    service: "secrets"
```

The `service` field is a human-readable label exposed in `.well-known`; it is
not used for routing decisions. Additional files can be dropped into a
`decoy_paths/` subdirectory and are merged automatically.

### Code path

- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go) — `LoadDecoyPaths`, `DecoyPaths`, `TarpitDescriptor`
- [`internal/tarpit/handler.go`](../../internal/tarpit/handler.go) — `DescribeTarpit()`, `SetDecoyPaths()`
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) — `tarpitDescriber` interface, `discoveryDoc.Tarpit`

### Operational notes

- Paths are hot-reloaded when `decoy_paths.yaml` changes — no restart needed.
- Keep the list to paths your `injection_strategy.yaml` actually handles.
- Add community-specific paths in `decoy_paths/` to avoid merge conflicts.

## Limitations

False positives in tarpit mode receive fake content. For this reason, tarpit
should be enabled only after observe-mode review and threshold tuning.

## Related

- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_rules](../modules/veilgate_rules.md)
- [Module veilgate_persistence](../modules/veilgate_persistence.md)

