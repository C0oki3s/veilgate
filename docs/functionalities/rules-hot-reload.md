# Module veilgate_rules

The `veilgate_rules` module documents external YAML rule files. These files
define detector weights, fingerprint classifications, tarpit templates, route
strategy, fake data, payloads, challenge behavior, ML settings, and dashboard
layout.

Rules are loaded from `rules_dir` when configured. Missing files fall back to
embedded defaults.

## Example Configuration

```yaml
rules_dir: "~/.veilgate/rules"
```

## Directives

- `rules_dir`
- `detector.yaml`
- `ip_reputation.yaml`
- `tls_fingerprints.yaml`
- `templates.yaml`
- `injection_strategy.yaml`
- `payloads.yaml`
- `fake_data.yaml`
- `challenge.yaml`
- `ml.yaml`
- `dashboard.yaml`
- `learned.yaml`

## `rules_dir`

Syntax:  `rules_dir: "<directory>"`  
Default: empty, embedded defaults  
Context: top-level

Defines where rule files are loaded from. If a file is not present in the
directory, the embedded default for that file is used. When `rules_dir` is set,
the watcher hot-reloads supported files.

### Code path

- [`internal/rules/loader.go`](../../internal/rules/loader.go)
- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go)
- [`internal/rules/watcher.go`](../../internal/rules/watcher.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

### Operational notes

- Treat rules as security policy.
- Version and review rule changes.
- Mount read-only in production where possible.
- A bad reload should not replace the last good in-memory rules.

### Validation

```bash
ls -la ~/.veilgate/rules
```

## Rule File Reference

| File | Purpose | Code area |
| --- | --- | --- |
| `detector.yaml` | Signal weights and matchers. | `internal/rules`, `internal/detector` |
| `signals.yaml` | Enable/disable signals, points overrides, custom signals. Hot-reloaded ~500 ms. | `internal/rules`, `internal/detector/scorer.go` |
| `ip_reputation.yaml` | CIDR categories, fleet rotation, UA rotation. | `internal/rules/ip_reputation.go`, `internal/detector/fleet.go` |
| `tls_fingerprints.yaml` | JA3/JA4 exact and prefix classifications. | `internal/tlsfp`, `internal/detector/tls.go` |
| `api_blueprint.yaml` / `openapi.yaml` | API route map for `api_blueprint_miss` signal. Accepts simple routes list, OpenAPI 3.x, or Swagger 2.0. | `internal/blueprint` |
| `templates.yaml` | Tarpit response templates. | `internal/tarpit/renderer.go` |
| `injection_strategy.yaml` | Tarpit route and payload strategy. | `internal/tarpit/handler.go` |
| `payloads.yaml` | Tarpit deception payload library (termination, rabbit_hole, cost_bomb, confusion, moral_appeal). `prompt_injection` category is present but empty by default since v1.1.5. | `internal/payloads` |
| `fake_data.yaml` | Fake profile value pools. | `internal/tarpit/profile.go` |
| `vulnerabilities.yaml` | Fake vulnerability and route lists. | `internal/tarpit/handler.go` |
| `challenge.yaml` | Challenge template, cookie, token, and verify settings. | `internal/challenge` |
| `ml.yaml` | Online ML and miner settings. | `internal/ml` |
| `dashboard.yaml` | Dashboard panels and charts. | `internal/telemetry/dashboard.go` |
| `learned.yaml` | Miner-proposed or operator-promoted learned rules. | `internal/ml`, `internal/rules` |

## Hot Reload

Syntax:  automatic watcher for supported rule files  
Default: disabled when `rules_dir` is empty  
Context: runtime

The watcher is registered for detector, signals, IP reputation, tarpit content,
challenge, ML, dashboard, TLS fingerprints, and API blueprint when applicable.
Runtime holders swap rule pointers so request-path reads remain cheap.

### Code path

- [`internal/rules/watcher.go`](../../internal/rules/watcher.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) registers each file.

### Operational notes

- Hot reload is not a substitute for testing.
- Keep a known-good rules revision available for rollback.
- Avoid editing production rule files manually without version control.

## Validation Commands

Trigger a known signal:

```bash
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

Check dashboard reload after editing dashboard rules:

```bash
curl -i http://127.0.0.1:9090/
```

## Related

- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_tarpit](../modules/veilgate_tarpit.md)
- [Module veilgate_ml](../modules/veilgate_ml.md)

