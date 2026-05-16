# `rules/injection_strategy.yaml`

> **File:** `/etc/veilgate/rules/injection_strategy.yaml`
> **Reload:** hot-reload (~500 ms).
>
> Two-part config: the route table that maps tarpit-bound requests to
> response templates, and the injector knobs that pick how many
> prompt-injection payloads (and which categories) get spliced into
> each response.

**On this page:**

- [`routes:`](#routes)
- [`injector:`](#injector)
- [Match types](#match-types)
- [Examples](#examples)
- [Related](#related)

## `routes:`

Ordered list. The first matching route wins. Falls through to the
template `generic_not_found` when nothing matches.

```yaml
routes:
  - match: prefix
    values: [/admin, /administrator]
    template: fake_admin
  - match: exact
    values: [/.git/config]
    template: fake_git_config
  - match: regex
    values: ["^/api/v[0-9]+/users/[0-9]+$"]
    template: api_json_fake
  - match: any
    values: []
    template: generic_not_found      # fallback
```

| Field | Type | Required | Purpose |
| --- | --- | --- | --- |
| `match` | string (enum) | yes | `prefix` / `exact` / `contains` / `regex` / `sqli` / `list` / `any` |
| `values` | list of strings | yes | depends on `match`; can be empty for `any` |
| `template` | string | yes | name from [`templates.yaml`](templates.md) |

## `injector:`

Controls how many prompt-injection payloads get woven into each tarpit
response and how the categories are weighted.

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `max_payloads_per_response` | int | `3` | hard cap per response |
| `visit_bucket_rotation` | bool | `true` | rotate the *style* selected for each visit-bucket so an agent cannot memorize one pattern |
| `style_weights` | map of map | see below | weights per style, scoped per route or `default` |
| `category_order` | list of strings | `[termination, rabbit_hole, cost_bomb, confusion, moral_appeal]` | order in which categories are sampled |

```yaml
injector:
  max_payloads_per_response: 3
  visit_bucket_rotation: true
  style_weights:
    default:
      termination: 2
      rabbit_hole: 2
      cost_bomb: 3
      confusion: 1
      moral_appeal: 1
    fake_admin:
      moral_appeal: 4              # heavier "you are unauthorized" framing
      termination: 2
  category_order:
    - termination
    - cost_bomb
    - rabbit_hole
    - moral_appeal
    - confusion
```

`style_weights.<template_name>` overrides `default` for responses that
land on that template.

## Match types

| Match | Semantics |
| --- | --- |
| `prefix` | path starts with any value in `values` (case-insensitive) |
| `exact` | path equals any value (case-insensitive) |
| `contains` | path contains any value as a substring (case-insensitive) |
| `regex` | path matches any compiled regex in `values`. Compiled regexes are cached per strategy version. |
| `sqli` | path or query contains any pattern from `vulnerabilities.sql_injection_patterns` (centralized list) |
| `list` | `values` are *names* of lists in `rules/vulnerabilities.yaml` (e.g. `honeypot_paths`, `fake_git_paths`); the route fires if the path matches any entry in any named list |
| `any` | unconditional - used as the final fallthrough route |

The `regex` matcher caches compiled regexes per strategy file
version. Hot-reloading the strategy file invalidates the cache; bad
regexes compile to a never-match pattern (no crash).

## Examples

### Route APIs to a JSON tarpit, everything else to HTML

```yaml
routes:
  - match: prefix
    values: [/api/, /v1/, /v2/]
    template: api_json_fake
  - match: prefix
    values: [/openapi, /swagger]
    template: fake_swagger
  - match: any
    values: []
    template: generic_not_found
```

### Heavier injection on the admin-panel decoy

```yaml
injector:
  style_weights:
    fake_admin:
      moral_appeal: 5
      termination: 3
      cost_bomb: 1
```

### Drop the cost-bomb category for low-bandwidth deployments

```yaml
injector:
  style_weights:
    default:
      termination: 3
      rabbit_hole: 3
      cost_bomb: 0           # skip cost_bomb entirely
      confusion: 2
      moral_appeal: 2
```

## Related

- [`rules/templates.yaml`](templates.md) - response bodies
- [`rules/payloads.yaml`](payloads.md) - payload library
- [`rules/vulnerabilities.yaml`](vulnerabilities.md) - lists referenced by `match: list`
- [Use case: LLM-agent defense](../../usecases/llm-agent-defense.md)

---

*Previous: [`rules/templates.yaml`](templates.md) | Next: [`rules/tls_fingerprints.yaml`](tls-fingerprints.md)*
