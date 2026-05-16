# `rules/vulnerabilities.yaml`

Syntax:  tarpit vulnerability helper lists  
Default: embedded `vulnerabilities.yaml`  
Context: `rules_dir`

The `vulnerabilities.yaml` file defines path and payload lists used by tarpit
routing. It helps the tarpit decide when to render fake Git config, fake
environment files, SQL error pages, or other vulnerability-shaped decoys.

This file is separate from top-level `detector.honeypot_paths`. The detector
uses top-level honeypots for scoring; the tarpit uses this file for route and
template selection.

## Example

```yaml
honeypot_paths:
  - /.git/config
  - /.env.backup

sql_injection_patterns:
  - "'"
  - "--"
  - "union"
  - "or 1=1"

fake_git_paths:
  - "/.git/config"
  - "/.git/HEAD"

fake_env_paths:
  - "/.env"
  - "/.env.backup"
```

## Fields

| Field | Type | Purpose |
| --- | --- | --- |
| `honeypot_paths` | list of paths | Named list available to tarpit routes. |
| `sql_injection_patterns` | list of substrings | Case-insensitive path/query markers for `match: sqli`. |
| `fake_git_paths` | list of paths | Named list for Git-shaped decoy routes. |
| `fake_env_paths` | list of paths | Named list for environment-file decoy routes. |

## Code Path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/tarpit/handler.go`](../../../internal/tarpit/handler.go)
- [`rules/injection_strategy.yaml`](../../../rules/injection_strategy.yaml)

## Operational Notes

- The file hot-reloads through the rules watcher.
- Keep real production routes out of vulnerability helper lists unless you
  intentionally want tarpit content on those paths after a tarpit decision.
- Keep this file aligned with `rules/injection_strategy.yaml`; route entries
  using `match: list` refer to list names from this file.

## Validation

```bash
curl -sS -A "sqlmap/1.7" "http://127.0.0.1:8080/search?q=' union select"
curl -sS http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## Related

- [`rules/injection_strategy.yaml`](injection-strategy.md)
- [`rules/templates.yaml`](templates.md)
- [`detector:`](../detector.md)
