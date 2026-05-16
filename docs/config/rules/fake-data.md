# `rules/fake_data.yaml`

Syntax:  fake profile data pools  
Default: embedded `fake_data.yaml`  
Context: `rules_dir`

The `fake_data.yaml` file supplies deterministic fake values used by the
tarpit profile store. A client profile picks one value from each pool, so the
same client sees a consistent fake company, stack, version, admin username,
password, and email domain across visits.

## Example

```yaml
versions:
  - "nginx/1.24.0"
  - "Apache/2.4.54 (Debian)"

stacks:
  - php
  - node-express

companies:
  - Acme Corp
  - Initech

admin_users:
  - admin
  - sysadmin

admin_passes:
  - password123
  - ChangeMe!

email_domains:
  - acme
  - initech
```

## Fields

| Field | Type | Purpose |
| --- | --- | --- |
| `versions` | list of strings | Fake server or application version strings. |
| `stacks` | list of strings | Fake technology stack identifiers. |
| `companies` | list of strings | Fake company names rendered into templates. |
| `admin_users` | list of strings | Fake account names used in tarpit responses. |
| `admin_passes` | list of strings | Fake passwords or lure credentials. |
| `email_domains` | list of strings | Fake domains used by templates. |

## Code Path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/tarpit/profile.go`](../../../internal/tarpit/profile.go)
- [`internal/tarpit/renderer.go`](../../../internal/tarpit/renderer.go)

## Operational Notes

- The file hot-reloads through the rules watcher.
- Existing client profiles keep values already selected; new profiles draw from
  updated pools.
- Do not include real customer names, real internal hostnames, or real
  credentials. These values are intentionally fake deception content.

## Validation

```bash
curl -sS -A "sqlmap/1.7" http://127.0.0.1:8080/.git/config
curl -sS http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

## Related

- [`rules/templates.yaml`](templates.md)
- [`rules/injection_strategy.yaml`](injection-strategy.md)
- [`tarpit:`](../tarpit.md)
