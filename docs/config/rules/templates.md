# `rules/templates.yaml`

> **File:** `~/.veilgate/rules/templates.yaml`
> **Reload:** hot-reload (~500 ms).
>
> Response bodies served by the tarpit. Each template is selected by a
> route in [`injection_strategy.yaml`](injection-strategy.md). Bodies
> are Go `text/template` strings with access to a per-IP-coherent fake
> profile.

**On this page:**

- [File shape](#file-shape)
- [Template variables](#template-variables)
- [Built-in templates](#built-in-templates)
- [Adding a template](#adding-a-template)
- [Related](#related)

## File shape

```yaml
templates:
  <template_name>:
    status: 200
    content_type: text/html
    headers:
      X-Powered-By: "Apache/2.4.{{.Profile.MinorVersion}}"
    body: |
      <html>
        <head><title>{{.Profile.Company}}</title></head>
        <body>...</body>
      </html>
```

| Field | Type | Required | Purpose |
| --- | --- | --- | --- |
| `status` | int | yes | HTTP status code returned (e.g. 200, 401, 403, 500) |
| `content_type` | string | yes | response Content-Type |
| `headers` | map[string]string | no | additional response headers; values are templated |
| `body` | string | yes | response body; Go text/template syntax |

## Template variables

The renderer hands every template a context object:

| Variable | Source | Notes |
| --- | --- | --- |
| `.Profile.Company` | `rules/fake_data.yaml` -> `companies[]` | deterministic per-IP - same client sees same value |
| `.Profile.AdminUser` | `rules/fake_data.yaml` -> `admin_users[]` | |
| `.Profile.AdminPass` | `rules/fake_data.yaml` -> `admin_passes[]` | |
| `.Profile.Stack` | `rules/fake_data.yaml` -> `stacks[]` | |
| `.Profile.Version` | `rules/fake_data.yaml` -> `versions[]` | |
| `.Profile.MinorVersion` | derived | small integer for plausible patch numbers |
| `.Profile.EmailDomain` | `rules/fake_data.yaml` -> `email_domains[]` | |
| `.Path` | request URL path | passed through `extra` map |
| `.Query` | request raw query | passed through `extra` map |

The deterministic mapping is `hash(client_ip) % len(pool)`. The same
attacker sees the same fake company every visit - that's the
"coherent fake application" mechanism.

## Built-in templates

The shipped default file includes:

| Template | Used by | Purpose |
| --- | --- | --- |
| `generic_not_found` | fallthrough route | basic 404 page that still sells the fake |
| `fake_admin` | `/admin*` and similar | login form claiming to be the operator's admin panel |
| `fake_git_config` | `/.git/config` | a synthesized but coherent gitconfig |
| `fake_env` | `/.env` | environment-file shape with fake secrets - register these as canaries |
| `sql_error` | requests with SQLi markers | a verbose-looking SQL error revealing fake schema |
| `api_json_fake` | `/api/*` | JSON API stub returning fake users / records |

See the embedded defaults at
[`internal/rules/defaults/templates.yaml`](../../../internal/rules/defaults/templates.yaml).

## Adding a template

```yaml
templates:
  fake_swagger:
    status: 200
    content_type: application/json
    headers:
      Cache-Control: "no-store"
    body: |
      {
        "openapi": "3.0.0",
        "info": {
          "title": "{{.Profile.Company}} Internal API",
          "version": "{{.Profile.Version}}"
        },
        "paths": {
          "/api/v1/admin/secret": {"get": {"summary": "internal - auth required"}},
          "/api/v1/users/{id}":   {"get": {"summary": "fetch user"}},
          "/api/v1/keys":         {"get": {"summary": "list api keys"}}
        }
      }
```

Then route to it from [`injection_strategy.yaml`](injection-strategy.md):

```yaml
routes:
  - match: prefix
    values: [/openapi, /swagger]
    template: fake_swagger
```

> **Tip.** Templates that *look* like real outputs from real software
> work best. Copy a real Apache 500 page, change the company name and
> stack version, run it through your tarpit. An LLM agent will keep
> probing the fake app instead of moving on.

## Related

- [`rules/injection_strategy.yaml`](injection-strategy.md) - route -> template mapping
- [`rules/fake_data.yaml`](fake-data.md) - pools that feed `.Profile.*`
- [`rules/payloads.yaml`](payloads.md) - prompt-injection content
- [Use case: API recon blocking](../../usecases/api-recon-blocking.md)

---

*Previous: [`rules/payloads.yaml`](payloads.md) | Next: [`rules/injection_strategy.yaml`](injection-strategy.md)*
