# How to set up API blueprinting

> **Goal:** Tell VeilGate which paths your application actually serves so it
> can fire the `api_blueprint_miss` signal whenever a client probes a path
> that is not in your documented API — a common recon pattern before an attack.

**On this page:**

1. [How it works](#how-it-works)
2. [Step 1 — enable rules_dir](#step-1--enable-rules_dir)
3. [Step 2 — choose a format](#step-2--choose-a-format)
4. [Step 3 — verify the signal fires](#step-3--verify-the-signal-fires)
5. [Format reference](#format-reference)
6. [Hot reload](#hot-reload)
7. [Tuning the signal weight](#tuning-the-signal-weight)
8. [Related](#related)

## How it works

VeilGate loads a route map at startup and whenever the file changes on disk.
On each request it checks two things:

1. **Namespace check** — is the first path segment (`api`, `v1`, etc.) one of
   the known prefixes from the blueprint?
2. **Route match** — does the full path match any blueprint route?

The `api_blueprint_miss` signal fires only when both conditions are true: the
path is *in* your API namespace but is *not* a documented route. Paths outside
any known namespace (e.g. `/static/logo.png`) are silently ignored — the signal
is not intended to catch every undocumented path, only probing within your API
surface.

Default points: **15**. Override in `rules/signals.yaml` (see
[Tuning the signal weight](#tuning-the-signal-weight)).

Signal family for endpoint-correlation metrics: `recon`.

## Step 1 — enable rules_dir

The blueprint file must be placed in the directory configured by `rules_dir`.
If you have not set `rules_dir` yet, add it to `veilgate.yaml`:

```yaml
rules_dir: "~/.veilgate/rules"
```

Create the directory if it does not exist:

```bash
mkdir -p ~/.veilgate/rules
```

## Step 2 — choose a format

VeilGate accepts three file formats. It searches for candidate files in this
order — the first file found wins:

| Priority | Filename | Format |
| --- | --- | --- |
| 1 | `api_blueprint.yaml` | Simple routes list (YAML) |
| 2 | `api_blueprint.json` | Simple routes list (JSON) |
| 3 | `openapi.yaml` | OpenAPI 3.x or Swagger 2.0 (YAML) |
| 4 | `openapi.json` | OpenAPI 3.x or Swagger 2.0 (JSON) |

If none of these files exists in `rules_dir` the signal is silently disabled
— no error, no score impact.

### Option A — simple routes list (recommended for small APIs)

Create `~/.veilgate/rules/api_blueprint.yaml`:

```yaml
routes:
  - /api/health
  - /api/users
  - /api/users/{id}
  - /api/orders
  - /api/orders/{id}
  - /api/orders/{id}/items
  - /v1/status
```

Use `{placeholder}` for any variable path segment. The placeholder name does
not matter — `{id}`, `{slug}`, `{uuid}` all behave identically. Any
non-empty value in that position matches.

The same format works as JSON (`api_blueprint.json`):

```json
{
  "routes": [
    "/api/health",
    "/api/users",
    "/api/users/{id}",
    "/api/orders",
    "/api/orders/{id}/items"
  ]
}
```

### Option B — OpenAPI 3.x spec

If you already maintain an OpenAPI 3.x document, drop it (or a copy) into
`rules_dir` as `openapi.yaml`. VeilGate reads only the `paths:` keys — the
rest of the document is ignored, so you can use your full spec without
stripping it:

```yaml
openapi: "3.0.3"
info:
  title: My API
  version: "2.0"
paths:
  /api/health: {}
  /api/users: {}
  /api/users/{id}: {}
  /api/orders: {}
  /api/orders/{id}:
    get:
      summary: Get order
    delete:
      summary: Delete order
  /api/orders/{id}/items: {}
```

Path parameter names (`{id}`, `{orderId}`, etc.) are preserved and match any
non-empty segment.

### Option C — Swagger 2.0 spec with basePath

Swagger 2.0 documents that use `basePath` are supported. VeilGate prepends the
`basePath` to every path key in `paths:` before building the route table:

```yaml
swagger: "2.0"
basePath: /v1
paths:
  /users: {}
  /users/{id}: {}
  /orders/{id}: {}
  /status: {}
```

After loading, the effective routes are `/v1/users`, `/v1/users/{id}`,
`/v1/orders/{id}`, and `/v1/status`. Requests to `/v1/unknown` will fire
`api_blueprint_miss`; requests to `/other/path` will not.

## Step 3 — verify the signal fires

Restart VeilGate (blueprint loading does not require a restart if you set the
file before VeilGate started, but a restart is the safest first check):

```bash
sudo systemctl restart veilgate
```

The startup log should confirm how many routes were loaded:

```
INF api blueprint loaded routes=42
```

If you see no such line, verify `rules_dir` is set and at least one of the four
candidate filenames exists in that directory.

Send a request to a path that is in the namespace but not in the blueprint:

```bash
curl -v http://localhost:8080/api/admin/debug
```

Then check the signal counter:

```bash
curl -s http://127.0.0.1:9090/metrics | grep api_blueprint_miss
```

You should see `veilgate_signal_hits_total{signal="api_blueprint_miss"}` with a
count of at least 1. If the counter is zero, confirm the path's first segment
(`api` in the example above) is present in at least one blueprint route — paths
outside all known namespaces are not scored.

## Format reference

### Path matching rules

| Rule | Example blueprint route | Matches | Does not match |
| --- | --- | --- | --- |
| Exact segment | `/api/users` | `/api/users`, `/api/users/` | `/api/users/42` |
| Path parameter | `/api/users/{id}` | `/api/users/42`, `/api/users/abc` | `/api/users` |
| Case-insensitive | `/API/Users` | `/api/users`, `/API/USERS` | — |
| No wildcard prefix | `/api/orders` | `/api/orders` | `/api/orders/99/items` |

Path parameters match exactly one segment — there is no `**` glob syntax. If
`/api/orders/{id}/items` is a real route, it must be listed explicitly.

### Namespace inference

The namespace is derived automatically from the first segment of every blueprint
route. If your blueprint contains `/api/users` and `/v1/status`, then both `api`
and `v1` become known namespaces. Only requests whose first path segment is in a
known namespace are eligible for `api_blueprint_miss`.

### Empty file handling

An empty `routes` list or a `paths` block with no keys is treated the same as no
file — the signal is disabled and no warning is emitted.

## Hot reload

VeilGate watches `rules_dir` with `fsnotify`. Editing or replacing any of the
four candidate files triggers a reload within a few seconds — no restart
required. The log line on reload:

```
INF api blueprint reloaded routes=55
```

If the new file is empty or cannot be parsed, the old blueprint stays active and
a warning is logged:

```
WRN load api blueprint failed err="yaml: unmarshal error..."
```

## Tuning the signal weight

The default weight is 15 points. To increase it (e.g. for high-fidelity APIs
where any undocumented route access is a strong signal) or to disable it
entirely, create `~/.veilgate/rules/signals.yaml`:

```yaml
signals:
  api_blueprint_miss:
    enabled: true
    points: 25
```

To disable the signal without removing the blueprint file:

```yaml
signals:
  api_blueprint_miss:
    enabled: false
```

The `signals.yaml` file is hot-reloaded on change.

## Related

- [Config: `rules_dir`](../config/top-level.md#rules_dir)
- [Config: rule customization](../config/rules/customization.md)
- [How-to: Endpoint correlation](endpoint-correlation.md)
- [How-to: Observe and tune](observe-and-tune.md)

---

*Previous: [Install community rules](install-community-rules.md) · Next: [Monitor with Prometheus](monitor-with-prometheus.md)*
