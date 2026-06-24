# Admin Dashboard Reference

This page is the lookup reference for the admin dashboard: command-line flags,
routes, API endpoints, files, authentication behavior, and implementation paths.

## Binary And Flags

Entrypoint:

```text
cmd/admin/main.go
```

Run:

```bash
veilgate-admin --config /etc/veilgate/veilgate.yaml --addr 127.0.0.1:8888
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--config` | `veilgate.yaml` if it exists, otherwise `~/.veilgate/veilgate.yaml` | Config file loaded, rendered, and edited by the dashboard. |
| `--addr` | `:8888` | Listen address passed to `http.ListenAndServe`. |
| `--user` | empty | Seeds a first user or updates an existing user's password when used with `--pass`. |
| `--pass` | empty | Password for `--user`. |
| `--db` | `<config-dir>/admin.db` | SQLite DB for users, sessions, reset tokens, and audit rows. Linux installs pass `/var/lib/veilgate/admin.db`. |
| `--audit-log` | `<config-dir>/audit.log` | JSONL audit backup. Linux installs pass `/var/lib/veilgate/admin-audit.log`. |

Installer default:

```text
127.0.0.1:8888
```

Manual binary default:

```text
:8888
```

## Startup Sequence

1. The CLI scans `os.Args` for `--config` early so default DB and audit paths can
   be derived from the selected config directory.
2. `admin.New` loads the YAML config through `internal/config`.
3. If no config is readable, the server continues with an empty config so the UI
   can still render enough to diagnose the path.
4. The admin DB opens. If there are no users, `admin` / `veilgate` is inserted
   and marked `must_change`.
5. `decoys.yaml` is loaded beside the DB. Missing or invalid decoy config falls
   back to the built-in default decoy set and writes a new file.
6. The audit logger is opened with SQLite as primary storage and JSONL as backup.
7. If proxy persistence is enabled, the event store is opened for read-side
   analytics and recommender queries.
8. Embedded templates and static files are parsed.
9. Browser routes and JSON API routes are registered on the same `ServeMux`.

## Browser Routes

| Route | Handler | Auth | Purpose |
| --- | --- | --- | --- |
| `/` | `handleCatchAll` | conditional | Redirects to `/dashboard`. |
| `/login` | `handleLogin` | public | Login form and session creation. |
| `/logout` | `handleLogout` | session-aware | Destroys session and clears cookie. |
| `/forgot-password` | `handleForgotPassword` | public | Issues reset token to server log. |
| `/reset-password` | `handleResetPassword` | public token | Consumes reset token. |
| `/account/password` | `handleChangePassword` | protected | Changes password; forced for seeded default account. |
| `/dashboard` | `handleDashboard` | protected | Summary, status cards, audit stats, and 24-hour analytics. |
| `/analytics` | `handleAnalytics` | protected | Range-selectable charts and live partial refresh. |
| `/settings` | `handleSettings` | protected | Structured and raw `veilgate.yaml` editor. |
| `/signals` | `handleSignals` | protected | Built-in signal overrides and preserved custom signals. |
| `/decoys` | `handleDecoys` | protected | Admin-port honeypot route management. |
| `/recommender` | `handleRecommender` | protected | ML signal recommendations and candidates. |
| `/rules` | `handleRules` | protected | Lists YAML rule files under `rules_dir`. |
| `/rules/{name}` | `handleRuleEdit` | protected | Reads or writes an individual rule file. |
| `/openapi` | `handleOpenAPI` | protected | Imports or edits `openapi.yaml`. |
| `/audit` | `handleAudit` | protected | Shows recent audit events and stats. |
| `/logs` | `handleLogs` | protected | Shows request capture rows or event-store rows. |
| `/static/*` | file server | public | Embedded CSS, JS, and images. |

Unknown paths are handled by the catch-all route. If a path matches a configured
decoy, the admin returns the decoy response and logs `decoy_probe`; otherwise it
returns a generic nginx-style 404.

## JSON API

All JSON API responses use `application/json`. Protected endpoints use the same
session cookie as the browser UI.

| Endpoint | Methods | Auth | Purpose |
| --- | --- | --- | --- |
| `/api/v1/health` | `GET` | public | Health, version, uptime. |
| `/api/v1/auth/login` | `POST` | public | Accepts username/password JSON and sets the session cookie. |
| `/api/v1/auth/logout` | `POST` | protected | Clears the session. |
| `/api/v1/auth/me` | `GET` | protected | Returns active username and auth status. |
| `/api/v1/status` | `GET` | protected | Version, uptime, config path, rules dir, auth status, mode, pending restart. |
| `/api/v1/config` | `GET` | protected | Returns parsed config and pending restart flag. |
| `/api/v1/config` | `PUT` | protected | Applies structured YAML patches while preserving omitted fields. |
| `/api/v1/config/raw` | `GET` | protected | Returns raw config YAML. |
| `/api/v1/config/raw` | `PUT` | protected | Replaces raw config YAML. |
| `/api/v1/rules` | `GET` | protected | Lists rule files. |
| `/api/v1/rules/{name}` | `GET` | protected | Reads one rule file. |
| `/api/v1/rules/{name}` | `PUT` | protected | Writes one rule file. |
| `/api/v1/rules/{name}` | `DELETE` | protected | Deletes one rule file. |
| `/api/v1/signals` | `GET` | protected | Returns built-in signals, overrides, custom signals, and file path. |
| `/api/v1/signals` | `PUT` | protected | Writes signal overrides and custom signals. |
| `/api/v1/openapi` | `GET` | protected | Returns blueprint content and parsed path count. |
| `/api/v1/openapi` | `PUT` | protected | Replaces blueprint content. |
| `/api/v1/audit` | `GET` | protected | Returns recent audit entries. Query: `limit`. |
| `/api/v1/audit/stats` | `GET` | protected | Returns audit counts. |
| `/api/v1/logs` | `GET` | protected | Returns recent request log rows. Query: `limit`. |

Example login:

```bash
curl -i -c admin.cookies \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"veilgate"}' \
  http://127.0.0.1:8888/api/v1/auth/login
```

Example status request:

```bash
curl -b admin.cookies http://127.0.0.1:8888/api/v1/status
```

Example raw config read:

```bash
curl -b admin.cookies http://127.0.0.1:8888/api/v1/config/raw
```

## Files And Persistence

| File | Owner | Written by | Purpose |
| --- | --- | --- | --- |
| `/var/lib/veilgate/admin.db` | admin service | DB layer | Users, sessions, reset tokens, and audit rows on Linux installs. |
| `/var/lib/veilgate/admin-audit.log` | admin service | audit logger | JSONL audit backup on Linux installs. |
| `/var/lib/veilgate/decoys.yaml` | admin service | decoy store | Live editable admin-port decoy list on Linux installs. |
| `<config-dir>/admin.db` | admin service | DB layer | Binary default when `--db` is omitted outside the installer. |
| `<config-dir>/veilgate.yaml` | admin service | settings page/API | Main proxy config. |
| `<rules_dir>/signals.yaml` | admin service | signals page/API | Signal overrides and custom signals. |
| `<rules_dir>/openapi.yaml` | admin service | OpenAPI page/API | Expected API blueprint. |
| `<rules_dir>/**/*.yaml` | admin service | rules page/API | Detection, payload, template, and learned rule files. |
| `<persist.path>` | proxy writes, admin reads | proxy event store | Analytics, request logs, recommender input. |

## Auth Behavior

If a DB opens successfully and has users, DB-backed auth is enabled. If the DB is
empty, the server seeds `admin` / `veilgate` with `must_change=true`.

If the DB cannot open but `--user` and `--pass` are provided, the server falls
back to flag-based auth. If no auth source is available, auth is disabled and
protected pages run as user `admin`.

The password reset flow has no SMTP integration. `/forgot-password` prints a
one-hour reset link to the admin process log.

## Security Headers

Page handlers are wrapped with middleware that sets:

| Header | Value intent |
| --- | --- |
| `Content-Security-Policy` | Restricts scripts, styles, images, fonts, object embedding, frames, and base URI. |
| `X-Content-Type-Options` | Sets `nosniff`. |
| `X-Frame-Options` | Sets `DENY`. |
| `Referrer-Policy` | Sets `no-referrer`. |

## Code Map

| File | Responsibility |
| --- | --- |
| `cmd/admin/main.go` | Flags, defaults, `admin.New`, and `ListenAndServe`. |
| `internal/admin/admin.go` | Server construction, templates, middleware, auth wrapper, routes. |
| `internal/admin/auth.go` | Cookie sessions and credential validation. |
| `internal/admin/db.go` | SQLite schema and user/session/reset-token storage. |
| `internal/admin/audit.go` | Audit entries, stats, DB/JSONL writes. |
| `internal/admin/handlers.go` | Browser page handlers. |
| `internal/admin/api.go` | JSON API. |
| `internal/admin/analytics.go` | Dashboard charts, analytics page, recommender. |
| `internal/admin/decoy.go` | Decoy store, catch-all behavior, decoy responses. |
| `internal/admin/signals.go` | Built-in signal metadata and `signals.yaml` marshaling. |
| `internal/admin/yaml_patch.go` | Comment-preserving config patch operations. |
| `internal/admin/embed.go` | Embedded templates and static assets. |

## Related

- [Use the admin dashboard](../how-to/use-admin-dashboard.md)
- [Admin dashboard operations](../operations/admin-dashboard.md)
- [Admin dashboard functionality overview](../functionalities/admin-dashboard.md)
