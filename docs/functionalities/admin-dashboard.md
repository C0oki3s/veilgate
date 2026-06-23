# Admin Dashboard

The admin dashboard is the browser UI and JSON API for operating a VeilGate
instance. It is implemented as a separate binary from the proxy so operators can
start, stop, and expose it independently.

## Start Command

Run the dashboard from source:

```bash
go run ./cmd/admin --config configs/veilgate.yaml
```

Run an installed binary:

```bash
veilgate-admin --config /etc/veilgate/veilgate.yaml
```

The admin binary accepts:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--config` | `veilgate.yaml` if present, otherwise `~/.veilgate/veilgate.yaml` | VeilGate config file to load and edit. |
| `--addr` | `:8888` | HTTP listen address for the admin UI. |
| `--user` | empty | Optional username to seed or update in the admin DB. |
| `--pass` | empty | Optional password for `--user`. |
| `--db` | `<config-dir>/admin.db` | SQLite DB for admin users, sessions, reset tokens, and audit rows. |
| `--audit-log` | `<config-dir>/audit.log` | JSONL audit backup written alongside DB audit rows. |

When installed through `scripts/install.sh`, the installer writes a systemd unit
for `veilgate-admin` and defaults the dashboard bind address to
`127.0.0.1:8888`. Pass `--admin-listen 0.0.0.0:8888` only when the host is
protected by a trusted network boundary or reverse proxy.

## Default Port

- Manual binary default: `:8888`.
- Installer default: `127.0.0.1:8888`.
- Systemd template: `deployments/systemd/veilgate-admin.service` uses
  `ADMIN_LISTEN_PLACEHOLDER`, replaced by the installer with the selected
  listen address.

If the dashboard is bound to localhost on a remote server, tunnel it:

```bash
ssh -L 8888:127.0.0.1:8888 user@host
```

Then open:

```text
http://localhost:8888
```

## Startup Flow

1. `cmd/admin/main.go` parses flags, derives default data paths from the config
   location, creates `admin.AdminConfig`, and starts `http.ListenAndServe`.
2. `internal/admin.New` loads the VeilGate YAML config. If the file is missing
   or unreadable, it starts with an empty config object so the UI can still
   render.
3. The admin DB opens at `<config-dir>/admin.db` unless `--db` is provided.
   If the DB has no users, it seeds `admin` / `veilgate` and requires a password
   change on first login.
4. `decoys.yaml` is loaded next to `admin.db`. If it does not exist, the server
   writes the curated default decoy list.
5. Audit logging is configured with DB storage plus a JSONL backup.
6. If `persist.enabled` and `persist.path` are configured, the dashboard opens
   the proxy event store read-only for analytics, request logs, and
   recommendations.
7. Embedded templates and static assets are parsed from `internal/admin/embed.go`,
   then page routes and `/api/v1/*` routes are registered.

## Pages

| Page | Route | What it shows or does |
| --- | --- | --- |
| Sign in | `/login` | Authenticates the admin session. If auth is disabled, it redirects to `/dashboard`. |
| Change password | `/account/password` | Changes the current password. First-run default credentials are forced through this page. |
| Forgot password | `/forgot-password` | Creates a reset token and prints the reset link to the server log. |
| Reset password | `/reset-password?token=...` | Consumes a reset token and sets a new password. |
| Dashboard | `/dashboard` | Shows mode, score thresholds, scoring window, rules directory health, audit stats, and 24-hour analytics. |
| Analytics | `/analytics` | Shows range-selectable request charts for 1 hour, 24 hours, 7 days, or 30 days. |
| Audit Log | `/audit` | Shows recent admin actions and audit statistics. |
| Request Logs | `/logs` | Shows captured request JSONL rows, or falls back to persisted event-store rows. |
| Settings | `/settings` | Edits proxy, detector, challenge, tarpit, TLS, persistence, capture, metrics, telemetry, and verifier config. |
| Signals | `/signals` | Enables/disables built-in detection signals and changes signal point weights. |
| Decoy Endpoints | `/decoys` | Adds, deletes, resets, and immediately serves admin-port honeypot paths. |
| Recommender | `/recommender` | Runs the ML signal recommender and displays rule-candidate YAML from persisted events. |
| OpenAPI | `/openapi` | Imports or edits `openapi.yaml` so VeilGate can compare traffic against the expected API surface. |
| Browse Rules | `/rules` | Lists editable YAML rule files from the configured rules directory. |
| Rule editor | `/rules/{name}` | Reads or writes an individual YAML rule file. |

The root path `/` redirects to `/dashboard`. Unknown paths do not reveal the
admin app: they are either matched against the live decoy list or returned as a
generic nginx-style 404.

## Actions Available

The admin UI can:

- Update `veilgate.yaml` through structured form tabs or raw YAML editing.
- Mark config changes as pending restart when the proxy must be restarted.
- Edit rule files under `rules_dir`; most rule changes hot-reload within about
  500 ms.
- Import an OpenAPI blueprint into `<rules_dir>/openapi.yaml`.
- Override detection signal weights and disabled/enabled state in
  `<rules_dir>/signals.yaml`.
- Manage decoy endpoints live in `<config-dir>/decoys.yaml`.
- View audit events, request logs, event-store analytics, and recommender output.
- Change the active admin user's password.
- Issue password reset tokens through the server log when no SMTP integration is
  configured.

## JSON API

The dashboard also exposes a session-cookie-authenticated JSON API:

| Endpoint | Methods | Purpose |
| --- | --- | --- |
| `/api/v1/health` | `GET` | Public health, version, and uptime check. |
| `/api/v1/auth/login` | `POST` | Public login endpoint that sets the admin session cookie. |
| `/api/v1/auth/logout` | `POST` | Clears the session. |
| `/api/v1/auth/me` | `GET` | Returns the active user and auth status. |
| `/api/v1/status` | `GET` | Returns version, uptime, config path, rules dir health, mode, and pending restart state. |
| `/api/v1/config` | `GET`, `PUT` | Reads config as structured JSON or applies surgical YAML patches. |
| `/api/v1/config/raw` | `GET`, `PUT` | Reads or replaces raw config YAML. |
| `/api/v1/rules` | `GET` | Lists rule files. |
| `/api/v1/rules/{name}` | `GET`, `PUT`, `DELETE` | Reads, writes, or deletes one rule file. |
| `/api/v1/signals` | `GET`, `PUT` | Reads built-in/custom signal state or writes signal overrides. |
| `/api/v1/openapi` | `GET`, `PUT` | Reads or replaces the OpenAPI blueprint. |
| `/api/v1/audit` | `GET` | Reads recent audit entries. |
| `/api/v1/audit/stats` | `GET` | Reads audit summary counts. |
| `/api/v1/logs` | `GET` | Reads recent request log entries. |

## Files Written

| Path | Purpose |
| --- | --- |
| `<config-dir>/admin.db` | Admin users, sessions, reset tokens, and DB-backed audit events. |
| `<config-dir>/audit.log` | JSONL audit backup. |
| `<config-dir>/decoys.yaml` | Live editable admin-port decoy routes. |
| `<rules_dir>/signals.yaml` | Signal overrides and custom signals. |
| `<rules_dir>/openapi.yaml` | Imported OpenAPI blueprint. |
| `<rules_dir>/**/*.yaml` | Rule files edited through `/rules`. |

On Linux installs, the systemd sandbox grants the admin service write access to
`/etc/veilgate`, `/var/lib/veilgate`, and `/var/log/veilgate`.

## Code Path

- [`cmd/admin/main.go`](../../cmd/admin/main.go) - CLI flags, data-path
  defaults, and HTTP server startup.
- [`internal/admin/admin.go`](../../internal/admin/admin.go) - server
  initialization, auth gate, middleware, template loading, and route wiring.
- [`internal/admin/handlers.go`](../../internal/admin/handlers.go) - browser
  page handlers for auth, settings, rules, signals, OpenAPI, audit, and logs.
- [`internal/admin/analytics.go`](../../internal/admin/analytics.go) - dashboard
  analytics, range charts, and recommender page.
- [`internal/admin/decoy.go`](../../internal/admin/decoy.go) - admin-port decoy
  matching, persistence, and deceptive response bodies.
- [`internal/admin/api.go`](../../internal/admin/api.go) - `/api/v1/*` JSON API.
- [`deployments/systemd/veilgate-admin.service`](../../deployments/systemd/veilgate-admin.service) -
  hardened systemd unit template.
- [`scripts/install.sh`](../../scripts/install.sh) - installer defaults and
  generated admin service.

## Operational Notes

- Treat the dashboard as an operator surface. Keep it on localhost or behind a
  trusted reverse proxy with TLS.
- The generated first-run credentials are `admin` / `veilgate`; the DB marks the
  account as `must_change`, so the first successful login is redirected to the
  password page.
- Settings writes update the YAML file immediately, but the running proxy must
  be restarted for core config changes to take effect.
- Rule, signal, OpenAPI, and decoy edits are written to disk immediately. Rule,
  signal, and OpenAPI changes rely on VeilGate rule hot reload; decoy changes
  take effect inside the admin process immediately.
- Analytics and recommender pages require persistence to be enabled in the proxy
  config and the event DB path to be readable by the admin service.

## Extended Docs

- [How-to: use the admin dashboard](../how-to/use-admin-dashboard.md)
- [Reference: admin dashboard](../reference/admin-dashboard-reference.md)
- [Operations: admin dashboard](../operations/admin-dashboard.md)
- [Security: admin dashboard private access](../operations/admin-dashboard-security.md)
