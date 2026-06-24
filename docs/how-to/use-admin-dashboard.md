# Use The Admin Dashboard

This guide walks through day-to-day use of the VeilGate admin dashboard after
the proxy is installed or running locally.

## 1. Start The Dashboard

From source:

```bash
go run ./cmd/admin --config configs/veilgate.yaml
```

From an installed host:

```bash
sudo systemctl status veilgate-admin
sudo journalctl -u veilgate-admin -f
```

Manual installed start:

```bash
/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr 127.0.0.1:8888
```

The binary default is `:8888`. The installer default is `127.0.0.1:8888`, which
keeps the dashboard private to the host.

On a remote server, tunnel the private listener:

```bash
ssh -L 8888:127.0.0.1:8888 user@host
```

Then open:

```text
http://localhost:8888
```

For production, keep the admin port behind Tailscale, a general VPN, or a
private subnet with NSG/security-group restrictions. See
[Admin Dashboard Security And Private Access](../operations/admin-dashboard-security.md).

## 2. Sign In

On first run, if the admin DB has no users, the dashboard seeds:

```text
username: admin
password: veilgate
```

The account is marked for mandatory password change. After login, the dashboard
redirects to `/account/password`; choose a real password before continuing.

If you want to seed or rotate a user from the command line:

```bash
veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --user admin \
  --pass 'replace-this-password'
```

When the DB already contains that user, the password is updated.

## 3. Read The Dashboard Page

Open `/dashboard` first. It summarizes the current operating state:

| Area | What to check |
| --- | --- |
| Mode | Confirms whether VeilGate is in `observe`, `challenge`, or `tarpit`. |
| Score thresholds | Shows the challenge and tarpit score cutoffs currently loaded from config. |
| Window | Shows the detector scoring window in seconds. |
| Rules directory | Confirms whether the configured `rules_dir` exists. |
| Audit stats | Shows recent admin actions and failed/successful operations. |
| Analytics | Shows the last 24 hours of decisions when persistence is enabled. |

If analytics are empty, check that the proxy config has persistence enabled:

```yaml
persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
```

The admin service must also be able to read that DB path.

## 4. Edit Settings

Open `/settings` to edit the main `veilgate.yaml` file. The page has structured
tabs for the common config groups and a raw YAML editor for direct edits.

Common edits:

| Tab | Typical use |
| --- | --- |
| Proxy | Change `listen`, `upstream`, mode, or `rules_dir`. |
| Detector | Tune score thresholds, scoring window, probe paths, and trusted IPs. |
| Challenge | Set challenge secret, difficulty, and token TTL. |
| Tarpit | Tune latency, response size, and response cache behavior. |
| TLS | Enable TLS and set certificate/key paths. |
| Persistence | Enable event storage and retention. |
| Capture | Enable JSONL request capture. |
| Metrics | Change metrics listener and API key. |
| Observability | Configure OTLP traces, logs, and metrics push. |
| Verifiers | Enable HMAC or bearer-token caller verification. |
| Raw | Edit the complete YAML file directly. |

After saving settings, the dashboard marks the config as pending restart. Restart
the proxy for core config changes to take effect:

```bash
sudo systemctl restart veilgate
```

Rule files are different: they usually hot-reload without restarting the proxy.

## 5. Tune Detection Signals

Open `/signals` to tune built-in scoring signals.

Use this page when:

- A normal client is being challenged too often.
- A scanner pattern is under-scored.
- You want to temporarily disable a noisy signal.
- You want to preserve custom signals while changing built-in weights.

Changes are written to:

```text
<rules_dir>/signals.yaml
```

VeilGate hot-reloads the file, usually within about 500 ms.

## 6. Manage Decoy Endpoints

Open `/decoys` to manage honeypot paths served by the admin process itself.
These paths protect the admin port from obvious scanners by returning plausible
fake login pages, forbidden pages, API errors, or generic not-found responses.

Examples:

| Path | Kind | Result |
| --- | --- | --- |
| `/wp-login.php` | login | Fake login page with HTTP 200. |
| `/.env` | forbidden | Fake forbidden secret-file response. |
| `/actuator/env` | apierror | Fake JSON server error. |
| `/shell.php` | notfound | Generic nginx-style 404. |

Decoy edits write to:

```text
/var/lib/veilgate/decoys.yaml
```

They take effect immediately inside the admin process. No proxy restart is
needed.

## 7. Edit Rules

Open `/rules` to browse YAML rule files under the configured `rules_dir`.
Open any file to edit it in the browser:

```text
/rules/detector/config.yaml
/rules/payloads/config.yaml
```

Rule saves write directly to disk and are audit-logged. Most rule files
hot-reload quickly; if a specific subsystem does not pick up a change, restart
the proxy and check `journalctl -u veilgate -f`.

## 8. Import An OpenAPI Blueprint

Open `/openapi` to paste or upload an OpenAPI file. The dashboard writes it to:

```text
<rules_dir>/openapi.yaml
```

VeilGate uses this blueprint to identify traffic that probes undocumented API
paths. After saving, the page shows the number of paths parsed from the file.

## 9. Review Logs, Audit, And Analytics

Use these pages during tuning:

| Page | Use |
| --- | --- |
| `/logs` | Review recent request decisions, scores, client IDs, and paths. |
| `/audit` | Review admin actions such as login, settings saves, rule edits, and decoy changes. |
| `/analytics` | Compare decisions, score histogram, top paths, top clients, user agents, and signal frequency across selectable time ranges. |
| `/recommender` | Generate signal recommendations and inspect current ML rule candidates. |

`/logs` prefers capture JSONL when capture is enabled. If no capture file is
available, it falls back to the persisted event store.

## Related

- [Admin dashboard reference](../reference/admin-dashboard-reference.md)
- [Admin dashboard operations](../operations/admin-dashboard.md)
- [Admin dashboard functionality overview](../functionalities/admin-dashboard.md)
