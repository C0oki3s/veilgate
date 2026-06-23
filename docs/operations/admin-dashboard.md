# Admin Dashboard Operations

This page covers deployment, hardening, backup, monitoring, and troubleshooting
for the VeilGate admin dashboard.

## Deployment Model

The dashboard is a separate process from the proxy:

```text
operator browser
        |
        v
veilgate-admin  --->  /etc/veilgate/veilgate.yaml
        |
        +--------->  /etc/veilgate/admin.db
        +--------->  /etc/veilgate/audit.log
        +--------->  /etc/veilgate/decoys.yaml
        +--------->  /var/lib/veilgate/events.db (read-side analytics)
```

The proxy can run without the dashboard, and the dashboard can start without the
proxy. This is intentional: operators can repair config, inspect logs, or edit
rules even while the proxy is stopped.

## systemd Service

The repository includes:

```text
deployments/systemd/veilgate-admin.service
```

The installer generates a unit with:

```ini
ExecStart=/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr 127.0.0.1:8888
```

Useful commands:

```bash
sudo systemctl status veilgate-admin
sudo systemctl restart veilgate-admin
sudo journalctl -u veilgate-admin -f
```

The admin service uses `PartOf=veilgate.service`, so it is tied to the proxy
unit lifecycle when installed through the provided service template. It can also
run standalone for config management.

## Bind Address Policy

Preferred production bind:

```text
127.0.0.1:8888
```

This requires SSH tunneling or a private reverse proxy and avoids exposing the
admin UI directly to the internet.

Only bind publicly when another control protects it:

```bash
veilgate-admin --config /etc/veilgate/veilgate.yaml --addr 0.0.0.0:8888
```

If you expose it through a reverse proxy, put TLS and access control in front of
it. The dashboard has application auth, but it is still an operator surface that
can edit config and rules.

For detailed private-access patterns with Tailscale, a general VPN, and cloud
NSG/security-group rules, see
[Admin Dashboard Security And Private Access](admin-dashboard-security.md).

## File Permissions

The systemd sandbox grants write access to:

```text
/etc/veilgate
/var/lib/veilgate
/var/log/veilgate
```

Recommended ownership:

```bash
sudo chown root:veilgate /etc/veilgate/veilgate.yaml
sudo chmod 0640 /etc/veilgate/veilgate.yaml
sudo chown -R veilgate:veilgate /var/lib/veilgate
sudo chmod 0700 /var/lib/veilgate
```

The admin service needs write permission for `admin.db`, `audit.log`, and
`decoys.yaml`. It needs rule directory write permission if operators will edit
signals, OpenAPI, or rule YAML from the dashboard.

## Backups

Back up these files before major edits or upgrades:

```bash
sudo tar -czf veilgate-admin-backup.tgz \
  /etc/veilgate/veilgate.yaml \
  /etc/veilgate/admin.db \
  /etc/veilgate/audit.log \
  /etc/veilgate/decoys.yaml \
  /var/lib/veilgate/.veilgate/rules
```

If your install uses a different `rules_dir`, back up that directory instead of
`/var/lib/veilgate/.veilgate/rules`.

For a quick config-only backup:

```bash
sudo cp /etc/veilgate/veilgate.yaml /etc/veilgate/veilgate.yaml.bak
```

## Upgrade Checklist

1. Back up `veilgate.yaml`, `admin.db`, `decoys.yaml`, and `rules_dir`.
2. Upgrade or replace `/usr/local/bin/veilgate-admin`.
3. Run `sudo systemctl daemon-reload` if the unit changed.
4. Restart the dashboard.
5. Sign in and verify `/dashboard`, `/settings`, `/rules`, and `/logs`.
6. Check `journalctl -u veilgate-admin -n 100` for DB, template, or permission
   errors.

## Monitoring

The admin dashboard exposes a public health endpoint:

```bash
curl -fsS http://127.0.0.1:8888/api/v1/health
```

Expected response includes:

```json
{
  "status": "ok",
  "version": "v...",
  "uptime": "..."
}
```

For authenticated state, use `/api/v1/status` with a session cookie. That
endpoint reports config path, rules directory, auth enabled state, mode, and
pending restart state.

Logs to watch:

```bash
sudo journalctl -u veilgate-admin -f
sudo journalctl -u veilgate -f
```

Dashboard analytics depend on the proxy event store. If persistence is disabled,
the admin UI still works, but analytics and recommender output will be empty.

## Troubleshooting

### Dashboard Does Not Start

Check service logs:

```bash
sudo journalctl -u veilgate-admin -n 100 --no-pager
```

Common causes:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `bind: address already in use` | Another process uses port 8888. | Change `--addr` or stop the other process. |
| `permission denied` writing DB/log | Service cannot write config directory. | Fix ownership or systemd `ReadWritePaths`. |
| Template parse error | Embedded templates and binary are mismatched. | Rebuild/reinstall the admin binary. |
| Empty config values | Wrong `--config` path. | Start with the intended `/etc/veilgate/veilgate.yaml`. |

### Cannot Sign In

If this is first run, try the seeded credentials:

```text
admin / veilgate
```

If the password was changed and lost, start the admin once with explicit
credentials to update that user:

```bash
sudo systemctl stop veilgate-admin
sudo -u veilgate /usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr 127.0.0.1:8888 \
  --user admin \
  --pass 'new-password'
```

Then stop that foreground process and restart the service.

Alternatively, use the forgot-password page. It prints a one-hour reset URL to
the admin log:

```bash
sudo journalctl -u veilgate-admin -f
```

### Settings Save But Proxy Behavior Does Not Change

The settings page writes `veilgate.yaml` immediately, but the running proxy must
be restarted for many config fields:

```bash
sudo systemctl restart veilgate
```

Rule, signal, and OpenAPI edits are written under `rules_dir` and usually
hot-reload without a proxy restart.

### Analytics Are Empty

Check config:

```yaml
persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
```

Then check permissions:

```bash
sudo -u veilgate test -r /var/lib/veilgate/events.db
```

If the file does not exist, the proxy may not have processed traffic yet or
persistence may be disabled.

### Request Logs Are Empty

`/logs` first checks capture JSONL when capture is enabled:

```yaml
capture:
  enabled: true
  path: "/var/lib/veilgate/capture.jsonl"
```

If capture is unavailable, it falls back to persisted events. Empty logs usually
mean both capture and persistence have no recent data.

### Decoys Are Not Matching

For prefix decoys, paths should end with `/`:

```yaml
decoys:
  - path: "/wp-admin/"
    prefix: true
    kind: login
```

Exact decoys match one path only:

```yaml
decoys:
  - path: "/.env"
    kind: forbidden
```

Edits made on `/decoys` are live immediately. If a direct file edit does not
show up, restart `veilgate-admin` so the process reloads `decoys.yaml`.

## Incident Response Notes

If the dashboard was exposed unexpectedly:

1. Bind it back to `127.0.0.1:8888`.
2. Restart `veilgate-admin`.
3. Change the admin password.
4. Review `/audit` for login attempts, settings saves, rule edits, and decoy
   changes.
5. Check `audit.log` and `admin.db` backups.
6. Review `/logs` and proxy logs for unusual requests to admin-like paths.
7. Rotate any secrets that may have been visible in `veilgate.yaml`.

## Related

- [Admin dashboard security and private access](admin-dashboard-security.md)
- [Use the admin dashboard](../how-to/use-admin-dashboard.md)
- [Admin dashboard reference](../reference/admin-dashboard-reference.md)
- [Security hardening](security_hardening.md)
