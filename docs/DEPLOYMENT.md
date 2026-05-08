# Linux Deployment

The supported deployment target is a Linux host running VeilGate as a systemd
service.

## Layout

```text
internet / edge proxy
        |
        v
   VeilGate
        |
        v
   upstream app
```

Recommended filesystem layout:

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/veilgate` | VeilGate binary. |
| `/etc/veilgate/veilgate.yaml` | Runtime config. |
| `/etc/veilgate/rules/` | Rule files. |
| `/var/lib/veilgate/` | SQLite store, dumps, audit log. |

## Build And Install

```bash
make build
sudo useradd --system --home /var/lib/veilgate --shell /usr/sbin/nologin veilgate
sudo install -m 0755 veilgate /usr/local/bin/veilgate
sudo mkdir -p /etc/veilgate /var/lib/veilgate
sudo cp configs/veilgate.yaml /etc/veilgate/veilgate.yaml
sudo cp -r rules /etc/veilgate/rules
sudo chown -R veilgate:veilgate /var/lib/veilgate
sudo chown -R root:root /etc/veilgate
```

Update `/etc/veilgate/veilgate.yaml`:

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
rules_dir: "/etc/veilgate/rules"

persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
  dump_path: "/var/lib/veilgate/dumps"

metrics:
  listen: "127.0.0.1:9090"
```

## Challenge Secret

Set a real secret before using `challenge` or `tarpit` mode:

```bash
sudo systemctl edit veilgate
```

Add:

```ini
[Service]
Environment=VEILGATE_SECRET=<long-random-secret>
```

Generate one with:

```bash
openssl rand -hex 32
```

## systemd Service

The repo includes:

```text
deployments/systemd/veilgate.service
```

Install it:

```bash
sudo cp deployments/systemd/veilgate.service /etc/systemd/system/veilgate.service
sudo systemctl daemon-reload
sudo systemctl enable --now veilgate
```

Check status and logs:

```bash
systemctl status veilgate
journalctl -u veilgate -f
```

## Metrics Access

Keep metrics private. The recommended config binds metrics to localhost:

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

Access from your workstation with SSH tunneling:

```bash
ssh -L 9090:127.0.0.1:9090 user@host
```

Then open:

```text
http://localhost:9090/
```

## Rollout

1. Start with `mode: "observe"`.
2. Review dashboard and `veilgate_signal_hits_total`.
3. Tune rules and thresholds.
4. Move to `mode: "challenge"`.
5. Move to `mode: "tarpit"` only after false positives are understood.

## Operational Checks

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
curl http://127.0.0.1:8080/
curl -A "python-requests/2.31.0" http://127.0.0.1:8080/.git/config
```

## Production Notes

- Run as the dedicated `veilgate` user.
- Keep `/etc/veilgate` writable only by root or your deployment system.
- Keep `/var/lib/veilgate` writable only by the service user.
- Keep metrics private.
- Keep `trusted_proxies` limited to proxies you operate.
- Back up or rotate SQLite dumps according to your retention policy.
