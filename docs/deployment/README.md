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

## Docker / Container

The official image is `ghcr.io/c0oki3s/veilgate:latest`. It runs as the
`nonroot` user (uid 65532) on a distroless base with no shell.

The image pre-creates `/home/nonroot/.veilgate/rules` owned by `nonroot` so
the ML miner can write `learned.yaml` even without a volume mount. When you
mount a rules directory over that path you **must not** use `:ro` — the miner
writes to `learned.yaml` on every tick and will log a `WRN miner tick error`
if the filesystem is read-only.

### Minimum run command

```bash
docker run -d --name veilgate \
  --network host \
  -v /etc/veilgate/veilgate.yaml:/etc/veilgate/veilgate.yaml:ro \
  -v /etc/veilgate/rules:/home/nonroot/.veilgate/rules \
  -e VEILGATE_SECRET=$(openssl rand -hex 32) \
  ghcr.io/c0oki3s/veilgate:latest -config /etc/veilgate/veilgate.yaml
```

### Volume mount summary

| Host path | Container path | Flags | Why |
| --- | --- | --- | --- |
| `/etc/veilgate/veilgate.yaml` | `/etc/veilgate/veilgate.yaml` | `:ro` | Config is read-only at runtime |
| `/etc/veilgate/rules` | `/home/nonroot/.veilgate/rules` | *(writable)* | Miner writes `learned.yaml` here every tick |
| `/etc/veilgate/tokens` | `/etc/veilgate/tokens` | `:ro` | Bearer token files |
| `/etc/veilgate/clients` | `/etc/veilgate/clients` | `:ro` | HMAC client files |
| `/var/lib/veilgate` | `/var/lib/veilgate` | *(writable)* | SQLite store and dumps (when `persist.enabled: true`) |

> **SELinux hosts (Fedora, RHEL, CentOS):** append `,z` to writable mounts and
> `,ro,z` to read-only mounts so Docker relabels the files for container access:
> ```
> -v /etc/veilgate/rules:/home/nonroot/.veilgate/rules:z
> -v /etc/veilgate/veilgate.yaml:/etc/veilgate/veilgate.yaml:ro,z
> ```

### Why the rules directory must be writable

The ML miner runs on a background timer (default: every 60 minutes). After
each tick it atomically writes candidate rules to
`<rules_dir>/learned.yaml` via a `.tmp` rename. If the mount is read-only,
every tick logs:

```
WRN miner tick error="miner: write learned.yaml: open .../learned.yaml.tmp: read-only file system"
```

No candidates are persisted, the Bayes classifier never learns from live
traffic, and the isolation forest refit buffer fills but is never committed
to disk. The proxy continues to function, but the online learning component
is silently disabled.

### Checking the miner is healthy

```bash
# No WRN miner lines = writable mount is working
docker logs veilgate 2>&1 | grep "miner"

# Candidates appear after enough traffic crosses min_support threshold
docker exec veilgate cat /home/nonroot/.veilgate/rules/learned.yaml
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
