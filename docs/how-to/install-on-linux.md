# How to install VeilGate on Linux

> **Goal:** End up with VeilGate running as a hardened systemd service on
> a fresh Ubuntu / Debian / RHEL host, with the proxy on `:8080` and
> private metrics on `127.0.0.1:9090`.

**On this page:**

1. [Install script (recommended)](#install-script-recommended)
2. [Clean Previous Install](#clean-previous-install)
3. [Manual install from source](#manual-install-from-source)
4. [Lay out the filesystem](#lay-out-the-filesystem)
5. [Drop in the systemd unit](#drop-in-the-systemd-unit)
6. [Verify](#verify)
7. [Common problems](#common-problems)
8. [Related](#related)

## Install script (recommended)

The quickest path — downloads the binary, installs a systemd service, installs
community rules, and writes a starter config in `observe` mode:

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

Available flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream URL` | `http://127.0.0.1:3000` | Your upstream application |
| `--listen ADDR` | `:8080` | Proxy listen address |
| `--metrics-listen ADDR` | `127.0.0.1:9090` | Metrics (keep private) |
| `--secret SECRET` | prompt or generated | Challenge signing secret |
| `--user USER` | `veilgate` | Service user to run VeilGate |
| `--no-service` | — | Skip systemd service |
| `--no-rules` | — | Skip community rules install |

The generated config keeps `rules_dir: "~/.veilgate/rules"`. Because the
systemd service runs as the `veilgate` user with home `/var/lib/veilgate`, that
path resolves at runtime to `/var/lib/veilgate/.veilgate/rules`.

If `--secret` is omitted on a new install, the installer prompts on interactive
terminals and otherwise generates a random secret. If the service user does not
exist, the installer asks before creating it on interactive terminals and
defaults to creation for non-interactive installs.

After install:

```bash
systemctl status veilgate
journalctl -u veilgate -f
```

## Clean Previous Install

Use this before reinstalling from scratch if an earlier install left stale
service files, permissions, or rule directories behind:

```bash
sudo systemctl disable --now veilgate 2>/dev/null || true
sudo rm -f /etc/systemd/system/veilgate.service
sudo systemctl daemon-reload
sudo systemctl reset-failed veilgate 2>/dev/null || true

sudo rm -f /usr/local/bin/veilgate
sudo rm -rf /etc/veilgate /var/lib/veilgate /var/log/veilgate
sudo userdel veilgate 2>/dev/null || true
```

Then rerun the installer:

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

## Manual install from source

Use this path when you want full control over the build or are in an
air-gapped environment.

Prerequisites:

- A Linux host running systemd (Ubuntu 22.04+, Debian 12+, RHEL/Rocky
  9+, Alma 9+).
- Go 1.25.10+ to build, OR a prebuilt `veilgate` binary.
- A real upstream HTTP service reachable from the host. The default
  config assumes `http://127.0.0.1:3000`.
- Optional: a TLS cert + key for the proxy listener. Required when you
  want JA3/JA4 fingerprinting.

```bash
git clone https://github.com/C0oki3s/veilgate
cd veilgate
make build
```

The binary lands at `./veilgate`. It is fully static (CGO disabled,
pure-Go SQLite) so it runs on any glibc-free environment too.

## Lay out the filesystem

```bash
sudo useradd --system --home /var/lib/veilgate --shell /usr/sbin/nologin veilgate
sudo install -m 0755 veilgate /usr/local/bin/veilgate
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate
sudo install -d -o veilgate -g veilgate -m 0700 /var/lib/veilgate
sudo install -d -o veilgate -g veilgate -m 0700 /var/log/veilgate
sudo install -m 0640 -o root -g veilgate \
  configs/veilgate.yaml /etc/veilgate/veilgate.yaml
sudo -u veilgate /usr/local/bin/veilgate update-rules --dir ~veilgate/.veilgate/rules
sudo chown -R veilgate:veilgate ~veilgate/.veilgate/rules
sudo find ~veilgate/.veilgate/rules -type d -exec chmod 0750 {} +
sudo find ~veilgate/.veilgate/rules -type f -exec chmod 0640 {} +
```

This gives you:

| Path | Owner / mode | Purpose |
| --- | --- | --- |
| `/usr/local/bin/veilgate` | root:root 0755 | binary |
| `/etc/veilgate/veilgate.yaml` | root:veilgate 0640 | runtime config |
| `~veilgate/.veilgate/rules/` | veilgate:veilgate 0750 | rule files and miner output |
| `/var/lib/veilgate/` | veilgate:veilgate 0700 | SQLite, audit log, capture |
| `/var/log/veilgate/` | veilgate:veilgate 0700 | reserved for future log files |

## Drop in the systemd unit

```bash
sudo install -m 0644 deployments/systemd/veilgate.service \
  /etc/systemd/system/veilgate.service
sudo systemctl daemon-reload
sudo systemctl enable --now veilgate
```

The unit ships with full sandboxing: `NoNewPrivileges=true`,
`ProtectSystem=strict`, `CapabilityBoundingSet=` empty,
`SystemCallFilter=@system-service`, and `MemoryDenyWriteExecute=true`.
Validate the hardening score:

```bash
sudo systemd-analyze security veilgate.service
```

A score of `OK` or `GOOD` is the target.

## Verify

```bash
# 1. Service health
systemctl status veilgate

# 2. Live logs
journalctl -u veilgate -f

# 3. Metrics endpoint (run on the host or via SSH tunnel)
curl -sS http://127.0.0.1:9090/metrics | grep -m5 veilgate_

# 4. Forward a real request
curl -i http://127.0.0.1:8080/

# 5. Smoke-test agent detection
curl -i -A "python-requests/2.31.0" http://127.0.0.1:8080/.git/config
```

The smoke test should produce a tarpit or challenge response (depending
on your `mode` setting), not a forwarded response. Watch the log line
in `journalctl` for the matching signal.

## Common problems

### "permission denied" reading rules at startup

The service user doesn't own the rules dir. Fix:

```bash
sudo chown -R veilgate:veilgate ~veilgate/.veilgate/rules
sudo chmod -R u+rwX,g-rwx,o-rwx ~veilgate/.veilgate/rules
```

### Service starts but exits immediately

Check the journal for a YAML parse error. Most often it's an indented
`scrub:` block under `capture:` that doesn't match the schema. Compare
against [config/capture](../config/capture.md).

### `systemd-analyze security` flags `CapabilityBoundingSet=`

That flag is intentional — VeilGate doesn't need any Linux capability
in its default config. If you uncommented `AmbientCapabilities=CAP_NET_BIND_SERVICE`
to bind a privileged port, `systemd-analyze` will note the relaxation.
That's expected.

### Cannot bind to port 80 / 443

Either:
1. Run behind another reverse proxy (Caddy, nginx) that owns the
   privileged port, or
2. Grant the binary the bind capability:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/veilgate
```

…and uncomment `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the
systemd unit.

## Related

- [Deployment reference](../deployment/README.md)
- [How-to: Observe-mode rollout & threshold tuning](observe-and-tune.md)
- [Config: top-level settings](../config/top-level.md)

---

*Previous: [How-to index](README.md) · Next: [Observe-mode rollout & threshold tuning](observe-and-tune.md)*
