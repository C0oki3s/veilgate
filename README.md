# VeilGate

VeilGate is an open-source deception proxy for teams that want to raise the cost
of automated security probing without putting fragile block rules in front of
real users.

It sits in front of a web application, scores each request, and chooses one of
three outcomes:

- **Real**: forward clean traffic to the upstream app.
- **Challenge**: ask suspicious-but-ambiguous clients to solve a browser proof of work.
- **Tarpit**: divert high-confidence agent traffic into a deterministic fake app.

The goal is not magic invulnerability. The goal is better economics: keep humans
and normal automation moving, while making AI-assisted scanners spend time,
tokens, and attention on believable dead ends.

## What It Does

- Reverse proxy with `observe`, `challenge`, `tarpit`, and threshold-driven `auto` modes.
- Detection signals for suspicious user agents, sparse browser headers,
  honeypot paths, timing regularity, scanner paths, SQLi/XSS/OOB markers,
  IP/UA rotation, cookie behavior, request graph shape, JA3/JA4 TLS fingerprints,
  HTTP/2 fingerprints, canary replay, and online ML scoring.
- Browser proof-of-work challenge with both **cookie** and **`X-Veilgate-Token`
  header** transports so cross-origin SPAs can solve and reattach the token
  on subsequent API calls. The 401 challenge response is SPA-aware: it returns
  HTML for top-level navigations and JSON (with the PoW metadata to solve
  inline) for `fetch` / `XHR` contexts.
- Operator-issued **HMAC verifier chain** for server-to-server clients that
  cannot solve the PoW (see [docs/how-to/server-to-server-hmac.md](docs/how-to/server-to-server-hmac.md)).
- Shadow application responses with stable per-client fake profiles.
- Prompt-injection and decoy payload injection for tarpit responses.
- SQLite persistence for events, feature rollups, audit logs, and canaries.
- Prometheus metrics and a lightweight dashboard on the metrics listener.
- Hot-reloadable YAML rule files, fed by the separate
  [veilgate-rules](https://github.com/C0oki3s/veilgate-rules) community repository.

## Quick Start

### Option 1 — Install script (recommended)

Downloads the binary, installs a systemd service, installs community rules, and
writes a starter config in `observe` mode.

```bash
# One-liner
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000

# Or download first, then run
curl -sSL https://veilgate.dev/install.sh -o install.sh
sudo ./install.sh --upstream http://localhost:3000
```

Flags:

| Flag | Default | Description |
| --- | --- | --- |
| `--upstream URL` | `http://127.0.0.1:3000` | Your upstream application |
| `--listen ADDR` | `:8080` | Proxy listen address |
| `--metrics-listen ADDR` | `127.0.0.1:9090` | Metrics (keep private) |
| `--secret SECRET` | prompt or generated | Challenge signing secret |
| `--user USER` | `veilgate` | Service user to run VeilGate |
| `--no-service` | — | Skip systemd service |
| `--no-rules` | — | Skip community rules install |

The packaged config uses `rules_dir: "~/.veilgate/rules"`. Under systemd,
VeilGate runs as the `veilgate` user whose home is `/var/lib/veilgate`, so this
resolves to `/var/lib/veilgate/.veilgate/rules`.

If `--secret` is omitted on a new install, the installer prompts on interactive
terminals and otherwise generates a random secret. If the service user does not
exist, the installer asks before creating it on interactive terminals and
defaults to creation for non-interactive installs.

After install:

```bash
systemctl status veilgate
journalctl -u veilgate -f
```

### Option 2 — Docker

```bash
docker run -d --name veilgate \
  --network host \
  -v /etc/veilgate/veilgate.yaml:/etc/veilgate/veilgate.yaml:ro \
  -v ~/.veilgate/rules:/home/nonroot/.veilgate/rules \
  -e VEILGATE_SECRET=$(openssl rand -hex 32) \
  ghcr.io/c0oki3s/veilgate:latest -config /etc/veilgate/veilgate.yaml
```

### Option 3 — Build from source

Prerequisite: Go `1.25.10` or newer.

```bash
git clone https://github.com/C0oki3s/veilgate.git
cd veilgate
make build
./veilgate -config configs/veilgate.yaml
```

By default VeilGate listens on `:8080`, proxies to `http://localhost:3000`,
and exposes metrics on `:9090`.

The default config starts in `observe` mode — baseline normal traffic before
enabling `challenge` or `tarpit`.

## Operating Modes

| Mode | Use it when | Behavior |
| --- | --- | --- |
| `observe` | Initial rollout and tuning | Scores and records traffic, always forwards upstream |
| `challenge` | You are comfortable interrupting suspicious clients | Medium-score traffic gets proof of work |
| `tarpit` | You are ready to deceive high-confidence agents | High-score traffic receives the fake app |
| `auto` | You want thresholds to drive enforcement per request | Forward below threshold, challenge middle scores, tarpit high scores |

Recommended rollout:

1. Run `observe` for at least several days.
2. Review metrics and event samples for false positives.
3. Enable `challenge` for ambiguous traffic.
4. Enable `tarpit` once your thresholds match your environment.

## Configuration

Start with [configs/veilgate.yaml](configs/veilgate.yaml):

```yaml
listen: ":8080"
upstream: "http://localhost:3000"
mode: "observe"
rules_dir: "~/.veilgate/rules"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  trusted_ips: []
  trusted_proxies: []

metrics:
  listen: ":9090"
```

Full reference: [Configuration reference](docs/reference/config-reference.md).

## Rules

VeilGate ships **no embedded rules**. The binary reads `rules_dir` at startup
and hot-reloads changes; if the directory is empty it starts with zero detection
signals. Rules come from one place:

- **[veilgate-rules](https://github.com/C0oki3s/veilgate-rules)** — the
  community-maintained rule pack. The `install.sh` script clones it
  automatically on first install. You can also update it manually with the
  built-in `update-rules` subcommand — no rebuild, no restart:

| | Installs rules automatically? |
| --- | --- |
| `install.sh` (first run) | **Yes** — clones via git |
| `veilgate` binary (startup) | **No** — reads `rules_dir`, never fetches |
| `veilgate update-rules` | Only when you explicitly call it |

  ```bash
  # Install the latest pack into ~/.veilgate/rules (the default location)
  veilgate update-rules

  # Or pin to a release tag
  veilgate update-rules --dir ~/.veilgate/rules --version v1.2.0

  # List available releases
  veilgate update-rules --list
  ```

  After the install, VeilGate's `fsnotify` watcher picks up the new files
  within ~500 ms. Each existing file is backed up as `<name>.bak` before
  being overwritten (pass `--no-backup` to skip). The installed version is
  recorded in `<rules_dir>/.rules-version.json` so CI and operators can
  check what is running without consulting git metadata.

  Treat both directories as security policy — review changes before
  deploying to production, especially `detector.yaml` and `ip_reputation.yaml`.
  Full guide and rollback procedure:
  [docs/how-to/install-community-rules.md](docs/how-to/install-community-rules.md).

## Documentation

- [Getting Started](docs/getting-started/README.md): local run and first checks.
- [Configuration Reference](docs/reference/config-reference.md): `veilgate.yaml` and rule files.
- [Deployment](docs/deployment/README.md): Linux/systemd installation.
- [Architecture](docs/architecture/README.md): request flow and subsystem design.
- [Operations](docs/operations/README.md): metrics, dashboards, alerts, routine checks.
- [Model Card](docs/model/README.md): ML signal behavior and limitations.
- [Reference Index](docs/reference/README.md): complete lookup-oriented reference pages.
- [Community Rules](docs/how-to/install-community-rules.md): install and update community-maintained rule sets via `veilgate update-rules`.
- [Threat Model](THREAT_MODEL.md): what VeilGate does and does not protect.

## Security Notes

- Only deploy VeilGate in front of systems you own or operate.
- Do not expose the metrics listener directly to the public internet.
- Set `VEILGATE_SECRET` or `challenge.secret` before using `challenge` or
  `tarpit` mode. VeilGate refuses to start outside `observe` mode with the
  default challenge secret.
- Treat files under `rules/` as security policy. Review and version them.
- Start with conservative thresholds and tune from observed traffic.

## Development

```bash
make test
make fmt
make build
```

The top-level [tests](tests) folder contains black-box integration tests.
Package-private unit tests live next to their packages because they verify
unexported detector, TLS fingerprint, tarpit, and ML helpers.

## License

Apache-2.0. See [LICENSE](LICENSE).
