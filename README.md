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
- Shadow application responses with stable per-client fake profiles.
- Prompt-injection and decoy payload injection for tarpit responses.
- SQLite persistence for events, feature rollups, audit logs, and canaries.
- Prometheus metrics and a lightweight dashboard on the metrics listener.
- Hot-reloadable YAML rule files.

## Quick Start

Prerequisite: Go `1.25.10` or newer.

```bash
git clone https://github.com/C0oki3s/veilgate.git
cd veilgate
make build
./veilgate -config configs/veilgate.yaml
```

By default VeilGate listens on `:8080`, proxies to `http://localhost:3000`,
and exposes metrics/dashboard on `:9090`.

Then test:

```bash
curl http://localhost:8080/
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl http://localhost:9090/metrics | grep veilgate
```

The default config starts in `observe` mode. That is intentional: you should
baseline normal traffic before enabling challenge or tarpit behavior.

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
rules_dir: "./rules"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  trusted_ips: []
  trusted_proxies: []

metrics:
  listen: ":9090"
```

Full reference: [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md).

## Documentation

- [Getting Started](docs/GETTING_STARTED.md): local run and first checks.
- [Configuration Reference](docs/CONFIG_REFERENCE.md): `veilgate.yaml` and rule files.
- [Deployment](docs/DEPLOYMENT.md): Linux/systemd installation.
- [Architecture](docs/ARCHITECTURE.md): request flow and subsystem design.
- [Operations](docs/OPERATIONS.md): metrics, dashboards, alerts, routine checks.
- [Model Card](docs/MODEL_CARD.md): ML signal behavior and limitations.
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
