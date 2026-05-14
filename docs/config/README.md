# Configuration reference

VeilGate has two configuration surfaces.

The **top-level config** at `/etc/veilgate/veilgate.yaml` controls the
proxy itself: ports, mode, upstream, persistence, capture, metrics. It
is loaded once at startup; changes require a service restart.

The **rules directory** at `/etc/veilgate/rules/` controls the
detection logic and the tarpit content. Files in this directory are
hot-reloaded — edits take effect within ~500 ms with no restart.

This reference is one page per file or section.

## Top-level config (`/etc/veilgate/veilgate.yaml`)

| Section | Purpose |
| --- | --- |
| [Top-level keys](top-level.md) | `mode`, `listen`, `upstream`, `rules_dir` |
| [`tls:`](tls.md) | HTTPS termination + JA3/JA4 fingerprinting |
| [`detector:`](detector.md) | thresholds, honeypot paths, trusted IPs/proxies |
| [`tarpit:`](tarpit.md) | latency / body-cap settings for the fake app |
| [`challenge:`](challenge.md) | proof-of-work secret, difficulty, TTL |
| [`metrics:`](metrics.md) | Prometheus / dashboard listener |
| [`persist:`](persist.md) | SQLite event store + retention |
| [`capture:`](capture.md) | optional JSONL request capture |

## Rules directory (`/etc/veilgate/rules/`)

| File | Purpose |
| --- | --- |
| [`detector.yaml`](rules/detector.md) | rule-based scorer: UA, headers, timing, toolchain, injection markers |
| [`ml.yaml`](rules/ml.md) | online ML hyperparameters + path redaction + miner |
| [`payloads.yaml`](rules/payloads.md) | prompt-injection payload library |
| [`templates.yaml`](rules/templates.md) | tarpit response templates |
| [`injection_strategy.yaml`](rules/injection-strategy.md) | route → template mapping + payload weights |
| [`tls_fingerprints.yaml`](rules/tls-fingerprints.md) | JA3 / JA4 known-fingerprint database |
| [`ip_reputation.yaml`](rules/ip-reputation.md) | CIDR categories + fleet-rotation thresholds |
| [`challenge.yaml`](rules/challenge.md) | challenge HTML template + difficulty |
| `vulnerabilities.yaml` | honeypot path + SQLi pattern lists for the tarpit |
| `fake_data.yaml` | fake company / user / version pools |
| `dashboard.yaml` | live-dashboard panel config |
| `learned.yaml` | miner-managed candidate rules (operator promotes) |

## Reload semantics

| Surface | Reload mechanism |
| --- | --- |
| Top-level config | restart required (`systemctl restart veilgate`) |
| Files under `rules_dir` | hot-reload via fsnotify, debounced 500 ms |
| `learned.yaml` | hot-reload + miner re-syncs from SQLite on every tick |
| Trusted-IP allowlist | top-level → restart required |

## Conventions

- Boolean keys default to `false` unless documented otherwise.
- Integer keys with `0` as default mean *use the built-in default*,
  not *disabled*. Where `0` actually disables, the per-key reference
  page says so explicitly.
- Path keys can be absolute or relative; relative paths resolve against
  the working directory of the systemd unit.
- Empty `[]` lists are valid and mean "no entries" — the loader does
  not fall back to defaults.

## Related

- [Deployment guide](../DEPLOYMENT.md) — install + systemd unit
- [How-to guides](../how-to/README.md) — task-oriented walk-throughs
- [Use cases](../usecases/README.md) — objective-driven examples

---

*Previous: [How-to guides](../how-to/README.md) · Next: [Top-level keys](top-level.md)*
