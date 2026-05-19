# How Configuration Is Resolved

This page explains where each VeilGate setting comes from at runtime and which
changes require a restart. It follows the same directive-oriented style used by
the module docs: source, default behavior, code path, and operational effect.

## The Three Configuration Layers

| Layer | Path | Reload |
| --- | --- | --- |
| Top-level config | `/etc/veilgate/veilgate.yaml` | restart required |
| Rules directory | `~/.veilgate/rules/*.yaml` | supported files hot-reload |
| Environment variables | service environment | restart required |

The top-level config controls what the proxy is: listener, upstream, mode,
TLS, persistence, capture, metrics, and verifier chain. The rules directory
controls how the proxy behaves: scoring rules, fingerprint labels, challenge
HTML, tarpit content, ML settings, dashboard layout, and learned candidates.
Environment variables are used for secrets that should not live in YAML.

## Top-Level `veilgate.yaml`

Syntax:  `veilgate -config <path>`  
Default: `configs/veilgate.yaml` in local development  
Context: startup

The top-level config is loaded once at startup. Changes to this file require a
process restart. Sending `SIGHUP` is not a config reload mechanism in the
current codebase.

### Code path

- [`internal/config/config.go`](../../internal/config/config.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

### Restart-required sections

- `listen`
- `upstream`
- `mode`
- `rules_dir`
- `tls`
- `detector` top-level thresholds, trusted IPs, and honeypot paths
- `tarpit`
- `challenge.secret`
- `metrics.listen`
- `persist`
- `capture`
- `verifiers`

Validation:

```bash
go run ./cmd/veilgate -config configs/veilgate.yaml
curl -i http://localhost:8080/
```

## Rules Directory

Syntax:  `rules_dir: "<directory>"`  
Default: empty, use embedded defaults  
Context: top-level config

Each rule loader reads from `rules_dir` when the file exists. If a file is
missing, that file falls back to the embedded default. Overrides are full-file
replacements, not deep merges. A custom `rules/detector.yaml` should therefore
contain the complete detector rule structure you want active.

### Code path

- [`internal/rules/loader.go`](../../internal/rules/loader.go)
- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go)
- [`internal/rules/watcher.go`](../../internal/rules/watcher.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

### Startup resolution

| Scenario | Result |
| --- | --- |
| `rules_dir` is empty | All rule files use embedded defaults. |
| `rules_dir` is set and `<name>.yaml` exists | Operator file is used. |
| `rules_dir` is set and `<name>.yaml` is missing | Embedded default is used for that file only. |
| Operator file exists but has invalid YAML | Startup fails, or hot reload keeps the previous good value. |

## Hot Reload Matrix

Files are watched by `internal/rules.Watcher` only when `rules_dir` is set.
The watcher debounces editor saves, calls the registered loader, and swaps the
new value into a runtime holder on success. Parse failures are logged and the
previous value remains active.

| Rule file | Hot reload | Runtime effect |
| --- | --- | --- |
| `detector.yaml` | yes | Calls `scorer.SetRules()`. |
| `ip_reputation.yaml` | yes | Calls `scorer.SetIPReputation()`. |
| `templates.yaml` | yes | Updates the tarpit template holder. |
| `fake_data.yaml` | yes | Updates fake-data pools for future profiles. |
| `vulnerabilities.yaml` | yes | Updates tarpit vulnerability helper lists. |
| `injection_strategy.yaml` | yes | Updates tarpit route and injector strategy. |
| `challenge.yaml` | yes | Updates challenge page, cookie, token, and SPA settings. |
| `ml.yaml` | yes | Updates ML scoring, miner settings, and path redaction. |
| `dashboard.yaml` | yes | Updates dashboard panels and chart configuration. |
| `tls_fingerprints.yaml` | yes, when TLS DB exists | Applies new JA3/JA4 labels with `tlsDB.Apply()`. |
| `payloads.yaml` | no | Loaded by `payloads.NewLibraryFromDir()` at startup; restart required. |
| `learned.yaml` | miner-managed | Read and written by the ML miner workflow. |

There is no current `rules/h2_fingerprints.yaml` loader or watcher. HTTP/2
fingerprint entries must be applied by code until that configuration surface is
implemented.

## Environment Variables

Syntax:  process environment  
Default: unset  
Context: startup

| Variable | Effect |
| --- | --- |
| `VEILGATE_SECRET` | Overrides `challenge.secret` before the proxy starts. |

`VEILGATE_SECRET` is checked at startup by `cmd/veilgate/main.go`. Use it to
keep the challenge secret out of static config files. Changing it requires a
restart and invalidates outstanding challenge tokens.

Example systemd drop-in:

```ini
[Service]
Environment=VEILGATE_SECRET=<long-random-hex>
```

## Debugging A Value That Did Not Take

If you edited `veilgate.yaml`, restart the process. Hot reload does not apply
to top-level config.

If you edited a rule file, confirm the file is listed as hot-reloadable in the
matrix above and check logs for parse errors:

```bash
journalctl -u veilgate -n 50 | grep -Ei 'reload|parse'
```

If a custom rule file is missing expected defaults, copy the corresponding file
from `internal/rules/defaults/` and edit the full file. Rule overrides are
full-file replacements.

If payload changes did not appear, restart VeilGate. `payloads.yaml` is not in
the current watcher registration list.

## Related

- [Configuration reference](README.md)
- [Rule customization guide](rules/customization.md)
- [Codebase coverage matrix](../internals/coverage_matrix.md)
