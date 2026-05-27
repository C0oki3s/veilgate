# Rules Directory Reference

This directory documents every YAML file under `rules_dir`. Rule files control
detector scoring, TLS labels, tarpit content, challenge presentation, ML
settings, dashboard layout, and miner-managed learned candidates.

Rule files are security policy. Keep them versioned, review changes like code,
and validate behavior in `mode: "observe"` before enforcement.

## Files

| Rule file | Reference | Main code path | Reload |
| --- | --- | --- | --- |
| `signals.yaml` | [signals.md](signals.md) | `rules.LoadSignals`, `detector.Scorer.SetSignals` | hot reload |
| `detector.yaml` | [detector.md](detector.md) | `rules.LoadDetector`, `detector.Scorer` | hot reload |
| `ip_reputation.yaml` | [ip-reputation.md](ip-reputation.md) | `rules.LoadIPReputation`, `detector.FleetTracker` | hot reload |
| `tls_fingerprints.yaml` | [tls-fingerprints.md](tls-fingerprints.md) | `rules.LoadTLS`, `tlsfp.Database` | hot reload when TLS DB exists |
| `challenge.yaml` | [challenge.md](challenge.md) | `rules.LoadChallenge`, `challenge.Handler` | hot reload |
| `ml.yaml` | [ml.md](ml.md) | `rules.LoadML`, `ml.Scorer`, `ml.Miner` | hot reload |
| `templates.yaml` | [templates.md](templates.md) | `rules.LoadTemplates`, `tarpit.Renderer` | hot reload |
| `injection_strategy.yaml` | [injection-strategy.md](injection-strategy.md) | `rules.LoadInjectionStrategy`, `tarpit.Handler` | hot reload |
| `payloads.yaml` | [payloads.md](payloads.md) | `rules.LoadPayloads`, `payloads.Library` | restart required |
| `fake_data.yaml` | [fake-data.md](fake-data.md) | `rules.LoadFakeData`, `tarpit.ProfileStore` | hot reload |
| `vulnerabilities.yaml` | [vulnerabilities.md](vulnerabilities.md) | `rules.LoadVulnerabilities`, `tarpit.Handler` | hot reload |
| `dashboard.yaml` | [dashboard.md](dashboard.md) | `rules.LoadDashboard`, `telemetry.Dashboard` | hot reload |
| `learned.yaml` | [learned.md](learned.md) | `rules.LoadLearned`, `ml.Miner` | miner-managed |

## Override Model

Syntax:  `rules_dir: "<directory>"`  
Default: embedded rule files  
Context: top-level config

If `<rules_dir>/<file>.yaml` exists, VeilGate uses that file instead of the
embedded default. The replacement is per file and complete. A partial
`detector.yaml`, for example, does not inherit omitted sections from the
embedded default.

### Code path

- [`internal/rules/loader.go`](../../../internal/rules/loader.go)
- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/rules/watcher.go`](../../../internal/rules/watcher.go)
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go)

## Hot Reload Summary

Most rule files are registered with the watcher when `rules_dir` is set. On a
successful parse, the new value is atomically swapped into the runtime holder.
On parse failure, the old value remains active.

`payloads.yaml` is the main exception: it is compiled into a payload library at
startup and requires process restart after edits. `learned.yaml` is maintained
by the ML miner workflow rather than a generic watcher registration.

## Validation

```bash
ls -la ~/.veilgate/rules
journalctl -u veilgate -n 50 | grep -Ei 'reload|parse'
curl -sS http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## Related

- [Configuration reference](../README.md)
- [Rule customization guide](customization.md)
- [Module veilgate_rules](../../modules/veilgate_rules.md)
