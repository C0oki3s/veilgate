# Operator And Test Tools

This functionality page covers the helper commands used to validate VeilGate
behavior outside the main request path.

## Commands

| Command | Purpose |
| --- | --- |
| `go run ./cmd/veilgate` | Start the proxy or run subcommands (`forget`, `update-rules`). |
| `veilgate update-rules` | Install or update community detection rules from [veilgate-rules](https://github.com/C0oki3s/veilgate-rules). |
| `veilgate forget` | Delete persisted rows for a client ID (RTBF/GDPR). |
| `go run ./cmd/replay` | Re-score persisted events with current detector rules. |
| `go run ./cmd/mlsmoke` | Run an in-process ML, persistence, and miner smoke test. |
| `go run ./cmd/localreq` | Generate local normal, suspicious, malicious, or mixed traffic. |

## `veilgate update-rules`

Downloads and installs a versioned release of community rules from
`https://github.com/C0oki3s/veilgate-rules` into the configured `rules_dir`.

```bash
# Install latest (default dir: ~/.veilgate/rules)
veilgate update-rules

# Install using config to find rules_dir
veilgate update-rules --config configs/veilgate.yaml

# Install into explicit directory
veilgate update-rules --dir ~/.veilgate/rules

# Pin a specific version
veilgate update-rules --dir ~/.veilgate/rules --version v1.2.0

# List available releases
veilgate update-rules --list

# Skip .bak file creation
veilgate update-rules --no-backup
```

**Flags:**

| Flag | Default | Description |
| --- | --- | --- |
| `--config` | `configs/veilgate.yaml` | Config file to read `rules_dir` from. |
| `--dir` | (from config) | Override the rules directory directly. |
| `--version` | `latest` | GitHub release tag to install. |
| `--list` | false | List available releases and exit. |
| `--no-backup` | false | Skip creating `.bak` copies before overwrite. |

After installation, most rules hot-reload automatically via the `fsnotify`
watcher. Only `payloads.yaml` requires a restart.

**Installed version tracking:** `<rules_dir>/.rules-version.json` records
the tag, install time, and file count.

**Security:** `update-rules` validates that all URLs use HTTPS and point to
`github.com` or `*.githubusercontent.com`. It enforces a 50 MB download cap
and rejects archive entries with path traversal patterns.

## Code path

- [`cmd/veilgate/update_rules.go`](../../cmd/veilgate/update_rules.go) — `runUpdateRules()`
- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go) — `runForget()`
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — subcommand dispatch
- [`cmd/replay/main.go`](../../cmd/replay/main.go)
- [`cmd/mlsmoke/main.go`](../../cmd/mlsmoke/main.go)
- [`cmd/localreq/main.go`](../../cmd/localreq/main.go)

## Usage

```bash
go run ./cmd/veilgate -config configs/veilgate.yaml
veilgate update-rules --dir ./rules
go run ./cmd/replay -db data/events.db -rules rules -limit 500
go run ./cmd/mlsmoke
go run ./cmd/localreq -base http://localhost:8080 -traffic malicious -n 20 -inspect
```

## Operational notes

- Use `localreq` to generate repeatable traffic while tuning thresholds.
- Use `replay` after editing rules to estimate impact on persisted traffic.
- Use `mlsmoke` to verify ML scoring and miner candidate output.
- Use `veilgate forget` for right-to-erasure workflows.
- Use `veilgate update-rules` in a weekly cron to stay current with community rules.

## Related

- [How-to: install community rules](../how-to/install-community-rules.md)
- [Operator and test tooling](../internals/tooling.md)
- [Codebase coverage matrix](../internals/coverage_matrix.md)
