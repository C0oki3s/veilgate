# Operator And Test Tooling

This page documents the helper commands under `cmd/`. These binaries are not
request-path modules, but they are part of the operational surface of the
codebase and are useful for validation, replay, and ML smoke testing.

## Commands

- `cmd/veilgate`
- `cmd/replay`
- `cmd/mlsmoke`
- `cmd/localreq`

## `cmd/veilgate`

Syntax:  `go run ./cmd/veilgate -config <path>`  
Default config path: `configs/veilgate.yaml`  
Context: main proxy process

The `veilgate` command starts the deception reverse proxy. It loads the
top-level config, applies `VEILGATE_SECRET`, loads rule files, wires detector,
challenge, tarpit, persistence, capture, verifier, metrics, ML, TLS, and HTTP/2
fingerprint components, then starts the proxy and metrics listeners.

It also contains the `forget` subcommand for right-to-erasure workflows.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)
- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go)
- [`internal/config/config.go`](../../internal/config/config.go)

### Validation

```bash
go run ./cmd/veilgate -config configs/veilgate.yaml
curl -i http://localhost:8080/
curl http://127.0.0.1:9090/metrics
```

## `cmd/replay`

Syntax:  `go run ./cmd/replay -db <events.db> -rules <rules_dir> -limit <n>`  
Default: `-db data/events.db -rules rules -agent-threshold 40`  
Context: offline detector validation

The `replay` command reads persisted events from SQLite and re-scores them with
the current detector rules. It is useful after editing `rules/detector.yaml` or
`rules/ip_reputation.yaml` because it estimates how existing traffic would score
under the new policy.

The command builds a fresh detector tracker with a 90 second window, loads the
configured detector rules, replays rows from the `events` table, and prints a
summary plus per-tool recall information.

### Code path

- [`cmd/replay/main.go`](../../cmd/replay/main.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)
- [`internal/rules/loader.go`](../../internal/rules/loader.go)

### Operational notes

- Replay is approximate because persisted rows do not contain the full original
  request headers. Header-dependent signals can be under-counted.
- Use replay for rule tuning, not as a complete forensic reconstruction.
- Run it against copied databases when testing destructive retention or cleanup
  workflows.

### Validation

```bash
go run ./cmd/replay -db data/events.db -rules rules -limit 500
go run ./cmd/replay -db data/events.db -rules rules -agent-threshold 50
```

## `cmd/mlsmoke`

Syntax:  `go run ./cmd/mlsmoke [-target <url>] [-curl-only] [-agent <n>] [-human <n>]`  
Default: `-target http://localhost:8080 -agent 30 -human 30`  
Context: ML and miner validation

The `mlsmoke` command is a self-contained ML smoke test. It wires production
detector, ML, persistence, rules, and miner packages in-process, generates
scripted agent-like and human-like fake requests, stores events in a temporary
SQLite database, triggers one miner pass, reads `rules/learned.yaml`, and
prints pass/fail assertions.

With `-curl-only`, it prints equivalent curl commands without running the
in-process smoke test. This is useful when validating a live VeilGate instance.

### Code path

- [`cmd/mlsmoke/main.go`](../../cmd/mlsmoke/main.go)
- [`internal/ml`](../../internal/ml)
- [`internal/persist/store.go`](../../internal/persist/store.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

### Operational notes

- The command creates a temporary rules directory and temporary SQLite database.
- It intentionally stresses ML feature extraction and miner candidate output.
- It is a smoke test, not a substitute for production observe-mode baselining.

### Validation

```bash
go run ./cmd/mlsmoke
go run ./cmd/mlsmoke -target http://localhost:8080 -curl-only
```

## `cmd/localreq`

Syntax:  `go run ./cmd/localreq -base <url> -traffic <mode> -n <count>`  
Default: `-base http://localhost:8080 -traffic normal`  
Context: local traffic generation

The `localreq` command sends local validation traffic to a running VeilGate
instance. It can generate normal browser-shaped requests, challenge-triggering
requests, malicious scanner-shaped requests, or a mixed set. It also supports
concurrency, TLS policy, IPv4/IPv6 selection, delay ranges, deterministic seeds,
and challenge-response inspection.

Common traffic modes:

| Mode | Purpose |
| --- | --- |
| `normal` | Browser-like requests for baseline scoring. |
| `challenge` | Suspicious enough to exercise challenge behavior. |
| `malicious` | Scanner and payload-shaped requests for detector validation. |
| `mixed` | Combined normal and suspicious traffic. |

### Code path

- [`cmd/localreq/main.go`](../../cmd/localreq/main.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go)

### Operational notes

- Use `-inspect` to print response details for challenge-like responses.
- Use `-tls strict` for real certificate validation and `-tls skip-verify` only
  for local self-signed test setups.
- Use `-seed` when you need repeatable request ordering.

### Validation

```bash
go run ./cmd/localreq -base http://localhost:8080 -traffic normal -n 20
go run ./cmd/localreq -base http://localhost:8080 -traffic malicious -n 20 -inspect
```

## Related

- [Codebase coverage matrix](coverage_matrix.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Rule customization guide](../config/rules/customization.md)
