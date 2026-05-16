# Module veilgate_persistence

The `veilgate_persistence` module documents the SQLite-backed event store. It
records request events, feature rollups, learned rule candidates, audit entries,
and tarpit canary state.

Persistence is optional in code, but the sample `configs/veilgate.yaml` enables
it because it is useful for operations, ML, and audit workflows.

## Example Configuration

```yaml
persist:
  enabled: true
  path: "./data/events.db"
  retention_days: 30
  queue_size: 4096
  dump_path: "./data/dumps"
  cache_size_kb: 65536
```

## Directives

- `persist.enabled`
- `persist.path`
- `persist.retention_days`
- `persist.queue_size`
- `persist.dump_path`
- `persist.cache_size_kb`

## `persist.enabled`

Syntax:  `enabled: true | false`  
Default: `false` if omitted; `true` in sample config  
Context: `persist`

Enables the SQLite store. When enabled, request handling queues events
asynchronously. The hot path does not block on disk; if the queue fills, events
are dropped.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) opens and wires the store.
- [`internal/persist/store.go#L83`](../../internal/persist/store.go#L83) creates the store.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) queues request events.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) can use canary lookup.

### Operational notes

- Treat the database as sensitive. It can contain IPs, paths, user agents,
  scores, signals, and features.
- Monitor queue depth and dropped events.
- Persistence enables canary replay and improves ML/miner workflows.

### Validation

```bash
ls -la ./data
curl http://127.0.0.1:9090/metrics | grep veilgate_persist_queue_depth
```

## `persist.path`

Syntax:  `path: "<file>"`  
Default: `"events.db"` when omitted by config defaults  
Context: `persist`

Sets the SQLite database file. Parent directories are created with restrictive
permissions. The database file is chmodded to `0600` when possible.

### Code path

- [`internal/config/config.go`](../../internal/config/config.go)
- [`internal/persist/store.go#L83`](../../internal/persist/store.go#L83)

### Operational notes

- Put the database on durable local storage.
- Keep it private.
- Backups should follow your privacy policy.

## `persist.retention_days`

Syntax:  `retention_days: <integer>`  
Default: `30`  
Context: `persist`

Defines how long event rows are retained before trimming. A background loop in
`cmd/veilgate/main.go` runs every six hours when persistence is enabled and the
retention value is positive.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)
- [`internal/persist/store.go`](../../internal/persist/store.go) implements `Trim()`.

### Operational notes

- Align retention with privacy and audit policy.
- Use `dump_path` when historical export is required before deletion.

## `persist.dump_path`

Syntax:  `dump_path: "<directory>"`  
Default: empty when omitted; `./data/dumps` in sample config  
Context: `persist`

Writes compressed CSV dumps before old event rows are trimmed. Empty disables
the dump step and trims directly.

### Code path

- [`internal/persist/dump.go`](../../internal/persist/dump.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

### Operational notes

- Dump files can contain sensitive metadata.
- Ensure dump retention is controlled separately.

## `persist.queue_size`

Syntax:  `queue_size: <integer>`  
Default: `4096` inside `persist.Open()` when omitted  
Context: `persist`

Controls the buffered channel between request handling and the SQLite flusher.
When full, events are dropped instead of blocking proxy traffic.

### Code path

- [`internal/persist/store.go`](../../internal/persist/store.go)
- `Store.Record()`
- `Store.RollupUpdate()`

### Operational notes

- Increase for bursty traffic.
- A permanently full queue means the disk or SQLite writer is falling behind.

## Canary Replay

Syntax:  internal persistence feature  
Default: enabled when persistence is enabled  
Context: runtime

The tarpit can record canary tokens into SQLite. Later requests that submit a
served token can trigger the `canary_replay` signal.

### Code path

- [`internal/persist/store.go`](../../internal/persist/store.go)
- `InsertCanary()`
- `CanaryProbe()`
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

## Forget Support

Syntax:  `veilgate forget --config <file> --ip <client-id> [--actor <name>]`  
Default: none  
Context: command line

Deletes persisted rows tied to a client ID and writes an audit entry.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/persist/store.go#L472`](../../internal/persist/store.go#L472)

## Related

- [Module veilgate_ml](../modules/veilgate_ml.md)
- [Module veilgate_metrics](../modules/veilgate_metrics.md)
- [How-to: handle RTBF](../how-to/handle-rtbf.md)

