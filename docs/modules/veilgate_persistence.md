# Module veilgate_persistence

The `veilgate_persistence` module documents the SQLite-backed event store. It
records request events, feature rollups, learned rule candidates, audit entries,
and tarpit canary state.

Persistence is optional in code, but the sample `configs/veilgate.yaml` enables
it because it is useful for operations, ML, and audit workflows. This module is
analogous to NGINX's access log, except VeilGate stores structured, queryable
events in SQLite with a schema designed for offline analysis and ML feature
extraction.

## Architecture

```
Proxy.serve()
    │
    ▼ (non-blocking)
 chan Event (queue_size)
    │
    ▼
 Flusher goroutine          ← single writer, WAL mode, no lock contention
    │
    ├── INSERT events
    ├── INSERT/UPDATE feature_rollup
    ├── INSERT rule_candidates
    └── INSERT canaries
```

The flusher is a single goroutine that reads from the buffered channel and
batches writes. A single writer to a WAL-mode SQLite database avoids all
concurrency overhead. If the channel is full (queue backpressure), `Record()`
drops the event and does not block proxy throughput.

## Database Schema

| Table | Purpose |
| --- | --- |
| `events` | One row per request: client ID, path, method, score, decision, signals JSON, HTTP status. |
| `feature_rollup` | Aggregated per-client feature vectors for ML training. |
| `rule_candidates` | Candidate detection rules proposed by the miner. |
| `canaries` | Tarpit canary tokens and associated client IDs for replay detection. |
| `audit_log` | Hash-chained audit entries written by the audit module. |
| `schema_version` | Single-row migration tracker. |

### `events` table columns

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER PK | Auto-increment row ID. |
| `ts` | TEXT | RFC3339 timestamp of the request. |
| `client_id` | TEXT | Resolved client IP or identifier. |
| `method` | TEXT | HTTP method. |
| `path` | TEXT | Request path. |
| `score` | INTEGER | Detector score (0–100). |
| `decision` | TEXT | `real`, `observe`, `challenge`, `tarpit`. |
| `signals` | TEXT | JSON array of fired signals. |
| `status` | INTEGER | HTTP status code returned to client. |
| `ua` | TEXT | User-Agent header value. |

## SQLite Pragmas

The store opens with the following pragmas for performance and durability:

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA busy_timeout=5000;
PRAGMA cache_size=-65536;   -- 64 MB (negative = kibibytes)
PRAGMA temp_store=MEMORY;
PRAGMA mmap_size=536870912; -- 512 MB
```

`MaxOpenConns=1` is set on the `sql.DB` pool to enforce the single-writer
contract. Do not increase this; concurrent writers with WAL mode will serialize
on the WAL lock and offer no benefit.

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
are dropped rather than slowing the proxy.

```go
// internal/persist/store.go (schematic)
func (s *Store) Record(e Event) {
    select {
    case s.queue <- e:
    default:
        // Queue full. Drop this event. Do not block proxy.
        droppedCounter.Inc()
    }
}
```

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — opens store, wires to proxy.
- [`internal/persist/store.go`](../../internal/persist/store.go) — `Open()`, flusher goroutine.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) — calls `store.Record()` after each response.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) — calls `store.CanaryProbe()`.

### Operational notes

- Treat the database file as sensitive: it contains IPs, paths, user agents,
  scores, and signals.
- Monitor dropped events: sustained drops indicate the flusher cannot keep pace.
- Persistence enables canary replay and offline ML training.

### Validation

```bash
ls -la ./data/
sqlite3 ./data/events.db "SELECT COUNT(*) FROM events;"
```

## `persist.path`

Syntax:  `path: "<file>"`  
Default: `"events.db"` (config default)  
Context: `persist`

Sets the SQLite database file path. Parent directories are created automatically
with `0700` permissions. The database file is created with `0600` permissions.

### Operational notes

- Place the file on durable, local storage (avoid network mounts for WAL mode).
- Do not open the file with multiple VeilGate instances simultaneously.
- Backup with `sqlite3 events.db ".backup events_backup.db"` (hot backup
  compatible with WAL mode).

### Validation

```bash
file ./data/events.db
# Should output: ./data/events.db: SQLite 3.x database, ...
```

## `persist.retention_days`

Syntax:  `retention_days: <integer>`  
Default: `30`  
Context: `persist`

Defines how long event rows are retained before trimming. A background loop in
`cmd/veilgate/main.go` runs every six hours. Before deleting old rows, the
flusher exports a gzipped CSV to `dump_path` if configured.

```go
// cmd/veilgate/main.go (schematic)
ticker := time.NewTicker(6 * time.Hour)
for range ticker.C {
    if cfg.Persist.DumpPath != "" {
        store.ExportCSV(cfg.Persist.DumpPath)
    }
    store.Trim(cfg.Persist.RetentionDays)
}
```

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — trim ticker goroutine.
- [`internal/persist/store.go`](../../internal/persist/store.go) → `Trim(days int)`.
- [`internal/persist/store.go`](../../internal/persist/store.go) → `ExportCSV(dir string)`.

### Operational notes

- Align retention with your privacy policy and any applicable regulations.
- `retention_days: 0` disables automatic trimming.
- Use `dump_path` to preserve trimmed events before deletion.

## `persist.dump_path`

Syntax:  `dump_path: "<directory>"`  
Default: empty (no dump step; trim only)  
Context: `persist`

Directory to write gzipped CSV exports before old event rows are deleted. Each
export is named with a timestamp. Empty disables the dump step.

### Operational notes

- Dump files contain the same sensitive data as the live database.
- Control dump directory permissions: `chmod 700 ./data/dumps`.
- Separate dump retention from live database retention.

### Validation

```bash
ls -lh ./data/dumps/
zcat ./data/dumps/*.csv.gz | head -5
```

## `persist.queue_size`

Syntax:  `queue_size: <integer>`  
Default: `4096`  
Context: `persist`

Controls the buffered channel between request handling and the flusher
goroutine. When full, events are dropped rather than blocking proxy traffic.

### Operational notes

- Default (4096) handles high-throughput traffic without memory pressure.
- Sustained drops indicate the SQLite flusher is lagging; check disk I/O.
- Increasing to `16384` helps in burst scenarios (e.g., DDoS scrub events).

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_persist
```

## `persist.cache_size_kb`

Syntax:  `cache_size_kb: <integer>`  
Default: `65536` (64 MB)  
Context: `persist`

Sets the SQLite `cache_size` pragma in kibibytes. Applied as a negative value
(`-N`) which SQLite interprets as kibibytes. Larger values reduce I/O for
repeated queries on the same pages.

### Operational notes

- 64 MB is appropriate for most deployments.
- Reduce to `16384` (16 MB) on memory-constrained systems.
- Increasing beyond 256 MB offers diminishing returns for write-heavy workloads.

## Canary Lifecycle

The tarpit handler can embed unique canary tokens into served fake responses.
When a client submits a previously served token back to the application (e.g.,
using a fake password extracted from a fake login form), the `canary_replay`
detector signal fires.

```
Tarpit serves response with embedded token T1
    │
    ▼
store.InsertCanary(token=T1, clientID="203.0.113.10")
    │
    ...later...
    │
Client sends request with token T1 in body or query
    │
    ▼
scorer.scoreCanaryReplay()
    │
store.CanaryProbe(token=T1) → true
    │
    ▼
signal canary_replay fires (+points)
```

The `canaries` table stores `(token TEXT, client_id TEXT, created_at TEXT)`.
`HitCanary()` marks the token as replayed and returns the original client ID for
correlation.

### Code path

- [`internal/tarpit/handler.go`](../../internal/tarpit/handler.go) — `injector.Inject()` embeds tokens.
- [`internal/persist/store.go`](../../internal/persist/store.go) → `InsertCanary()`, `HitCanary()`.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreCanaryReplay()`.

## Forget Support

Syntax:  `veilgate forget --config <file> --ip <client-id> [--actor <name>]`  
Default: none  
Context: command line

Deletes persisted rows (events, feature rollups, canaries) tied to a specific
client ID and writes a hash-chained audit entry. Used for right-to-be-forgotten
(RTBF) compliance requests.

```bash
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --actor "privacy-team"
```

The forget command also clears the in-memory tracker state for that client ID
when run against a live instance via the IPC socket, if enabled.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go) — forget subcommand.
- [`internal/persist/store.go`](../../internal/persist/store.go) → `Forget(clientID string)`.
- [`internal/audit/audit.go`](../../internal/audit/audit.go) — `Entry` written for the forget action.

### Validation

```bash
# Before
sqlite3 ./data/events.db "SELECT COUNT(*) FROM events WHERE client_id='203.0.113.10';"

veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --actor "privacy-team"

# After
sqlite3 ./data/events.db "SELECT COUNT(*) FROM events WHERE client_id='203.0.113.10';"
# Expected: 0
```

## Related

- [Module veilgate_ml](veilgate_ml.md)
- [Module veilgate_metrics](veilgate_metrics.md)
- [Module veilgate_audit](veilgate_audit.md)
- [Persistence event store internals](../functionalities/persistence-event-store.md)
- [How-to: handle RTBF](../how-to/handle-rtbf.md)

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

- [Module veilgate_ml](veilgate_ml.md)
- [Module veilgate_metrics](veilgate_metrics.md)
- [How-to: handle RTBF](../how-to/handle-rtbf.md)

