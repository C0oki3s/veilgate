# Persistence Flow

This page documents the SQLite event store implemented in `internal/persist`.
The store serves three consumers: the operator (audit, review), the ML
pipeline (feature rollups, weak-label training), and the detector (canary
replay lookup).

## Architecture Overview

```
Proxy hot path (goroutine per request)
  │
  ├─ persist.Store.Record(Event)
  │    └─ channel send (non-blocking)
  │         if queue full → dropped counter++, return
  │
  └─ persist.Store.RollupUpdate(RollupDelta)
       └─ channel send (non-blocking)
            if queue full → drop, return

Background flusher goroutine (single writer)
  │
  ├─ select { case e := <-s.queue, case d := <-s.rollupQueue }
  │    accumulate batch up to flushInterval (default: 1 second)
  │
  ├─ tx := db.BeginTx()
  │    INSERT INTO events ...
  │    UPDATE feature_rollup ...
  │    tx.Commit()
  │
  └─ every 6 hours: trim()
       ├─ export rows older than retention_days to gzipped CSV (if dump_path != "")
       └─ DELETE FROM events WHERE time < cutoff
```

The proxy hot path never blocks on disk. If the queue channel fills
(`persist.queue_size`, default `4096`), new events are silently dropped and
`s.dropped` is incremented. Monitor dropped events via the persistence queue
depth metric.

---

## Database Connection

**Driver:** `modernc.org/sqlite` (pure-Go, no CGO)  
**File:** `persist.path` (default: `./data/events.db`)  
**Max connections:** 1 (single writer enforces serial WAL commits)

SQLite is opened with the following pragmas:

| Pragma | Value | Reason |
| --- | --- | --- |
| `journal_mode` | `WAL` | Better concurrency; proxy is single writer + dashboard readers |
| `synchronous` | `NORMAL` | Durability/throughput tradeoff; acceptable for telemetry data |
| `busy_timeout` | `5000 ms` | Prevents read timeouts when a commit races a dashboard query |
| `cache_size` | `-<cfg.WalMB * 1024>` | Negative means KiB; default 64 MB page cache |
| `temp_store` | `MEMORY` | Keeps ORDER BY / GROUP BY scratch off disk |
| `mmap_size` | `536870912` (512 MiB) | Allows kernel page cache to serve hot reads |

```go
// internal/persist/store.go
pragmas.Add("_pragma", "journal_mode=WAL")
pragmas.Add("_pragma", "synchronous=NORMAL")
pragmas.Add("_pragma", "busy_timeout=5000")
pragmas.Add("_pragma", fmt.Sprintf("cache_size=-%d", cfg.WalMB*1024))
pragmas.Add("_pragma", "temp_store=MEMORY")
pragmas.Add("_pragma", "mmap_size=536870912")
db.SetMaxOpenConns(1)
```

The database file is created with permissions `0600` (`os.Chmod`). The parent
directory is created with `0700` if it does not exist.

---

## Schema

### `events` table

Stores one row per request handled by the proxy.

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY | Auto-increment |
| `time` | TEXT | UTC timestamp (RFC 3339) |
| `client_id` | TEXT | Resolved client IP |
| `method` | TEXT | HTTP method |
| `path` | TEXT | Request path |
| `user_agent` | TEXT | User-Agent header |
| `header_bitmap` | INTEGER | Bitmask of present browser-typical headers |
| `ja3` | TEXT | JA3 fingerprint (empty when TLS not terminated at VeilGate) |
| `ja4` | TEXT | JA4 fingerprint (from `X-Veilgate-JA4` header or TLS hook) |
| `score` | INTEGER | Final detector score `0–100` |
| `signals` | TEXT | JSON array of signal names that fired |
| `decision` | TEXT | `real`, `observe`, `challenge`, or `tarpit` |
| `features_json` | TEXT | ML feature vector JSON (from `ml.Extractor`, empty when ML disabled) |

### `feature_rollup` table

Stores per-`(feature, bucket, label)` counts for the online ML Naive Bayes
classifier. Updated by `RollupUpdate()` calls from `ml.Scorer.Observe()`.

| Column | Type | Description |
| --- | --- | --- |
| `feature` | TEXT | Feature name |
| `bucket` | TEXT | Feature bucket value |
| `label` | TEXT | `agent` or `human` |
| `count` | INTEGER | Accumulated observation count |

### `rule_candidates` table

Stores miner-proposed rule candidates. The miner writes here; the operator
reviews and promotes via the rules workflow.

| Column | Type | Description |
| --- | --- | --- |
| `feature` | TEXT | Feature name |
| `bucket` | TEXT | Feature bucket value |
| `posterior` | REAL | P(agent \| feature=bucket) estimate |
| `support` | INTEGER | Number of supporting observations |
| `active` | INTEGER | `1` when operator-promoted |
| `proposed_at` | TEXT | Timestamp when proposed |
| `first_seen` | TEXT | Timestamp of first relevant event |

### `canaries` table

Stores tarpit-issued canary tokens for replay detection.

| Column | Type | Description |
| --- | --- | --- |
| `token` | TEXT UNIQUE | The canary token string |
| `client_id` | TEXT | Client ID that received the canary |
| `issued_at` | TEXT | Timestamp of issue |

### `schema_version` table

Records applied migration version. Used to detect and apply new schema
migrations on startup.

---

## Event Flow: Request Handling

1. `proxy.Server.serve()` builds a `persist.Event` after the decision is
   selected.
2. `ml.Extractor.Extract()` builds the feature vector JSON (when ML is wired).
3. `persist.Store.Record(event)` sends to `s.queue` channel.

```go
// internal/proxy/proxy.go
if s.persist != nil {
    var featuresJSON string
    if s.mlExtractor != nil {
        featuresJSON = s.mlExtractor.Extract(r, 0, r.Header.Get("X-Veilgate-JA4")).JSON()
    }
    s.persist.Record(persist.Event{
        Time:         time.Now().UTC(),
        ClientID:     clientID,
        ...
        FeaturesJSON: featuresJSON,
    })
}
```

4. The flusher goroutine batches events and commits them to SQLite within
   `flushInterval` (default: 1 second).

---

## Event Flow: ML Rollup Updates

The online ML scorer calls `persist.Store.RollupUpdate()` for each observation
to update the `feature_rollup` table. This is the incremental training signal
for the Naive Bayes component.

```go
// internal/ml/scorer.go (called from detector.Scorer.Score)
s.mlScorer.Observe(mlVec, total, s.agentThreshold)
  └─ for each (feature, bucket) in mlVec:
       persist.Store.RollupUpdate(RollupDelta{
           Feature: feature,
           Bucket:  bucket,
           Label:   "agent" | "human",
       })
```

---

## Event Flow: Canary Lookup

The tarpit emits canary tokens via payload injection. These tokens are
registered in the `canaries` table. The detector's `CanaryLookup` interface
is satisfied by `*persist.Store`:

```go
// internal/persist/store.go
func (s *Store) HitCanary(token, clientID string) (origClientID string, hit bool) {
    ...
}
```

`Scorer.scoreCanaryReplay()` calls `HitCanary()` on every request when the
canary lookup is wired. Since this is a database lookup on the hot path, the
query must be fast. The `canaries.token` column is indexed.

**Code path:**

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) wires `persist.Store` as `CanaryLookup`.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreCanaryReplay()`
- [`internal/persist/store.go`](../../internal/persist/store.go) → `HitCanary()`

---

## Background Flusher

A single goroutine (`s.flusher()`) reads from both `s.queue` and
`s.rollupQueue`. It accumulates events for `flushInterval` then opens a
transaction and writes all pending rows in a single `tx.Commit()`.

```go
// internal/persist/store.go
func (s *Store) flusher() {
    defer s.wg.Done()
    ticker := time.NewTicker(s.flushInterval)
    defer ticker.Stop()
    for {
        select {
        case <-s.stop:
            s.drainAndFlush()
            return
        case <-ticker.C:
            s.flush()
        }
    }
}
```

When `Store.Close()` is called, the flusher drains remaining queue items
before returning. This prevents event loss on graceful shutdown.

---

## Retention and Trimming

The flusher runs a retention trim every 6 hours. The trim:

1. Selects rows from `events` where `time < (now - retention_days)`.
2. If `dump_path` is non-empty, exports matching rows to a gzipped CSV file
   named `dump-<timestamp>.csv.gz` in the dump directory.
3. Deletes the selected rows from `events`.

```yaml
# veilgate.yaml
persist:
  retention_days: 30
  dump_path: "./data/dumps"
```

Setting `dump_path: ""` skips the export and trims directly.

**Security note:** dump files contain the same data as the database and should
be protected with the same file permissions. If dumps are not needed, set
`dump_path: ""`.

---

## Queue Saturation

When the queue channel fills, `Record()` and `RollupUpdate()` drop the event
and increment `s.dropped`. The proxy hot path is never blocked.

Monitor queue depth and drops:

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_persist
```

If drops are frequent:

- Increase `persist.queue_size` to absorb burst traffic.
- Reduce `persist.flush_interval` (not directly configurable; embedded at `1s`).
- Consider whether the SQLite write path is a bottleneck (check WAL file size
  and disk latency).

---

## Operational Notes

- The database file contains client IPs, paths, user agents, scores, signals,
  and ML feature vectors. Treat it as sensitive data.
- File permissions are set to `0600` at creation. Verify after deployment.
- The parent directory is created with `0700` at startup.
- Do not point `persist.path` to a network filesystem. SQLite WAL mode
  requires byte-range locking, which is unreliable on NFS/SMB.
- Use `persist.dump_path` for long-term archival rather than growing the
  SQLite file indefinitely.
- The `:memory:` path is supported for testing; data is lost on process exit.

---

## Limitations

- Single-writer SQLite is a bottleneck under very high request volume. The
  queue and batch flush are designed to absorb bursts, but at extreme volume
  the drop counter will grow.
- Retention trimming is approximate; the 6-hour trim interval means data older
  than `retention_days` can persist up to 6 hours beyond the target.
- Canary lookup adds a SQLite read to the hot path per request. This is fast
  for typical workloads but may add latency under heavy load on slow disks.

---

## Related

- [Module veilgate_persistence](../modules/veilgate_persistence.md)
- [Detector Signal Flow](detector_signal_flow.md) — `canary_replay` signal
- [Tarpit Rendering Flow](tarpit_rendering_flow.md) — canary emission
- [Module veilgate_ml](../modules/veilgate_ml.md)
- [`persist:` config reference](../config/persist.md)
