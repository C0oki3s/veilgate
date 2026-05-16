# `persist:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `persist:`
> **Reload:** restart required.

The SQLite-backed event store. Holds the events, feature rollups, rule
candidates, audit log, and tarpit canaries. Required for the ML miner
and the `veilgate forget` subcommand.

**On this page:**

- [`enabled`](#enabled)
- [`path`](#path)
- [`retention_days`](#retention_days)
- [`flush_every_ms`](#flush_every_ms)
- [`queue_size`](#queue_size)
- [`dump_path`](#dump_path)
- [`cache_size_kb`](#cache_size_kb)
- [Schema overview](#schema-overview)
- [Example](#example)
- [Related](#related)

## Parameters

### `enabled`

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

Turn the SQLite store on. When `false`, the ML miner has no place to
persist candidates and `veilgate forget --ip` will refuse to run.
**Production deployments should set this to `true`.**

---

### `path`

| Type | Required | Default |
| --- | --- | --- |
| string (file path) | no | `events.db` |

Path to the SQLite file. Parent directory is created at 0755 if
missing; the file is created at 0600. Recommended location:
`/var/lib/veilgate/events.db`.

```yaml
persist:
  path: /var/lib/veilgate/events.db
```

The systemd unit's `ReadWritePaths=/var/lib/veilgate /var/log/veilgate`
limits the sandbox to that directory; if you point `path` somewhere
else, add the parent to `ReadWritePaths`.

---

### `retention_days`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `30` |

How long event rows are kept before the trim goroutine deletes them.
The trim runs every 6 hours; rows older than `retention_days x 24h`
are removed. Set `0` to disable trimming entirely.

The trim runs *after* the optional CSV.gz dump (see `dump_path`), so
the dump captures rows that are about to be trimmed.

---

### `flush_every_ms`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `1000` |

Batch-commit interval in milliseconds. Lower values reduce the
in-flight queue depth at the cost of more fsync work. The default of
1 s is fine for most workloads; raise to 2000-5000 for very high RPS,
where the queue saturates only on traffic bursts.

---

### `queue_size`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `4096` |

Buffered channel depth for the event-write queue. When this fills up,
new events are **dropped** with a counter bump
(`Store.Dropped()`). The drop policy keeps the proxy hot path off the
disk - a slow disk can never block request scoring.

If you see persistent drops in production, raise this *and*
investigate disk throughput.

---

### `dump_path`

| Type | Required | Default |
| --- | --- | --- |
| string (directory path) | no | `""` (disabled) |

Directory to write rotated `events-<timestamp>.csv.gz` archives every
6 hours, alongside the trim. Leave empty to disable archives -
rotated rows are then simply deleted.

```yaml
persist:
  dump_path: /var/lib/veilgate/dumps
```

The CSV.gz file is appropriate for shipping to a SIEM / data lake
that you control. Rotate or delete archives according to your
retention policy.

---

### `cache_size_kb`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `65536` (64 MiB) |

SQLite page cache size in **kilobytes**. Default of 64 MiB is fine for
deployments under ~1k RPS. Raise to 256-512 MiB for read-heavy
dashboard workloads.

The store also sets `mmap_size=512 MiB` and `temp_store=MEMORY`
unconditionally, which carry most of the read performance.

## Schema overview

| Table | Purpose |
| --- | --- |
| `events` | one row per request - features, decision, signals fired |
| `features_rollup` | rolling counts of (feature, bucket, agent_count, human_count) used by the miner |
| `rule_candidates` | the miner's proposed (feature, bucket, posterior, support) rules |
| `audit_log` | hash-chained operator-action log |
| `tarpit_canaries` | tokens served from the tarpit, watched for replay |
| `schema_version` | single-row migration version table |

Cross-reference: [Engineering gaps -> storage layout](../internals/engineering-gaps.md).

## Example

```yaml
persist:
  enabled: true
  path: /var/lib/veilgate/events.db
  retention_days: 30
  dump_path: /var/lib/veilgate/dumps
  queue_size: 4096
  flush_every_ms: 1000
  cache_size_kb: 65536
```

## Related

- [How-to: Handle a Right-to-Erasure (RTBF) request](../how-to/handle-rtbf.md)
- [How-to: Promote learned rules](../how-to/promote-learned-rules.md)
- [`capture:`](capture.md) - separate JSONL capture stream
- [`rules/ml.yaml`](rules/ml.md) - miner thresholds

---

*Previous: [`metrics:`](metrics.md) | Next: [`capture:`](capture.md)*
