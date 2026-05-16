# Module veilgate_audit

The `veilgate_audit` module records operator and system actions in a
hash-chained audit log. It also documents the `veilgate forget` command, which
deletes persisted rows for a client identifier and records the deletion.

Audit logging is not an access-control mechanism. It is evidence generation:
each entry includes the previous entry hash so later review can detect
tampering or gaps in the log sequence.

## Hash Chain Mechanism

Each audit entry computes its own hash from the entry content plus the previous
entry's hash:

```
hash(entry_N) = SHA-256(entry_N.fields + prev_hash(entry_N-1))
```

This creates a tamper-evident chain: modifying, inserting, or deleting any
entry breaks all subsequent hashes. Verification requires replaying the chain
from the seed (or from a known-good checkpoint).

```go
// internal/audit/audit.go (schematic)
type Entry struct {
    Time     time.Time
    Actor    string
    Action   string
    Target   string
    Outcome  string
    Detail   string
    Meta     map[string]any
    PrevHash string  // SHA-256 hex of the previous entry
    Hash     string  // SHA-256 hex of this entry
}

func chainHash(e *Entry) string {
    h := sha256.New()
    fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s|%s|%s",
        e.Time.UTC().Format(time.RFC3339Nano),
        e.Actor, e.Action, e.Target,
        e.Outcome, e.Detail, e.PrevHash,
        marshalMeta(e.Meta))
    return hex.EncodeToString(h.Sum(nil))
}
```

Chain continuity across restarts is maintained by `SetSeedHash()`, which reads
the last known hash from the JSONL file or SQLite `audit_log` table before
writing the first entry after startup.

## Dual-Backend Architecture

VeilGate writes audit entries to two backends simultaneously:

| Backend | Format | File | Purpose |
| --- | --- | --- | --- |
| JSONL file | Newline-delimited JSON | `<persist.path>/../audit.log` | SIEM shipping, offline analysis |
| SQLite table | Relational rows | `<persist.path>` (events.db) | Queryable with `sqlite3`, joins with events |

Both backends implement the `Writer` interface:

```go
// internal/audit/audit.go
type Writer interface {
    Append(e *Entry) error
}
```

If one backend fails, the other continues. Failed writes are logged to stderr.

### JSONL format example

```json
{"ts":"2024-01-15T10:30:00.123456Z","actor":"system","action":"process.start","target":"veilgate","outcome":"ok","detail":"listening on :8080","prev_hash":"0000000000000000...","hash":"a3f2b8e1c9d5..."}
{"ts":"2024-01-15T10:31:00.456Z","actor":"ops-user","action":"data.forget","target":"203.0.113.10","outcome":"ok","detail":"4 events deleted, 2 canaries deleted","meta":{"rows_deleted":4,"canaries_deleted":2},"prev_hash":"a3f2b8e1c9d5...","hash":"f8e2b3c1..."}
```

### SQLite audit_log schema

| Column | Type | Description |
| --- | --- | --- |
| `id` | INTEGER PK | Auto-increment row ID. |
| `ts` | TEXT | RFC3339Nano timestamp. |
| `actor` | TEXT | Who performed the action. |
| `action` | TEXT | Canonical action label. |
| `target` | TEXT | Resource affected. |
| `outcome` | TEXT | `ok` or `error`. |
| `detail` | TEXT | Human-readable description. |
| `meta` | TEXT | JSON metadata. |
| `prev_hash` | TEXT | Previous entry hash (hex). |
| `hash` | TEXT | This entry hash (hex). |

## Standard Actions

| Action | Trigger |
| --- | --- |
| `process.start` | VeilGate process starts. |
| `process.stop` | VeilGate process receives shutdown signal. |
| `config.reload` | A hot-reload watcher triggers a rule reload. |
| `data.forget` | `veilgate forget` command executes. |
| `challenge.pass` | Client solves a PoW challenge. |
| `verifier.accept` | HMAC verifier accepts a request. |

## Example Configuration

```yaml
persist:
  enabled: true
  path: "./data/events.db"
```

Forget command:

```bash
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --actor ops
```

## Directives

- `persist.enabled`
- `persist.path`
- `veilgate forget --config`
- `veilgate forget --ip`
- `veilgate forget --actor`
- `veilgate forget --dry-run`

## `persist.enabled`

Syntax:  `enabled: true | false`  
Default: `false` if omitted; `true` in sample config  
Context: `persist`

Enables the SQLite audit mirror. When persistence is enabled, audit entries are
written to both the JSONL file and the `audit_log` SQLite table.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — opens audit writers and wires them.
- [`internal/audit/audit.go`](../../internal/audit/audit.go) — `Logger`, hash chain, both backends.
- [`internal/persist/store.go`](../../internal/persist/store.go) — `AppendAudit()` for SQLite.

### Operational notes

- Even without SQLite, the JSONL file is written when a `persist.path`
  parent directory is accessible.
- Ship the JSONL file to a SIEM for long-term evidence retention.

## `persist.path`

Syntax:  `path: "<file>"`  
Default: `"events.db"` (config default)  
Context: `persist`

Defines the SQLite database. The JSONL audit file is placed beside this path
as `audit.log`.

### Operational notes

- The audit file is opened with mode `0600`.
- Parent directories are created with `0700`.

## Audit Entry Fields

| Field | Type | Description |
| --- | --- | --- |
| `ts` | RFC3339Nano string | UTC timestamp of the action. |
| `actor` | string | `system`, CLI user, API key, or operator name. |
| `action` | string | Canonical dot-separated action label (e.g., `data.forget`). |
| `target` | string | Resource affected (e.g., client ID, config file path). |
| `outcome` | string | `ok` or `error`. |
| `detail` | string | Human-readable description. |
| `meta` | JSON object | Structured context (counts, identifiers, options). |
| `prev_hash` | SHA-256 hex | Hash of the previous entry. `0000...` for the first entry. |
| `hash` | SHA-256 hex | Hash of this entry. Computed from all fields including `prev_hash`. |

### Code path

- [`internal/audit/audit.go`](../../internal/audit/audit.go) → `Logger.Log()`, `chainHash()`, `SetSeedHash()`.

## `veilgate forget --config`

Syntax:  `veilgate forget --config <file>`  
Default: `configs/veilgate.yaml`  
Context: command line

Selects the config file used to find the persistence database.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/config/config.go`](../../internal/config/config.go)

## `veilgate forget --ip`

Syntax:  `veilgate forget --ip <client-id>`  
Default: none  
Context: command line

Required. Defines the client identifier to delete from durable persistence.
This is usually an IP address because the proxy uses the resolved client ID as
the persistence key.

The forget command deletes rows from `events`, `feature_rollup`, and `canaries`
for the client ID. An audit entry with action `data.forget` is written to both
backends.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/persist/store.go`](../../internal/persist/store.go) → `Forget(clientID string)`.

### Operational notes

- Does not clear in-memory tracker, Bayes, or IsoForest state inside a running
  proxy. Restart the proxy when in-memory and durable state must both be cleared
  immediately.
- Use `--dry-run` first to confirm what would be deleted.

### Validation

```bash
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --dry-run
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --actor "privacy-team"
sqlite3 ./data/events.db "SELECT * FROM audit_log ORDER BY id DESC LIMIT 5;"
```

## `veilgate forget --actor`

Syntax:  `veilgate forget --actor <name>`  
Default: `$USER`, then `cli`  
Context: command line

Sets the actor field in the audit entry for the forget action. Use this to
attribute RTBF requests to specific operators or request tickets.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/audit/audit.go`](../../internal/audit/audit.go) → `Logger.Log()` actor field.

## `veilgate forget --dry-run`

Syntax:  `veilgate forget --dry-run`  
Default: disabled  
Context: command line

Reports what would be deleted without committing changes. Prints the row counts
for each table. No audit entry is written in dry-run mode.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)

### Validation

```bash
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --dry-run
# Outputs: would delete N events, M canaries for 203.0.113.10
```

## Chain Verification

To verify chain integrity offline:

```bash
# Extract audit entries
sqlite3 ./data/events.db "SELECT ts,actor,action,target,outcome,detail,meta,prev_hash,hash FROM audit_log ORDER BY id;"

# Or from JSONL
jq -r '[.ts,.actor,.action,.target,.outcome,.detail,.prev_hash,.hash] | @tsv' ./data/audit.log
```

Recompute each entry's hash from its fields and `prev_hash`. Any mismatch
indicates insertion, deletion, or modification of an entry.

## System Actions

VeilGate records the following system-initiated actions:

| Action | When |
| --- | --- |
| `process.start` | Startup, after listeners are bound. |
| `process.stop` | SIGTERM or SIGINT received. |
| `config.reload` | Hot-reload watcher successfully reloads a rule file. |

## Limitations

- Audit logging does not prevent unauthorized changes; it provides evidence for
  detecting and investigating them.
- If both backends fail to write, the action proceeds without a durable audit
  row. Failures are logged to stderr.
- Hash chains prove sequence integrity only when the full log is retained and
  the seed hash is preserved across restarts.

## Related

- [Module veilgate_persistence](veilgate_persistence.md)
- [Audit and forget internals](../functionalities/audit-and-forget.md)
- [How-to: handle RTBF](../how-to/handle-rtbf.md)

## Example Configuration

```yaml
persist:
  enabled: true
  path: "./data/events.db"
```

Forget command:

```bash
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --actor ops
```

## Directives

- `persist.enabled`
- `persist.path`
- `veilgate forget --config`
- `veilgate forget --ip`
- `veilgate forget --actor`
- `veilgate forget --dry-run`

## `persist.enabled`

Syntax:  `enabled: true | false`  
Default: `false` if omitted; `true` in sample config  
Context: `persist`

Enables the SQLite audit mirror. When persistence is enabled, audit entries can
be written to the `audit_log` table through `audit.SQLBackend`.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) wires audit logging.
- [`internal/audit/audit.go`](../../internal/audit/audit.go) implements the hash chain.
- [`internal/persist/store.go`](../../internal/persist/store.go) implements `AppendAudit()`.

### Operational notes

- Persistence stores audit rows alongside request metadata.
- Keep the database private.
- Ship the JSONL audit file to a SIEM if long-term evidence is required.

## `persist.path`

Syntax:  `path: "<file>"`  
Default: `"events.db"` when omitted by config defaults  
Context: `persist`

Defines the SQLite event database. The JSONL audit file is created beside this
path as `audit.log` by `cmd/veilgate/main.go`.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)
- [`internal/audit/audit.go`](../../internal/audit/audit.go)

### Operational notes

- Parent directories are created with restrictive permissions by the
  persistence and audit packages where possible.
- The audit file is opened with mode `0600`.

## Audit Entry Fields

Syntax:  internal JSONL object  
Default: generated per action  
Context: runtime

Each audit entry contains:

| Field | Meaning |
| --- | --- |
| `ts` | UTC timestamp. |
| `actor` | `system`, CLI user, API key, or operator name. |
| `action` | Canonical action such as `process.start` or `data.forget`. |
| `target` | Resource affected by the action. |
| `outcome` | `ok` or `error`. |
| `detail` | Human-readable detail. |
| `meta` | Structured context. |
| `prev_hash` | Previous entry hash. |
| `hash` | SHA-256 hash for this entry. |

### Code path

- [`internal/audit/audit.go`](../../internal/audit/audit.go)
- `Logger.Log()`
- `chainHash()`

## `veilgate forget --config`

Syntax:  `veilgate forget --config <file>`  
Default: `configs/veilgate.yaml`  
Context: command line

Selects the config file used to find the persistence database.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/config/config.go`](../../internal/config/config.go)

## `veilgate forget --ip`

Syntax:  `veilgate forget --ip <client-id>`  
Default: none  
Context: command line

Required. Defines the client identifier to delete from durable persistence.
This is usually an IP address because the proxy uses the resolved client ID as
the persistence key.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/persist/store.go#L472`](../../internal/persist/store.go#L472)

### Operational notes

- The command deletes rows from `events` and `tarpit_canaries` for the client.
- It does not clear in-memory tracker, Bayes, or Isolation Forest state inside
  an already-running proxy.
- Restart the proxy after a forget request when durable and in-memory state
  must both be cleared immediately.

### Validation

```bash
veilgate forget --config configs/veilgate.yaml --ip 203.0.113.10 --dry-run
```

## `veilgate forget --actor`

Syntax:  `veilgate forget --actor <name>`  
Default: `$USER`, then `cli`  
Context: command line

Sets the actor stored in the audit row for the forget action.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)
- [`internal/audit/audit.go`](../../internal/audit/audit.go)

## `veilgate forget --dry-run`

Syntax:  `veilgate forget --dry-run`  
Default: disabled  
Context: command line

Reports what would be deleted without committing changes.

### Code path

- [`cmd/veilgate/forget.go`](../../cmd/veilgate/forget.go)

## System Actions

VeilGate records process start, process stop, selected config reload outcomes,
and forget actions. The logger seeds the hash chain from the last known audit
hash in the audit file or SQLite table when available.

## Limitations

- Audit logging does not prevent malicious changes; it helps detect and
  investigate them.
- If both file and SQL audit backends fail, the action can proceed without a
  durable audit row.
- Hash chains prove sequence integrity only when logs are retained.

## Related

- [Module veilgate_persistence](veilgate_persistence.md)
- [How-to: handle RTBF](../how-to/handle-rtbf.md)
- [Internals code map](../internals/code_map.md)

