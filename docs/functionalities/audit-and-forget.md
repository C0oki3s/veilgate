# Module veilgate_audit

The `veilgate_audit` module records operator and system actions in a
hash-chained audit log. It also documents the `veilgate forget` command, which
deletes persisted rows for a client identifier and records the deletion.

Audit logging is not an access-control mechanism. It is evidence generation:
each entry includes the previous entry hash so later review can detect
tampering or gaps.

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

- [Module veilgate_persistence](../modules/veilgate_persistence.md)
- [How-to: handle RTBF](../how-to/handle-rtbf.md)
- [Internals code map](../internals/code_map.md)

