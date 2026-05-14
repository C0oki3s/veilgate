# How to handle a Right-to-Erasure (RTBF) request

> **Goal:** Delete every record VeilGate persisted about a specific
> client identifier (typically an IP address), produce an audit-trail
> entry for the deletion, and confirm no in-memory state survives.

**On this page:**

1. [Background](#background)
2. [Step 1 — identify the client identifier](#step-1--identify-the-client-identifier)
3. [Step 2 — run a dry-run forget](#step-2--run-a-dry-run-forget)
4. [Step 3 — execute the forget](#step-3--execute-the-forget)
5. [Step 4 — flush in-memory state](#step-4--flush-in-memory-state)
6. [Step 5 — verify and document](#step-5--verify-and-document)
7. [What `forget` does NOT touch](#what-forget-does-not-touch)
8. [Related](#related)

## Background

`veilgate forget --ip <addr>` is a one-shot subcommand that opens the
existing event store, deletes every row tied to the given client
identifier, and writes a `data.forget` audit-log entry tied to the
operator who ran it.

The command is idempotent: running it twice on the same identifier is
safe. It is not destructive beyond the named identifier — no other
client's data is touched.

## Step 1 — identify the client identifier

VeilGate keys events by `client_id`, which is the resolved client IP
after applying the trusted-proxies allowlist. For most deployments
that's a public IP.

If the request came through a CDN or another proxy, the `client_id`
recorded is the *original* IP, not the CDN IP — provided
`detector.trusted_proxies` was set correctly.

To enumerate identifiers seen in a window:

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT DISTINCT client_id FROM events
   WHERE ts >= '2026-04-01T00:00:00Z'
   ORDER BY client_id"
```

## Step 2 — run a dry-run forget

```bash
sudo -u veilgate /usr/local/bin/veilgate forget \
  --config /etc/veilgate/veilgate.yaml \
  --ip 198.51.100.42 \
  --dry-run
```

Output:

```
DRY RUN — would forget client "198.51.100.42" from /var/lib/veilgate/events.db
```

Dry-run does not write to the database and does not write to the audit
log. Use it to confirm the identifier is correct before committing.

## Step 3 — execute the forget

```bash
sudo -u veilgate /usr/local/bin/veilgate forget \
  --config /etc/veilgate/veilgate.yaml \
  --ip 198.51.100.42 \
  --actor "ops-rotation@example.com"
```

Output:

```
forget: deleted 412 rows tied to "198.51.100.42"
forget: restart the proxy to flush in-memory Bayes/IF state for this client
```

The `--actor` flag goes into the audit log entry. If omitted, the
command falls back to `$USER` or the literal `cli`. Always pass an
identifying actor on production runs.

What gets deleted, in one transaction:

| Table | Rows touched |
| --- | --- |
| `events` | every request from this client |
| `tarpit_canaries` | every canary token served to this client |

## Step 4 — flush in-memory state

The Bayes classifier and Isolation Forest training rows live in RAM.
The forget command does not touch them — it can't, because the running
process owns that memory.

To wipe in-memory traces:

```bash
sudo systemctl restart veilgate
```

After restart, the Bayes classifier reloads from a clean state, and
the Isolation Forest re-trains from the still-buffered numeric rows
(which are themselves derived from events that were just deleted —
within one IF refit cycle, they're gone too).

Operators who run a multi-replica setup must restart all replicas.

## Step 5 — verify and document

Confirm the rows are gone:

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT COUNT(*) FROM events WHERE client_id = '198.51.100.42'"
# expected: 0

sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT COUNT(*) FROM tarpit_canaries WHERE client_id = '198.51.100.42'"
# expected: 0
```

Read back the audit entry:

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT ts, actor, action, target, outcome, detail
     FROM audit_log
     WHERE action = 'data.forget'
     ORDER BY id DESC LIMIT 1"
```

Or in the JSONL audit file:

```bash
sudo grep '"action":"data.forget"' /var/lib/veilgate/audit.log | tail -1
```

Save the audit row alongside the original request from the data subject.
That pair is the evidence package for compliance.

## What `forget` does NOT touch

For honesty and auditor questions:

- **The capture file** (`requests.jsonl`), if enabled. The capture
  janitor's retention does eventually clear it, but the immediate
  deletion path is to manually scrub or delete the file. Capture is
  off by default precisely so this isn't usually a concern.
- **Backups.** If you back up `events.db`, your existing
  backup-deletion procedure must also delete the row. VeilGate has no
  visibility into your backup pipeline.
- **Off-box log shipping.** If you ship to a SIEM via filebeat /
  vector / cloudwatch, propagate the deletion request there too.
- **The audit log itself.** The hash chain is intentionally
  tamper-evident. The audit row recording a forget is the *receipt*
  of the deletion; it does not, itself, contain the data subject's
  identifier as a payload (only as a `target` field, which most
  regulators accept as legitimate).

## Related

- [Use case: Compliance & audit evidence](../usecases/compliance-evidence.md)
- [Config: persist](../config/persist.md)
- [Config: capture](../config/capture.md)

---

*Previous: [Promote learned rules](promote-learned-rules.md) · Next: [Monitor with Prometheus + Grafana](monitor-with-prometheus.md)*
