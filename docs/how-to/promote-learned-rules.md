# How to promote learned rules

> **Goal:** Take the (feature, bucket) candidates the ML miner has
> proposed and turn the high-confidence ones into active detection rules
> — without ever auto-promoting on production.

**On this page:**

1. [Where candidates come from](#where-candidates-come-from)
2. [Step 1 — wait for the miner to fill `learned.yaml`](#step-1--wait-for-the-miner-to-fill-learnedyaml)
3. [Step 2 — review candidates](#step-2--review-candidates)
4. [Step 3 — promote one candidate](#step-3--promote-one-candidate)
5. [Step 4 — observe the change](#step-4--observe-the-change)
6. [Demoting a bad candidate](#demoting-a-bad-candidate)
7. [Related](#related)

## Where candidates come from

The ML pipeline:

1. The detector scores every request and emits a weak label —
   `agent` if score ≥ challenge threshold, `human` if score = 0,
   abstain otherwise.
2. The Bayes classifier consumes the label + the (feature, bucket)
   pairs from the request.
3. On a timer (default hourly), the miner walks the Bayes posterior
   and writes (feature, bucket, posterior, support) tuples that pass
   `min_posterior` and `min_support` thresholds into
   `rules/learned.yaml`.
4. Each candidate is `active: false` by default.

`auto_promote_confidence` exists but should stay at `0.0` on
production. Surfaces with hand-curated rules don't tolerate surprises.

## Step 1 — wait for the miner to fill `learned.yaml`

Default cadence is once an hour, requiring `min_support: 200` evidence
per candidate. Realistic timeline:

| Traffic volume | Time to first candidate |
| --- | --- |
| 100 req/sec | a few hours |
| 10 req/sec | a day |
| 1 req/sec | a week |
| < 1 req/sec | likely never; lower `min_support` if you accept more noise |

Check progress:

```bash
sudo cat ~/.veilgate/rules/learned.yaml
```

Or query SQLite directly — both are kept in sync:

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  'SELECT feature, bucket, posterior, support, active
     FROM rule_candidates
     ORDER BY posterior DESC
     LIMIT 20'
```

## Step 2 — review candidates

A typical entry:

```yaml
candidates:
  - feature: ua_token
    bucket: hexstrike
    posterior: 0.987
    support: 412
    active: false
    proposed_at: 2026-04-22T08:00:00Z
```

Read it as: *"the `ua_token` feature with bucket value `hexstrike` was
seen on 412 weakly-labelled events; 98.7 % of those events were
labelled `agent`."*

For each candidate, ask:

- **Does the bucket name look like an agent fingerprint?**
  `hexstrike`, `pentestgpt`, `nikto`, `python-httpx` — promote.
- **Is the bucket a generic browser token?** `mozilla`, `webkit`,
  `chrome` — do **not** promote. The miner found correlation, not
  causation, and your weak label is feeding back on itself.
- **Is the bucket a path n-gram you don't recognize?** Investigate
  with the events table before promoting. A bucket like
  `wp-admin/admin-ajax.php` is a fine promotion; a bucket like
  `assets/<hex>` is a redaction failure — fix `path_redaction.custom`
  instead.
- **Is the support large enough?** Anything below 1000 is suggestive,
  not conclusive. Wait for more evidence on borderline cases.

## Step 3 — promote one candidate

Two ways. Both produce identical end states; pick whichever fits your
workflow.

### Way A — edit the YAML

```bash
sudo -u veilgate vim ~/.veilgate/rules/learned.yaml
# Change `active: false` → `active: true` on the row you want.
```

The watcher hot-reloads the file. The change lands in the in-memory
Bayes model immediately. The miner persists the active flag back to
SQLite on its next tick.

### Way B — flip in SQLite

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "UPDATE rule_candidates SET active = 1
   WHERE feature = 'ua_token' AND bucket = 'hexstrike'"
```

The next miner tick rewrites `learned.yaml` with the active flag set.

Both paths emit an audit-log entry — if you want a clean trail, prefer
the SQL path because it doesn't require shell access to the rules
directory.

## Step 4 — observe the change

```bash
# Live signal hits — the new rule should start contributing
curl -sS http://127.0.0.1:9090/metrics | grep ml_agent_score
```

In Grafana:

```promql
rate(veilgate_signal_hits_total{signal="ml_agent_score"}[5m])
```

If the rate climbs visibly after promotion, the rule is working. If
it doesn't, either the bucket no longer matches recent traffic (the
attacker rotated tools) or the rule is redundant with an existing
hand-written rule.

## Demoting a bad candidate

If a promoted rule starts catching legitimate traffic:

1. Set `active: false` in `learned.yaml` (hot-reload picks it up
   within ~500 ms).
2. Or:
   ```sql
   UPDATE rule_candidates SET active = 0
   WHERE feature = '<feature>' AND bucket = '<bucket>';
   ```

The candidate stays in the table — you may want to revisit it after
investigating the false positive. Delete only if you're certain:

```sql
DELETE FROM rule_candidates WHERE feature = '<feature>' AND bucket = '<bucket>';
```

The miner won't re-propose it on the next tick if the underlying
posterior is below `min_posterior`. If it does re-propose, that's a
signal — your weak label might be wrong.

## Related

- [Config: rules/ml.yaml](../config/rules/ml.md)
- [Model card](../model/README.md) — what the miner is and isn't
- [How-to: Observe-mode rollout & threshold tuning](observe-and-tune.md)

---

*Previous: [Observe-mode rollout & threshold tuning](observe-and-tune.md) · Next: [Handle a Right-to-Erasure (RTBF) request](handle-rtbf.md)*
