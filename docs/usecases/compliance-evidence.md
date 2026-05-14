# Use case: Compliance & audit evidence

> **Summary:** Security and audit committees in 2026 increasingly ask for
> a documented "AI threat exposure" answer. VeilGate produces durable
> evidence — telemetry, an audit log, a model card, and a deletion
> primitive — that maps directly to the controls auditors want to see.

**On this page:**

1. [The problem](#the-problem)
2. [What VeilGate provides](#what-veilgate-provides)
3. [Mapping to control frameworks](#mapping-to-control-frameworks)
4. [Configuration for an audit-friendly install](#configuration-for-an-audit-friendly-install)
5. [Operational gotchas](#operational-gotchas)
6. [Related](#related)

## The problem

A typical audit conversation in 2026 includes:

- "What's your posture on AI-driven attackers?"
- "Show me the Record of Processing for any ML model that ingests
  customer traffic."
- "Walk me through how you'd respond to a Right-to-Erasure request."
- "What controls prevent the deletion of audit trail entries?"

A WAF answers the first one weakly and the rest not at all. VeilGate
answers all four out of the box.

## What VeilGate provides

| Audit ask | VeilGate primitive |
| --- | --- |
| AI threat-exposure narrative | The dashboard at `:9090` plus the `veilgate_attacker_cost_usd_total` metric show exactly what an agent encountered |
| Model documentation | [docs/MODEL_CARD.md](../MODEL_CARD.md) — inputs, learning behaviour, limitations |
| Privacy-by-design | Default-on path redaction, capture off by default |
| Right-to-Erasure | `veilgate forget --ip <addr>` — deletes every row tied to a client, writes an audit entry |
| Tamper-evident audit trail | Hash-chained `audit.log` (SHA-256 chain across rows) plus an `audit_log` table in SQLite |
| Operator action log | Every config reload, every threshold change, every promotion of a learned rule lands in the audit chain |
| Retention controls | `capture.retention_hours` + janitor; `persist.retention_days` + dump |

## Mapping to control frameworks

These mappings are *narrative*, not certifications. Use them as starting
points for your own auditor conversation.

### SOC 2

- **CC7.2 (system monitoring):** `/metrics`, dashboard, audit log.
- **CC7.3 (incident response evidence):** Persisted events table; the
  `signals_json` column on each event documents *why* a request was
  flagged.
- **CC6.1 (logical access):** systemd unit runs as the dedicated
  `veilgate` user with `CapabilityBoundingSet=` empty.

### GDPR

- **Art. 17 (Right to erasure):** `veilgate forget --ip <addr>`.
- **Art. 25 (Data protection by design):** path redaction on by
  default, capture off by default, model never ingests bodies/values.
- **Art. 30 (Records of processing):** the
  [model card](../MODEL_CARD.md) is the canonical answer.

### ISO 27001

- **A.8.16 (monitoring):** Prometheus + dashboard.
- **A.8.15 (logging):** the audit chain.
- **A.5.34 (privacy):** path redaction + retention configuration.

### EU AI Act (low-risk security tool)

- The model card documents the system, its inputs, intended use, and
  limitations.
- The classifier is purely additive (gated by a confidence floor) —
  never the sole basis for a decision.
- Operator review is required to promote `learned.yaml` candidates.

## Configuration for an audit-friendly install

### `/etc/veilgate/veilgate.yaml`

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
rules_dir: "/etc/veilgate/rules"
mode: "challenge"                   # observe -> challenge -> tarpit ramp

detector:
  score_tarpit_threshold: 70
  score_challenge_threshold: 40

persist:
  enabled: true
  path: /var/lib/veilgate/events.db
  retention_days: 90                # match your retention policy

capture:
  enabled: false                    # off in production by default
  # When research-enabled (separate, quarantined env):
  # retention_hours: 168
  # scrub:
  #   - { regex: "(?i)bearer [a-z0-9._-]+", replace: "bearer <redacted>" }

metrics:
  listen: 127.0.0.1:9090            # private — SSH-tunnel only
```

### `/etc/veilgate/rules/ml.yaml`

```yaml
enabled: true
path_redaction:
  enabled: true
  custom:
    # Add your domain identifiers — auditors specifically ask about MRNs,
    # account numbers, customer IDs.
    - { regex: "^MRN-\\d+$",      replace: "<patient>" }
    - { regex: "^acct_[a-z0-9]+$", replace: "<account>" }

miner:
  enabled: true
  auto_promote_confidence: 0.0      # never auto-promote; operator review only
```

### Audit-log location

```
/var/lib/veilgate/audit.log         # JSONL hash chain
sqlite> SELECT * FROM audit_log;    # in events.db, same content, indexable
```

Ship the JSONL file to your SIEM via your existing collector
(filebeat / vector / cloudwatch agent / fluentbit).

## Operational gotchas

- **The audit chain restarts cleanly across reboots** — the next entry
  references the previous chain head. A gap means a chain restart, not
  necessarily tampering.
- **`learned.yaml` is operator-owned**. The miner writes candidates;
  operators promote them. Auditors who ask "how do we know the rules
  haven't drifted" want to see the promotion entries in the audit log.
- **The capture file, when enabled, is in scope for any data-protection
  framework you operate under.** Default is off. If you turn it on for
  research, keep it in a quarantined environment with the same data
  classification as production.
- **`veilgate forget --ip` does not touch in-memory state** — Bayes
  counts and Isolation Forest training rows in RAM persist until
  process restart. Schedule a restart after a forget; the documentation
  says so explicitly so you can quote it back to an auditor.

## Related

- [Business case](../BUSINESS_CASE.md) — compliance posture in detail
- [Engineering gaps](../ENGINEERING_GAPS.md) — what is and isn't shipped
- [How-to: Handle an RTBF request](../how-to/handle-rtbf.md)
- [Config: persist](../config/persist.md)
- [Config: capture](../config/capture.md)
- [Model card](../MODEL_CARD.md)

---

*Previous: [API recon blocking](api-recon-blocking.md) · Next: [How-to guides](../how-to/README.md)*
