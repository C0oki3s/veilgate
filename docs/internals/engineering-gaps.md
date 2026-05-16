# Engineering Gaps

Companion to the [business case](../product/business-case.md). Where the case study
asks "should we?", this document answers "what's done, what's deferred,
and what would the next pass look like?".

The deployment shape this document assumes is the supported one:
**a single Linux host running VeilGate as a hardened systemd service**.
Anything that requires a multi-tenant control plane is deferred.

---

## 1. Status Of The Hardening Punch List

Tracked here so the audit story has one place to look. Every item
landed in the codebase except where explicitly marked deferred.

### 1.1 Path redaction — shipped

- [internal/ml/features.go](../../internal/ml/features.go) — `PathRedactor`
  with built-in UUID / long-int / hex / base64 rules and an
  `AddCustom` hook.
- Wired into `pathNgrams` so `/users/12345/orders` becomes
  `users/<id>/orders` before bucketing.
- Configurable via `path_redaction:` in `rules/ml.yaml` (custom
  regex list).
- Tests in [internal/ml/features_redaction_test.go](../../internal/ml/features_redaction_test.go)
  assert that raw IDs never make it into a path_ngram bucket.

### 1.2 Capture hardening — shipped

- [internal/telemetry/capture.go](../../internal/telemetry/capture.go) —
  file mode 0600, parent dir 0700, regex scrub before write,
  retention janitor, byte-accurate rotation accounting.
- Config gained `retention_hours`, `janitor_every`, `file_mode`,
  `scrub` in [internal/config/config.go](../../internal/config/config.go).
- The janitor goroutine starts when retention is set; it's a no-op
  otherwise.
- Default in shipped configs is **capture off**. Operators flip it on
  for research.

### 1.3 `veilgate forget --ip` — shipped

- [cmd/veilgate/forget.go](../../cmd/veilgate/forget.go) implements the
  subcommand.
- `Store.ForgetClient` deletes from `events` and `tarpit_canaries` in
  one transaction.
- Writes a `data.forget` audit entry tied to the actor name.
- Operator restart wipes any RAM-resident traces (Bayes counts are
  in-memory).

### 1.4 Audit log — shipped

- New package [internal/audit/audit.go](../../internal/audit/audit.go).
- Hash-chained JSONL `FileWriter` plus a SQL `audit_log` table.
- `SetSeedHash` continues the chain across process restarts.
- Wired in [cmd/veilgate/main.go](../../cmd/veilgate/main.go) for
  process start/stop and config reloads.

### 1.5 SQLite improvements — shipped

- [internal/persist/store.go](../../internal/persist/store.go) sets
  `temp_store=MEMORY` and `mmap_size=512 MiB`.
- A maintenance goroutine runs `PRAGMA wal_checkpoint(TRUNCATE)` and
  canary GC every 5 minutes.

### 1.6 Model card — shipped

- [model card](../model/README.md). Inputs, weak-supervision label
  rule, learning behaviour, limitations, operator guidance.

---

## 2. Status Of The Detection Signals

The §7 catalogue from the original engineering-gaps document is now
implemented. Each signal lives in
[internal/detector/scorer.go](../../internal/detector/scorer.go) and is
wired into `Score`.

| Layer | Technique | Where it lives |
| --- | --- | --- |
| TLS | JA3 / JA4 fingerprints | [internal/tlsfp/](../../internal/tlsfp/) |
| TLS | HTTP/2 SETTINGS fingerprint | [internal/h2fp/h2fp.go](../../internal/h2fp/h2fp.go) — Settings, Database, Store, Classifier |
| HTTP | Sec-Fetch coherence | `scoreSecFetch` + ML feature `sec_fetch_coh` |
| HTTP | Header value canonicalization | ML feature `header_canon_fp` |
| HTTP | Accept-Encoding posture | `scoreAcceptEncoding` + ML feature `accept_enc` |
| HTTP | HTTP/3 mismatch | `scoreH3Mismatch` reads proxy-set header |
| Behavioural | Request-graph topology | `scoreRequestGraph` over `Sec-Fetch-Dest` distribution |
| Behavioural | Cookie ecology | `scoreCookieEcology` |
| Behavioural | Per-IP fan-out | `scoreFanout` (60s window, distinct paths) |
| LLM-specific | Tool-chain HMM | `scoreToolchainHMM` over ordered recon → probe → exploit |
| LLM-specific | Reasoning-pause timing | ML feature `pause_bucket` |
| LLM-specific | Failure-recovery shape change | `scoreFailureRecovery` |
| LLM-specific | Self-identifying UAs | existing `suspicious_ua` substrings in `rules/detector.yaml` |
| Cross-request | Tarpit canary replay | `scoreCanaryReplay` + `tarpit_canaries` SQLite table |
| Cross-request | TLS session-resumption refusal | surfaced via JA4 store TTL pattern + operator-tagged categories |

The ML feature vector grew correspondingly. See [model card](../model/README.md)
for the canonical input list.

---

## 3. What Is Not Done

These are deliberate omissions, not oversights.

### 3.1 Multi-tenancy — deferred

The Scorer, Miner, and Store all hold per-process state. Splitting
that into a `TenantScope` is a quarter of work that delivers nothing
for the self-hosted operator. Not started.

### 3.2 Postgres backend — deferred

`modernc.org/sqlite` is the right choice for the supported
deployment. A driver-abstraction over `database/sql` plus `sqlc` for
codegen is the right path **if** a multi-host deployment ever
warrants it. Not started.

### 3.3 S3 / object-store capture — deferred

The capture file is local-only. Operators ship it to a SIEM with the
tooling they already use (filebeat / vector / cloudwatch agent). A
built-in S3 sink would push us toward managing customer cloud
credentials, which is procurement friction we don't want.

### 3.4 H2 SETTINGS wire capture — partially deferred

The h2fp data layer is in place. The wire capture (a custom
`http2.Framer` wrapper that observes the SETTINGS frame at connection
setup) is not wired into the listener. The classifier degrades
gracefully — when no SETTINGS are captured, the signal is silent.

### 3.5 JS-beacon endpoint — deferred

The detector has hooks ready (`X-Veilgate-*` request headers flow
into ML features automatically), but a `/__veilgate/beacon` handler
that accepts canvas/WebGL fingerprints from a tiny JS payload is not
implemented. Deferred.

### 3.6 Cross-deployment learned-rule sharing — won't fix

Sharing `learned.yaml` candidates across operators is a network-effects
question with a privacy cost we don't want to pay. Each deployment is
its own model. Documented as a non-goal.

---

## 4. Storage Layout

The supported layout, mirrored in [deployment guide](../deployment/README.md):

| Path | Purpose | Permissions |
| --- | --- | --- |
| `/usr/local/bin/veilgate` | binary | 0755 root:root |
| `/etc/veilgate/veilgate.yaml` | config | 0640 root:veilgate |
| `/etc/veilgate/rules/` | rule files | 0750 root:veilgate |
| `/var/lib/veilgate/events.db` | SQLite event store | 0600 veilgate:veilgate |
| `/var/lib/veilgate/audit.log` | audit chain | 0600 veilgate:veilgate |
| `/var/lib/veilgate/requests.jsonl` | optional capture | 0600 veilgate:veilgate |

The systemd unit at [deployments/systemd/veilgate.service](../../deployments/systemd/veilgate.service)
declares `ReadWritePaths=/var/lib/veilgate /var/log/veilgate` so the
sandboxed process cannot write anywhere else. `ProtectSystem=strict`
plus `CapabilityBoundingSet=` empty plus `SystemCallFilter=@system-service`
keep the blast radius minimal.

---

## 5. Detection Hot Path

The synchronous-per-request budget is the binding constraint. Order of
operations in [internal/detector/scorer.go](../../internal/detector/scorer.go):

1. Trusted-IP allowlist short-circuit.
2. Record event in tracker (constant time).
3. Honeypot path lookup (map).
4. Header / UA / timing / toolchain signals.
5. Path-bruteforce, wordlist, injection, OOB signals.
6. IP reputation + fleet rotation + UA rotation.
7. TLS fingerprint + H2 fingerprint signals.
8. Sec-Fetch / Accept-Encoding / H3-mismatch signals.
9. Cross-request signals (request graph, cookie ecology, fan-out,
   failure recovery, tool-chain HMM).
10. Canary replay lookup.
11. ML scorer (Bayes posterior + Isolation Forest score).
12. Aggregate + cap at 100.

Everything except the ML scorer and the canary lookup is
allocation-free in the no-match case. The ML scorer is gated by a
configurable confidence floor so weak signal stays silent.

---

## 6. Test Surface

| Package | What it covers |
| --- | --- |
| `internal/ml` | Bayes separation, isolation forest, miner snapshot writeback, path redaction, pause buckets, sec-fetch coherence, accept-encoding posture |
| `internal/detector` | Each individual signal; clean-browser regression; IP-rotation suite |
| `internal/persist` | Store open + drain + trim + canary lifecycle |
| `internal/payloads` | Injector style rotation |
| `internal/rules` | YAML loaders + watcher debounce |
| `internal/tarpit` | Route matching; injection-strategy regex cache |
| `internal/tlsfp` | JA3 / JA4 hash format |

`go test ./...` is green on the current tree.

---

## 7. Operator Surface Recap

Commands an operator runs in production:

```
veilgate -config /etc/veilgate/veilgate.yaml          # serve
veilgate forget --ip <addr> -config <cfg>              # GDPR RTBF
systemctl status veilgate                              # health
journalctl -u veilgate -f                              # logs
sqlite3 /var/lib/veilgate/events.db                    # ad-hoc query
systemd-analyze security veilgate.service              # hardening score
```

Every one of these is documented in [deployment guide](../deployment/README.md).

---

*Last updated: 2026-05-09. Status flags reflect the working tree on
that date.*
