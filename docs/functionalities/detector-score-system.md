# Detector Score System

The detector assigns a score between 0 and 100 to every request. The score
is an additive sum of all fired signal points, capped at 100. The proxy uses
that score — together with `mode`, `score_challenge_threshold`, and
`score_tarpit_threshold` — to decide what to do with the request.

## Score calculation

```
score = min(100, Σ points_of_fired_signals)
```

Each signal that fires contributes its configured points to the running total.
Signals do not cancel each other out. A request carrying an injection payload
from a cloud-egress IP after hitting a honeypot path will accumulate points
from all three signals simultaneously.

## Score tiers and threat_level

The raw score maps to a human-readable `threat_level` label. This label is
attached to every request log line as a structured field and is suitable for
use as a SigNoz, Grafana, or Datadog filter value.

| Score range | `threat_level` | Typical implication |
| --- | --- | --- |
| 0–29 | `low` | Expected normal traffic; no signals fired or only weak signals. |
| 30–59 | `medium` | One or two moderate signals (sparse headers, UA rotation, IP reputation). Worth monitoring. |
| 60–79 | `high` | Multiple signals including strong indicators (wordlist path, fleet rotation, schema_first). Challenge or tarpit likely. |
| 80–100 | `critical` | High-confidence attack behaviour (injection payload, canary replay, honeypot + fleet rotation). Tarpit at default thresholds. |

The `threat_level` band boundaries (30/60/80) are fixed constants derived from
experience with real attack traffic. The `score_challenge_threshold` (default 40)
and `score_tarpit_threshold` (default 70) that actually control routing are
independent values operators tune for their traffic.

## Decision selection

The proxy maps score and `mode` into a routing decision:

| Mode | Score | Decision |
| --- | --- | --- |
| `observe` | any | `observe` — always proxied upstream; score and signals are recorded but have no routing effect. |
| `challenge` | `< challenge_threshold` | `real` — proxied upstream. |
| `challenge` | `≥ challenge_threshold` | `challenge` — PoW page served. |
| `tarpit` | `< challenge_threshold` | `real` |
| `tarpit` | `[challenge_threshold, tarpit_threshold)` | `challenge` |
| `tarpit` | `≥ tarpit_threshold` | `tarpit` — fake application response served. |
| `auto` | `< challenge_threshold` | `real` |
| `auto` | `[challenge_threshold, tarpit_threshold)` | `challenge` |
| `auto` | `≥ tarpit_threshold` | `tarpit` |

`observe` mode is the recommended starting point. Run in observe mode to
collect score histograms and signal firing rates before enabling any enforcement.

## Log severity routing

Every request produces a structured log line at a zerolog level that matches
the routing decision:

| Decision | zerolog level | SigNoz colour |
| --- | --- | --- |
| `tarpit` | `error` | Red |
| `challenge` | `warn` | Yellow |
| `real` | `info` | Blue |
| `observe` | `info` | Blue |

This mapping means you can filter "all tarpitted requests" in SigNoz simply
by severity = ERROR — no knowledge of the `decision` field is required.

The `threat_level` field gives the score-band label. These two fields together
let you ask questions like "what was the threat level distribution of requests
that ended up challenged?" without writing PromQL.

## Configuration

```yaml
detector:
  score_challenge_threshold: 40   # default
  score_tarpit_threshold: 70      # default
  window_seconds: 90              # rolling tracker window
  trusted_ips: []                 # bypass all signals for these IPs
  trusted_proxies: []             # trust XFF from these peers
  probe_paths:                    # honeypot paths
    - /.git/config
    - /.env.backup
```

## Signal groups

| Group | Signals |
| --- | --- |
| Header shape | `empty_ua`, `suspicious_ua`, `sparse_headers` |
| Browser consistency | `sec_fetch_absent`, `sec_fetch_partial`, `ae_browser_empty`, `ae_browser_no_br`, `h3_mismatch` |
| Timing | `regular_timing` |
| Toolchain / pentest | `toolchain_full`, `toolchain_partial`, `toolchain_hmm`, `toolchain_hmm_partial` |
| Path and payload | `honeypot_hit`, `path_bruteforce`, `wordlist_path`, `injection_marker`, `oob_interaction`, `encoding_chain` |
| IP / rotation | `ip_reputation`, `ip_rotation_fleet`, `ua_rotation` |
| TLS / HTTP/2 | `tls_agent`, `tls_bot`, `tls_non_browser`, `h2_agent`, `h2_bot`, `h2_non_browser` |
| Session / behavioral | `graph_flat`, `graph_doc_heavy`, `cookie_stateless`, `fanout_high`, `fanout_extreme`, `recovery_pivot`, `bundle_mining`, `header_mutation`, `schema_first`, `cache_miss_anomaly`, `no_cookie_return`, `auth_probe_sequence` |
| Deception feedback | `canary_replay` |
| API blueprint | `api_blueprint_miss` |
| ML | `ml_agent_score` |

See [Detection Signals](detection-signals.md) for the full per-signal reference
including default points, condition requirements, and attack family.

## Configuring signals

Every signal can be enabled/disabled or have its default points overridden
at runtime without a restart via `rules/signals.yaml`. Custom detection rules
can also be added using only YAML — no Go code required.

```yaml
# rules/signals.yaml
signals:
  honeypot_hit:
    enabled: true
    points: 100       # instant tarpit on any honeypot hit
  ml_agent_score:
    enabled: false    # suppress during model retraining
```

See [`rules/signals.yaml`](../config/rules/signals.md) for the full reference.

## Related

- [Detection Signals](detection-signals.md) — per-signal reference (all 43 signals)
- [`rules/signals.yaml`](../config/rules/signals.md) — enable/disable, points overrides, custom signals
- [`rules/detector.yaml`](../config/rules/detector.md) — default points and scoring tiers
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_ml](../modules/veilgate_ml.md)
