# `rules/ml.yaml`

> **File:** `~/.veilgate/rules/ml.yaml`
> **Reload:** hot-reload (changes apply within ~500 ms).
>
> Hyperparameters for the online ML signal: Naive Bayes + Isolation
> Forest. Also configures path redaction and the rule-mining loop.
>
> See [model card](../../model/README.md) for the conceptual
> model documentation.

**On this page:**

- [Top-level keys](#top-level-keys)
- [`bayes:`](#bayes)
- [`iso_forest:`](#iso_forest)
- [`miner:`](#miner)
- [`path_redaction:`](#path_redaction)
- [Example](#example)
- [Related](#related)

## Top-level keys

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | turn the `ml_agent_score` signal on/off |
| `score_max_points` | int | `40` | ceiling contribution of this signal to the overall score |
| `alpha` | float `[0,1]` | `0.7` | blend: `1.0` = pure Bayes, `0.0` = pure Isolation Forest |
| `burn_in_events` | int | `500` | return 0 until Bayes has seen this many labeled examples |
| `min_confidence_to_fire` | float `[0,1]` | `0.2` | combined score must clear this to contribute any points |

```yaml
enabled: true
score_max_points: 40
alpha: 0.7
burn_in_events: 500
min_confidence_to_fire: 0.2
```

> **`min_confidence_to_fire`.** Set to `0.25-0.30` if you see ML
> contributing weak points to legit traffic during observe mode.
> Set to `0` only if you want the signal to fire on any positive
> posterior (rarely a good idea).

---

## `bayes:`

| Key | Type | Default |
| --- | --- | --- |
| `laplace_smoothing` | float | `1.0` |
| `max_ngram_length` | int | `3` |
| `timing_buckets_seconds` | list of float | `[0.1, 0.5, 1, 2, 5, 10, 30, 60, 300]` |

`max_ngram_length: 3` means the path is split on `/` and 1-, 2-, and
3-grams of the lowercased segments are emitted. Larger values explode
the feature space without much detection lift.

`timing_buckets_seconds` defines the upper bounds of inter-request gap
buckets. The fine-grained `pause_bucket` feature is hardcoded to be
LLM-cadence-tuned and is not configurable here.

---

## `iso_forest:`

Isolation Forest controls.

| Key | Type | Default |
| --- | --- | --- |
| `tree_count` | int | `50` |
| `sample_size` | int | `256` |
| `retrain_every_n_events` | int | `5000` |
| `max_depth` | int | `8` (approx  ceil(log2(sample_size))) |
| `train_max_rows` | int | `0` (use all buffered rows) |

The forest refits every `retrain_every_n_events`; the refit goroutine
fires on a 1-minute timer, so the actual cadence is *whichever happens
first*: enough new rows or 1 minute since the last fit.

`train_max_rows: 2000` is a good cap on high-volume sites - the forest
plateaus around a few thousand rows and capping bounds fit time.

---

## `miner:`

The rule miner walks the Bayes posterior on a timer and writes
high-confidence (feature, bucket) pairs to `learned.yaml` for operator
review.

| Key | Type | Default |
| --- | --- | --- |
| `enabled` | bool | `true` |
| `interval_minutes` | int | `60` |
| `min_support` | int | `200` |
| `min_posterior` | float `[0,1]` | `0.9` |
| `auto_promote_confidence` | float `[0,1]` | `0.0` (manual review only) |
| `write_path` | string | `learned.yaml` (resolved relative to `rules_dir`) |

> **Production guidance.** Keep `auto_promote_confidence` at `0.0`. The
> miner surfaces correlations, not causation; the operator decides
> which become active rules. See the
> [promote-learned-rules how-to](../../how-to/promote-learned-rules.md).

---

## `path_redaction:`

Scrubs high-entropy path segments before they become Bayes buckets.
Built-in patterns: UUIDs, long numeric IDs, hex strings, base64-ish
tokens.

| Key | Type | Default |
| --- | --- | --- |
| `enabled` | bool | `true` |
| `custom` | list of `{regex, replace}` | `[]` |

Custom rules apply *in addition to* the built-in patterns. Use them
for app-specific identifier shapes:

```yaml
path_redaction:
  enabled: true
  custom:
    - { regex: "^MRN-\\d+$",        replace: "<patient>" }
    - { regex: "^acct_[A-Za-z0-9]+$", replace: "<account>" }
    - { regex: "^doc_[A-Z0-9]{12}$",  replace: "<docid>" }
```

Bad regexes are silently dropped at startup - verify in the journal
log immediately after a config change.

> **Privacy.** Redaction protects the persisted feature store
> (`learned.yaml`, `features_rollup` table). The hot path's in-memory
> Bayes counts go through the same redaction. Disabling redaction is
> only appropriate in a private research environment.

## Example

```yaml
enabled: true
score_max_points: 40
alpha: 0.7
burn_in_events: 500
min_confidence_to_fire: 0.2

bayes:
  laplace_smoothing: 1.0
  max_ngram_length: 3
  timing_buckets_seconds: [0.1, 0.5, 1, 2, 5, 10, 30, 60, 300]

iso_forest:
  tree_count: 50
  sample_size: 256
  retrain_every_n_events: 5000
  max_depth: 8
  train_max_rows: 2000

miner:
  enabled: true
  interval_minutes: 60
  min_support: 200
  min_posterior: 0.9
  auto_promote_confidence: 0.0
  write_path: learned.yaml

path_redaction:
  enabled: true
  custom: []
```

## Related

- [Model card](../../model/README.md)
- [How-to: Observe-mode rollout](../../how-to/observe-and-tune.md)
- [How-to: Promote learned rules](../../how-to/promote-learned-rules.md)
- [`rules/detector.yaml`](detector.md) - rule-based scorer
- [`rules/learned.yaml`](learned.md) - miner candidate output

---

*Previous: [`rules/detector.yaml`](detector.md) | Next: [`rules/payloads.yaml`](payloads.md)*
