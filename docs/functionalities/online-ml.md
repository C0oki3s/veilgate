# Module veilgate_ml

The `veilgate_ml` module documents optional online ML scoring and rule mining.
ML is an additive detector signal, not the primary enforcement engine. The
deterministic detector and thresholds still control final routing.

When enabled, ML can add the `ml_agent_score` signal. The final score remains
capped at `100`.

## Example Configuration

```yaml
# rules/ml.yaml
enabled: true
score_max_points: 40
min_confidence_to_fire: 0.2

bayes:
  laplace_smoothing: 1.0
  max_ngram_length: 4

iso_forest:
  tree_count: 100
  sample_size: 256
  retrain_every_n_events: 5000

miner:
  enabled: true
  write_path: rules/learned.yaml
```

## Directives

- `enabled`
- `score_max_points`
- `min_confidence_to_fire`
- `bayes`
- `iso_forest`
- `miner`
- `path_redaction`

## `enabled`

Syntax:  `enabled: true | false`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Enables ML scoring. The scorer is constructed at startup either way, but the
rules gate determines whether ML contributes points.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) constructs and wires ML.
- [`internal/ml/scorer.go`](../../internal/ml/scorer.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

### Operational notes

- Use deterministic rules and observe-mode baselines first.
- Treat ML as a supporting signal.
- Watch `veilgate_ml_score_points` and `veilgate_ml_fits_total`.

Key metrics for ML health:

| Prometheus | OTel | What to watch |
| --- | --- | --- |
| `veilgate_ml_fits_total{status="ok"}` | `veilgate.ml.fits.total` | Refit cadence — should increment regularly under traffic. |
| `veilgate_ml_fit_duration_seconds` | `veilgate.ml.fit_duration` | Watch for sudden spikes. |
| `veilgate_ml_bayes_observed` | `veilgate.ml.bayes_observed` | Burn-in gauge — increases during initial traffic. |
| `veilgate_ml_bayes_entries` | `veilgate.ml.bayes_entries` | Should stay well below the 100 k cap. |
| `veilgate_ml_bayes_evictions_total` | `veilgate.ml.bayes_evictions.total` | Non-zero = cap pressure; consider raising max_entries. |
| `veilgate_miner_candidates_total` | `veilgate.ml.miner_candidates.total` | Candidates written to `learned.yaml` per miner tick. |

OTel instruments for bayes_evictions and miner_candidates were added in
v1.1.5 via atomic bridges — they now achieve full parity with Prometheus.

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_ml
```

## `score_max_points`

Syntax:  `score_max_points: <integer>`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Caps the maximum number of points contributed by `ml_agent_score`.

### Code path

- [`internal/ml/scorer.go`](../../internal/ml/scorer.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

### Operational notes

- Lower this value if ML is noisy in observe mode.
- Do not let ML alone push normal traffic into tarpit until reviewed.

## `min_confidence_to_fire`

Syntax:  `min_confidence_to_fire: <float>`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Sets the minimum combined confidence before ML adds points. Below this value,
ML stays silent.

### Code path

- [`internal/ml/scorer.go`](../../internal/ml/scorer.go)

### Operational notes

- Raise to reduce low-confidence contributions.
- Lower only after reviewing false negatives.

## `bayes`

Syntax:  `bayes: {laplace_smoothing, max_ngram_length, timing_buckets_seconds}`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Configures the online Naive Bayes component and path n-gram extraction.

### Code path

- [`internal/ml/bayes.go`](../../internal/ml/bayes.go)
- [`internal/ml/features.go`](../../internal/ml/features.go)

## `iso_forest`

Syntax:  `iso_forest: {tree_count, sample_size, retrain_every_n_events, max_depth, train_max_rows}`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Configures the Isolation Forest anomaly component. A background loop refits the
forest when enough rows are buffered and the previous fit is not still running.

### Code path

- [`internal/ml/isoforest.go`](../../internal/ml/isoforest.go)
- [`internal/ml/scorer.go`](../../internal/ml/scorer.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

## `miner`

Syntax:  `miner: {enabled, interval_minutes, min_support, min_posterior, auto_promote_confidence, write_path}`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Controls candidate generation into `rules/learned.yaml`. Candidates should be
reviewed before promotion.

### Code path

- [`internal/ml/miner.go`](../../internal/ml/miner.go)
- [`internal/persist/store.go`](../../internal/persist/store.go)

### Operational notes

- Learned rules are suggestions, not automatic production policy.
- Promote through code review.
- Keep `learned.yaml` versioned.

## `path_redaction`

Syntax:  `path_redaction: {enabled, custom}`  
Default: enabled by built-in redactors unless disabled  
Context: `rules/ml.yaml`

Scrubs high-entropy path segments such as UUIDs, numeric IDs, hex values, and
configured custom identifiers before they become features.

### Code path

- [`internal/ml/features.go`](../../internal/ml/features.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

### Operational notes

- Keep enabled unless intentionally researching raw feature behavior.
- Add custom redactors for app-specific identifiers.

## Related

- [Model Card](../model/README.md)
- [Module veilgate_persistence](../modules/veilgate_persistence.md)
- [How-to: promote learned rules](../how-to/promote-learned-rules.md)

