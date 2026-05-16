# Module veilgate_ml

The `veilgate_ml` module documents optional online ML scoring and rule mining.
ML is an additive detector signal, not the primary enforcement engine. The
deterministic rules and thresholds still control final routing. When enabled,
ML adds the `ml_agent_score` signal. The final score is capped at 100 regardless
of what ML contributes.

This module is analogous to NGINX's `limit_req_zone` learning mode — it learns
patterns from observed traffic, but all enforcement decisions remain under
explicit operator control.

## Algorithm Overview

VeilGate's ML component is a hybrid of two models that operate concurrently:

### Naive Bayes (online, incremental)

A multinomial Naive Bayes classifier operating over path n-gram features plus
behavioral features (timing buckets, status ratios, request rate, UA type).

- **Feature extraction**: `internal/ml/features.go` extracts path segments,
  builds n-grams up to `max_ngram_length`, and redacts high-entropy tokens
  (UUIDs, numeric IDs, hex strings) before they become features.
- **Classes**: `bot` and `human`. The classifier computes
  $P(\text{bot} \mid \text{features})$ using Laplace-smoothed counts.
- **Weak-label training**: `Observe(vec, total, agentThreshold)` is called
  after each scored request. If the deterministic score is above
  `agentThreshold`, the example is weakly labeled as `bot`. If it is below a
  low threshold, it is labeled `human`. Ambiguous examples are not labeled.
- **Burn-in**: ML does not fire until `observed` atomic counter reaches a
  minimum threshold (configured in `ml.yaml`). Below burn-in, the signal
  returns 0 points with reason `burn-in`.

```go
// internal/ml/scorer.go (schematic)
func (s *Scorer) Score(vec FeatureVec) Result {
    if s.observed.Load() < s.cfg.BurnInObservations {
        return Result{Points: 0, Reason: "burn-in"}
    }
    posterior := s.bayes.PosteriorBot(vec)
    anomaly := s.isoForest.Score(vec)
    // Combine and scale
    combined := combineScores(posterior, anomaly, s.cfg)
    if combined < s.cfg.MinConfidenceToFire {
        return Result{Points: 0, Reason: "below-threshold"}
    }
    return Result{
        Points:        int(combined * float64(s.cfg.ScoreMaxPoints)),
        Reason:        "ml_agent_score",
        PosteriorAgent: posterior,
        Anomaly:       anomaly,
        Fired:         true,
    }
}
```

### Isolation Forest (periodic refit)

An Isolation Forest anomaly detector built over the feature vectors of recent
requests. Requests that require fewer tree splits to isolate (shorter average
path length) have higher anomaly scores.

- **Refit**: `RefitAsync()` is triggered when the sample buffer reaches
  `retrain_every_n_events`. It refits in a background goroutine to avoid
  blocking the proxy.
- **Score**: `isoForest.Score(vec)` returns a value in [0, 1]. Higher values
  mean the feature vector is more anomalous relative to the training window.
- **Combination**: Both the Bayes posterior and the isolation score are
  combined with configurable weights. Either component can be dominant.

### Miner

The miner reads the `rule_candidates` table from SQLite (written by the ML
component) and produces candidate detection rules in `rules/learned.yaml`.
These are suggestions for operator review, not automatically promoted policy.

## Burn-in Period

ML does not contribute to scores during the burn-in period. This prevents
untrained models from influencing enforcement decisions immediately after a
fresh deployment. During burn-in:

- `Score()` returns 0 points with reason `"burn-in"`.
- `Observe()` still accumulates training examples.
- The Prometheus counter `veilgate_ml_observations_total` increments.

Once `observed >= burn_in_observations` (configured in `ml.yaml`), the ML
signal becomes active.

**Recommendation**: start in `observe` mode with ML enabled so the model
trains on production traffic before any enforcement is enabled.

## Example Configuration

```yaml
# rules/ml.yaml
enabled: true
score_max_points: 40
min_confidence_to_fire: 0.2
burn_in_observations: 1000

bayes:
  laplace_smoothing: 1.0
  max_ngram_length: 4
  timing_buckets_seconds: [0.1, 0.5, 1.0, 5.0]

iso_forest:
  tree_count: 100
  sample_size: 256
  retrain_every_n_events: 5000
  max_depth: 12

miner:
  enabled: true
  interval_minutes: 60
  min_support: 0.1
  min_posterior: 0.8
  auto_promote_confidence: 0.95
  write_path: "rules/learned.yaml"

path_redaction:
  enabled: true
  custom:
    - pattern: "/users/[0-9]+"
      replacement: "/users/{id}"
```

## Directives

- `enabled`
- `score_max_points`
- `min_confidence_to_fire`
- `burn_in_observations`
- `bayes`
- `iso_forest`
- `miner`
- `path_redaction`

## `enabled`

Syntax:  `enabled: true | false`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Enables ML scoring. The scorer is constructed at startup either way; this field
gates whether the ML signal contributes points to incoming requests.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — constructs and wires ML scorer.
- [`internal/ml/scorer.go`](../../internal/ml/scorer.go) — `Score()` checks `enabled`.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) — calls `mlScorer.Score()`.

### Operational notes

- Use deterministic rules and observe-mode baselines first.
- Treat ML as a supporting signal that adds points, never the sole signal.
- Watch `veilgate_ml_score_points` and `veilgate_ml_fits_total`.

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_ml
```

## `score_max_points`

Syntax:  `score_max_points: <integer>`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Caps the maximum points contributed by `ml_agent_score`. Even if the combined
Bayes/IsoForest confidence is 1.0, ML adds at most this many points to the
total score.

### Operational notes

- Set to `20–40` while validating the model on production traffic.
- Lower to `10` if false positives appear in observe mode.
- Do not set above `60` unless the model has been validated on at least 30 days
  of production traffic.

## `min_confidence_to_fire`

Syntax:  `min_confidence_to_fire: <float 0.0–1.0>`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Minimum combined confidence (weighted Bayes posterior + IsoForest anomaly) for
the ML signal to add points. Below this value, ML returns 0 points.

### Operational notes

- `0.2` is a conservative starting point.
- Reduce only after reviewing false negatives.
- Raise if the model generates low-confidence noise on normal traffic.

## `bayes`

Syntax:  `bayes: {laplace_smoothing, max_ngram_length, timing_buckets_seconds}`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Configures the online Naive Bayes component:

| Sub-field | Description |
| --- | --- |
| `laplace_smoothing` | Additive smoothing constant. `1.0` is standard Laplace smoothing. |
| `max_ngram_length` | Maximum path n-gram length. Longer captures multi-segment patterns. |
| `timing_buckets_seconds` | Inter-request timing bucket boundaries for behavioral features. |

### Code path

- [`internal/ml/bayes.go`](../../internal/ml/bayes.go) — `NaiveBayes` struct, `PosteriorBot()`.
- [`internal/ml/features.go`](../../internal/ml/features.go) — `Extract()`, n-gram tokenizer.

## `iso_forest`

Syntax:  `iso_forest: {tree_count, sample_size, retrain_every_n_events, max_depth, train_max_rows}`  
Default: embedded rule value  
Context: `rules/ml.yaml`

Configures the Isolation Forest anomaly component:

| Sub-field | Description |
| --- | --- |
| `tree_count` | Number of isolation trees. `100` is standard. |
| `sample_size` | Subsample rows per tree during training. `256` is standard. |
| `retrain_every_n_events` | Trigger async refit after this many observed events. |
| `max_depth` | Maximum isolation depth. Controls overfitting. |
| `train_max_rows` | Maximum rows in the training buffer. Old rows are evicted. |

### Code path

- [`internal/ml/isoforest.go`](../../internal/ml/isoforest.go) — `IsoForest` struct, `Fit()`, `Score()`.
- [`internal/ml/scorer.go`](../../internal/ml/scorer.go) — `RefitAsync()` trigger.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — refit trigger goroutine.

### Operational notes

- Higher `tree_count` increases memory and refit time.
- Increase `retrain_every_n_events` to reduce refit frequency on high-volume
  traffic.
- Check `veilgate_ml_fits_total{result="ok"}` to confirm refits are succeeding.

## `miner`

Syntax:  `miner: {enabled, interval_minutes, min_support, min_posterior, auto_promote_confidence, write_path}`  
Default: embedded rule value  
Context: `rules/ml.yaml`

The miner reads high-confidence records from `rule_candidates` and writes
proposed detection rules to `write_path`. Candidates must be reviewed before
being relied upon for enforcement.

| Sub-field | Description |
| --- | --- |
| `enabled` | Enables the background miner goroutine. |
| `interval_minutes` | How often the miner runs. |
| `min_support` | Minimum fraction of bot-labeled traffic showing a feature. |
| `min_posterior` | Minimum Bayes posterior for inclusion as a candidate rule. |
| `auto_promote_confidence` | Confidence threshold for auto-writing to `learned.yaml`. |
| `write_path` | Output YAML file for proposed rules. |

### Code path

- [`internal/ml/miner.go`](../../internal/ml/miner.go) — `Miner.Run()`.
- [`internal/persist/store.go`](../../internal/persist/store.go) — reads `rule_candidates` table.

### Operational notes

- Treat `learned.yaml` as a review queue, not live policy.
- Run the miner for 1–2 weeks before reviewing output.
- Version `learned.yaml` in Git for traceability.

## `path_redaction`

Syntax:  `path_redaction: {enabled, custom}`  
Default: enabled with built-in redactors  
Context: `rules/ml.yaml`

Scrubs high-entropy path segments before they become ML features. Without
redaction, UUIDs and numeric IDs create unique feature tokens that never repeat,
making n-gram features meaningless.

Built-in redactors replace:
- UUIDs (`/api/abc123de-...`) → `/api/{uuid}`
- Long numeric IDs (`/users/1234567890`) → `/users/{id}`
- Long hex strings → `{hex}`

Custom redactors allow app-specific patterns:

```yaml
path_redaction:
  enabled: true
  custom:
    - pattern: "/users/[0-9]+"
      replacement: "/users/{id}"
    - pattern: "/sessions/[a-f0-9]{32}"
      replacement: "/sessions/{token}"
```

### Code path

- [`internal/ml/features.go`](../../internal/ml/features.go) — `Redact()`.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — wires path redaction config.

### Operational notes

- Keep enabled unless intentionally studying raw path feature distributions.
- Add custom redactors for application-specific high-entropy routes.
- Verify redaction is working by watching feature token diversity in
  `rule_candidates`.

## Related

- [Model Card](../model/README.md)
- [Module veilgate_persistence](veilgate_persistence.md)
- [Online ML internals](../functionalities/online-ml.md)
- [How-to: promote learned rules](../how-to/promote-learned-rules.md)

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
- [Module veilgate_persistence](veilgate_persistence.md)
- [How-to: promote learned rules](../how-to/promote-learned-rules.md)

