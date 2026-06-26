# Recommender Improvement Plan

**Status:** Planning  
**Version:** v1.1.8 baseline  
**Last updated:** 2026-06-24

---

## Overview

This document is the full improvement roadmap for VeilGate's signal recommender and ML detection layer. It is structured in four phases, from quick reliability wins to network-effect moat features.

### Why this matters

The current recommender generates useful suggestions but has fundamental ceiling problems:

- 5 analyzers, all pattern-matching on frequency alone
- On-demand analysis with a 10 s timeout — times out under real load
- Trains on weak labels (`score >= threshold` as proxy for "is bot")
- No JA4 fingerprint analysis despite storing JA4 on every event
- No LLM-specific behavioral analysis
- Signal weights are static YAML integers — never updated from observed outcomes
- Every confirmed attacker (honeytoken fired, challenge solved) is a wasted training example

The result: ~60% bot catch rate, ~4–6% false positive rate, weeks to detect new attack patterns.

The target after all phases: 95%+ catch rate, <0.5% FP rate, hours to detect new patterns.

---

## Baseline Metrics (v1.1.8)

| Metric | Value | Notes |
|---|---|---|
| Bot catch rate | ~60% | % of bots scoring ≥ challenge threshold |
| False positive rate | ~4–6% | Legitimate traffic flagged |
| Signal coverage | ~60% | % of known attack techniques triggering ≥1 signal |
| Time to detect new pattern | Weeks | Manual rule writing required |
| Analyzer count | 5 | PathExtension, PathPrefix, UASubstring, MethodCombo, UAPathCombo |
| ML model | Naive Bayes (70%) + Isolation Forest (30%) | Static alpha blend |
| Training label quality | Weak (heuristic) | `score >= threshold` as "agent" proxy |
| LLM agent detection | ~20% | Only via UA and path signals |

---

## Phase 1 — Foundation (Week 1–2)

**Goal:** Make the existing system reliable and expand analyzer coverage with zero architectural change.  
**Expected improvement:** 1.3× catch rate, 1.5× FP reduction, recommender never times out.

---

### 1.1 Background Recommender Caching

**Problem:** `handleRecommender` calls `rec.Analyze()` synchronously on every page load against a 10 s timeout. Under load it times out and shows nothing.

**Fix:** The `Run()` method and `StoreSuggestions()` already exist but are never called. Wire them up on startup so the recommender refreshes in the background every 6 hours. The HTTP handler serves the pre-computed cache from the `signal_suggestions` table instantly.

**Files:**
- `internal/admin/admin.go` — spawn `go s.runBackgroundRecommender()` after `openEventStore()`
- `internal/admin/analytics.go` — `handleRecommender` reads from `store.LoadSuggestions()` first, falls back to on-demand only on cold start

**Impact:** Zero detection improvement. Makes the page reliable and makes the 6-hour refresh cycle feasible for heavier analysis.

---

### 1.2 JA4 Fingerprint Analyzer

**Problem:** The `ja4` column is stored on every event. Automated tools almost never match real browser TLS fingerprints. This data is completely unused by the recommender.

**Research backing:** JA4 fingerprinting achieves ~98% precision in distinguishing bots from browsers ([arxiv 2602.09606](https://arxiv.org/html/2602.09606v1)). Modern anti-bot systems use JA4 alongside UA matching for full coverage.

**What it does:** Queries top JA4 values in tarpitted vs clean traffic. Any JA4 prefix appearing in ≥ `min_support` tarpitted events with ≥ `min_confidence` precision becomes a signal recommendation with 30 points (higher than UA signals — TLS fingerprints are harder to spoof than User-Agents).

**New files:**
- `internal/recommender/analyzer_ja4.go` — `JA4FingerprintAnalyzer` implementing `Analyzer`
- `internal/persist/store.go` — add `TopJA4ByTarpit(since, tarpitThreshold, limit)` query

**New condition type required:**
- `internal/rules/` + `internal/detector/scorer_custom.go` — add `ja4_prefix` condition type

**SQL query:**
```sql
SELECT ja4,
       COUNT(*) AS total,
       SUM(CASE WHEN score >= ? OR decision = 'tarpit' THEN 1 ELSE 0 END) AS tarpit
FROM events
WHERE ts >= ? AND ja4 != '' AND ja4 IS NOT NULL
GROUP BY ja4
HAVING tarpit > 0
ORDER BY tarpit DESC
LIMIT 50
```

**Signal output example:**
```yaml
- name: auto_ja4_t13d1516h2
  source: ja4_fingerprint
  confidence: 0.97
  support: 312
  false_positive_rate: 0.001
  signal:
    name: auto_ja4_t13d1516h2
    description: "Requests with suspicious TLS fingerprint (JA4 prefix t13d1516h2)"
    enabled: false
    points: 30
    conditions:
      - type: ja4_prefix
        value: t13d1516h2
```

**Impact:** +8–12% catch rate on bots that spoof User-Agents but use consistent TLS fingerprints (the majority of scanning tools).

---

### 1.3 Query Parameter Analyzer

**Problem:** SQL injection attempts, parameter fuzzing, and API enumeration all appear in query strings. None of the 5 current analyzers look at query parameters.

**What it does:** Extracts `?key` from every sampled path. Finds parameter names (e.g., `debug`, `cmd`, `file`, `id`) that appear almost exclusively in tarpitted traffic.

**New files:**
- `internal/recommender/analyzer_queryparam.go` — `QueryParamAnalyzer`

**Signal output example:**
```yaml
- name: auto_qp_cmd
  source: query_param
  confidence: 0.94
  support: 67
  signal:
    name: auto_qp_cmd
    enabled: false
    points: 15
    conditions:
      - type: query_contains
        value: cmd=
```

**Impact:** +3–5% catch rate on injection-class attacks that hit clean-looking paths with attack parameters.

---

### 1.4 Score-Aware Tarpitted Count (Aligns v1.1.8)

**Problem:** In observe mode, the recommender's `CountEventsByDecision` classified "tarpitted" as `decision='tarpit'` only. In observe mode nothing is ever tarpitted — so the recommender had near-zero training signal.

**Fix:** Already shipped in v1.1.8 — `CountDecisions` and `DecisionTimeSeries` now use `score >= tarpitThreshold OR decision='tarpit'` as the tarpitted label. Apply the same fix to `CountEventsByDecision` used by analyzers so recommender training labels align.

**Files:**
- `internal/persist/store.go` — `CountEventsByDecision` already has this logic; verify analyzers use it

**Impact:** The recommender now has training signal even in pure observe mode. All confidence/FP calculations become meaningful from day 1.

---

### Phase 1 Summary

| Item | Effort | Detection delta | FP delta |
|---|---|---|---|
| Background caching | Small | 0% | 0% |
| JA4 analyzer | Medium | +8–12% | ~0% |
| Query param analyzer | Small | +3–5% | +0.5% |
| Score-aware labels | Trivial | Enables accurate training | — |
| **Phase 1 total** | **~1 week** | **+11–17%** | **Slight improvement** |

---

## Phase 2 — Step Change (Month 1–2)

**Goal:** Build feedback loops and new intelligence dimensions that make detection self-improving.  
**Expected improvement:** 3–4× catch rate over baseline, 5× faster response to new attack tools.

---

### 2.1 Canary Token Feedback Loop

**The single highest-ROI item in this entire plan.**

**Problem:** When a `canary_token` signal fires, that is a **confirmed attacker** — they consumed a honeytoken embedded in a tarpit response and used it in a subsequent request. This is cryptographic proof of malicious intent. Currently this confirmation goes nowhere. The event is logged, the signal fires, and nothing is learned.

**What it does:**
1. When `canary_token` fires for client X, look up all prior events for that `client_id`
2. Mark them `confirmed_agent = 1` in the events table (new column)
3. Aggregate the signals that fired across those events into a high-confidence training batch
4. Increment `agent_count` in `features_rollup` for every feature in those events
5. On the next miner tick, those features get posterior updates with ground-truth labels

Similarly: when a challenge is successfully solved by a client, mark their events `confirmed_human = 1` and increment `human_count` in rollup.

**Schema change:**
```sql
ALTER TABLE events ADD COLUMN confirmed_agent INTEGER NOT NULL DEFAULT 0;
ALTER TABLE events ADD COLUMN confirmed_human INTEGER NOT NULL DEFAULT 0;
```

**Files:**
- `internal/persist/store.go` — `MarkConfirmedAgent(clientID string)`, `MarkConfirmedHuman(clientID string)`
- `internal/detector/scorer.go` — after `canary_token` signal fires, call `store.MarkConfirmedAgent(clientID)`
- Proxy middleware — after challenge solve, call `store.MarkConfirmedHuman(clientID)`
- `internal/persist/store.go` — miner uses `confirmed_agent`/`confirmed_human` columns for higher-weight rollup updates

**Impact:** Turns every successful tarpit into a labeled training example. Supervised learning on confirmed labels is 4–8× more sample-efficient than the current unsupervised approach. Catch rate improvement compounds over time as the system learns.

---

### 2.2 Operator Event Labeling UI

**Problem:** Operators looking at the logs page know which events are bots and which aren't. This knowledge is locked in their heads.

**What it does:** Add a "Mark as bot" / "Mark as human" button on each row of the logs page (`/logs`). Calls a new API endpoint that updates `confirmed_agent` / `confirmed_human` on that event and triggers a rollup update. The miner incorporates operator-labeled events on its next tick.

Even 100 labeled examples per week would dramatically improve training quality.

**Files:**
- `internal/admin/templates/pages/logs.html` — add label buttons per row
- `internal/admin/api.go` — `POST /api/events/:id/label` endpoint
- `internal/persist/store.go` — `LabelEvent(id int64, label string)`

**Impact:** Creates a human-in-the-loop training signal. Operators surface domain knowledge the ML can't infer from traffic alone.

---

### 2.3 LLM Behavioral Analyzer

**Problem:** LLM agents (OpenAI, Claude, Gemini) are VeilGate's primary target. They have a highly distinctive behavioral fingerprint that is already being captured but never analyzed:
- Inter-request pauses of 3–5 s (OpenAI inference) or 5–8 s (Claude) in the `pause_bucket` feature
- Systematic path traversal: many distinct paths, consistent depth increments
- No JavaScript execution signals (no cookie refresh, no browser-specific headers)

The `pause_bucket` feature is already in `features_json` for every event. This data is captured but the recommender ignores it entirely.

**What it does:** Queries clients where the dominant `pause_bucket` is `3_5` or `5_8` AND they've hit 5+ distinct paths. These are almost certainly LLM agents doing systematic recon.

**New store query:**
```sql
WITH client_features AS (
    SELECT client_id,
           COUNT(DISTINCT path) AS distinct_paths,
           SUM(CASE WHEN score >= ? OR decision='tarpit' THEN 1 ELSE 0 END) AS tarpit_count
    FROM events WHERE ts >= ?
    GROUP BY client_id
    HAVING distinct_paths >= 5
)
-- Cross with features_rollup to find dominant pause_bucket per client
```

**New files:**
- `internal/recommender/analyzer_llm.go` — `LLMBehavioralAnalyzer`
- `internal/persist/store.go` — `LLMClientStats(since, tarpitThreshold)`

**New condition type:**
- `pause_bucket_pattern` — evaluated by the session tracker, fires when a client's rolling pause distribution matches a specified bucket pattern

**Signal output example:**
```yaml
- name: llm_inference_timing
  source: llm_behavioral
  confidence: 0.92
  support: 47
  rationale: >
    47 clients show consistent LLM pause patterns (3–5s or 5–8s inter-request gaps)
    combined with systematic path traversal (5+ distinct paths). Human browsing
    produces irregular timing; LLM inference latency is statistically distinct.
  signal:
    name: llm_inference_timing
    description: "Inter-request timing consistent with LLM inference latency"
    enabled: false
    points: 25
    conditions:
      - type: pause_bucket_pattern
        value: "3_5|5_8"
```

**Impact:** +10–15% catch rate specifically on LLM agents. Very low FP rate — human browsing almost never produces consistent 3–8 s inter-request pauses across 5+ requests.

---

### 2.4 Score Correlation Analyzer

**Problem:** Signal weights are static. `suspicious_ua` has 20 points regardless of whether it's currently predicting high-score or low-score events. There is no mechanism to know if a signal is over- or under-weighted.

**What it does:** For each signal name in `signals_json`, compute:
- `avg_score_when_fired` across events in the lookback window
- `avg_score_when_not_fired`
- `precision_at_challenge_threshold` (what % of events where this fired scored ≥ challenge threshold)

Compares against the signal's configured `points`. If `avg_score_when_fired` is much higher than `points` would predict, recommend an increase. If much lower, recommend a decrease.

**New store query:**
```sql
SELECT je.value AS signal,
       AVG(score) AS avg_score,
       COUNT(*) AS fired_count,
       SUM(CASE WHEN score >= ? THEN 1 ELSE 0 END) AS challenge_count
FROM events, json_each(signals_json) je
WHERE ts >= ? AND json_valid(signals_json)
GROUP BY je.value
ORDER BY fired_count DESC
LIMIT 100
```

**Output:** Adds a `weight_adjustments` section to the recommender page and YAML:
```yaml
weight_adjustments:
  - signal: suspicious_ua
    current_points: 20
    recommended_points: 30
    avg_score_when_fired: 67
    precision_at_challenge: 0.91
    rationale: >
      Fires on avg score 67, with 91% of matches scoring above challenge threshold.
      Current weight of 20 is conservative — increase to 30.

  - signal: sec_fetch_partial
    current_points: 15
    recommended_points: 8
    avg_score_when_fired: 22
    precision_at_challenge: 0.41
    rationale: >
      Fires on avg score 22, only 41% above challenge threshold.
      May be firing on legitimate SPAs. Consider reducing to 8.
```

**New files:**
- `internal/recommender/analyzer_score_corr.go` — `ScoreCorrelationAnalyzer`
- `internal/persist/store.go` — `SignalScoreStats(since, challengeThreshold)`

**Impact:** Better-calibrated weights reduce FP rate by 1–3% and increase precision on challenge decisions.

---

### 2.5 Adaptive Signal Weight Recommendations (6-hour cycle)

**Problem:** Score correlation analysis (2.4) runs once. Weights change once. But attack tools evolve week by week.

**What it does:** On every background recommender cycle (every 6 hours), recompute score correlations and update the weight recommendations in the `signal_suggestions` table. Operators see an always-current recommendation. A future auto-promote path (Phase 3) can apply safe adjustments automatically.

**Impact:** Signal tuning goes from quarterly manual review to continuous automated recommendation.

---

### 2.6 Temporal Analyzer

**Problem:** Attacks cluster at specific UTC hours. A scanner running at 03:00 UTC every night is not a human. This pattern is invisible to per-request scoring.

**What it does:** Computes hourly attack rate as `tarpitted_count / total_count` per UTC hour. Hours where the ratio is > 3× the overall average become a signal recommendation. Also detects day-of-week patterns.

**New files:**
- `internal/recommender/analyzer_temporal.go` — `TemporalAnalyzer`

**Signal output example:**
```yaml
- name: auto_time_0300_0400
  source: temporal
  confidence: 0.89
  support: 234
  signal:
    name: auto_time_0300_0400
    description: "Requests between 03:00–04:00 UTC (historically 89% attack traffic)"
    enabled: false
    points: 10
    conditions:
      - type: utc_hour_range
        value: "3-4"
```

**Impact:** +3–6% catch rate on scheduled scanners. Very low FP rate during identified attack windows.

---

### Phase 2 Summary

| Item | Effort | Detection delta | FP delta |
|---|---|---|---|
| Canary token feedback loop | Medium | +15–20% (compounds) | −5% |
| Operator event labeling UI | Medium | +5–10% (over time) | −3% |
| LLM behavioral analyzer | Medium | +10–15% | −0.1% |
| Score correlation analyzer | Small | 0% direct | −1–3% |
| Adaptive weight cycle | Small | 0% direct | −2–4% |
| Temporal analyzer | Small | +3–6% | ~0% |
| **Phase 2 total** | **~3–4 weeks** | **+33–51% over baseline** | **Major reduction** |

**Compounded Phase 1 + 2: ~3–4× baseline catch rate, FP rate under 2%.**

---

## Phase 3 — Exponential (Month 3–6)

**Goal:** Build the architectural features that create compounding returns — the system gets smarter every day with decreasing operator effort.

---

### 3.1 Community Threat Intel Feed (Opt-In)

**The network effect lever.**

**Problem:** VeilGate is self-hosted. Every instance sees only its own traffic. A new scanning tool fingerprinted at one deployment is unknown to all others until a community rule is manually written and released. This is weeks of lag.

**What it does:** An opt-in contribution system where VeilGate instances share signal posteriors and fingerprint hashes — never traffic content, IPs, or request data.

**What gets shared (opt-in only):**
```
✓ JA4 prefix → posterior probability (e.g., "t13d1516h2: 0.97 agent")
✓ ua_token → posterior (e.g., "python-requests: 0.98 agent")
✓ path_ngram hash → tarpit rate (hashed, not raw paths)
✗ Never: IPs, full paths, request bodies, user data, anything identifiable
```

**Architecture:**
```
Instance A detects new tool (JA4: abc123, posterior: 0.96, support: 200)
    → Contributes to community aggregator (opt-in flag in config)
    → Aggregator federates: weighted average across all contributors
    → New entry in community veilgate-rules feed
    → All subscribed instances pull updated learned.yaml within 1 hour
    → No instance B operator needed to write a rule
```

**Infrastructure needed:**
- Aggregator service (small Go service, can be run on veilgate.dev)
- `POST /api/v1/contribute` endpoint on aggregator
- `GET /api/v1/feed` endpoint serving aggregated posteriors
- New config option: `community.enabled: false`, `community.endpoint: ""`
- Background goroutine in VeilGate to contribute + pull on miner tick

**Impact:** Time-to-detect for new attack tools drops from weeks to hours. Every deployment benefits from every other deployment's observations. This is the Cloudflare/DataDome advantage — now available for self-hosted deployments.

---

### 3.2 Auto-Promote with Safety Guard

**Problem:** High-confidence candidates sit in the `rule_candidates` table indefinitely waiting for operator action. `auto_promote_confidence` is set to `0.0` (disabled) by default.

**What it does:** A safe, conservative auto-promotion path:
1. A candidate must have `posterior >= 0.99` for 7 consecutive miner ticks (7 days if interval = 24h)
2. Support must be ≥ 500 events (enough statistical evidence)
3. FP rate on clean traffic must be < 0.5%
4. Auto-promotion writes the candidate to `learned.yaml` with `active: true`
5. An audit log entry is created and flagged in the admin UI for operator awareness
6. Operator can revert via the Rules page

**Config addition to ml.yaml:**
```yaml
miner:
  auto_promote_confidence: 0.99      # Was 0.0 (disabled)
  auto_promote_min_days: 7           # Must be consistent for 7 days
  auto_promote_min_support: 500      # Must have enough evidence
  auto_promote_max_fp_rate: 0.005    # Must not exceed 0.5% FP on clean traffic
```

**Impact:** High-confidence patterns get activated without human intervention. Reduces operator burden for obvious cases while keeping humans in the loop for anything ambiguous.

---

### 3.3 Co-Occurrence Matrix and Signal Fusion

**Problem:** Multiple signals often fire together. If `suspicious_ua` + `sparse_headers` + `empty_ua` all fire together on 80% of the same events, they're highly correlated and their individual weights overcount the same underlying evidence.

**What it does:**
1. Build a co-occurrence matrix: for each pair of signals (S1, S2), compute how often they fire on the same event
2. Identify clusters of highly co-occurring signals (> 0.85 co-occurrence rate)
3. Two outputs:
   - **Fusion suggestion:** "These 3 signals always fire together. Consider creating a combined signal with merged score."
   - **Weight correction:** Reduce individual weights of highly correlated signals to avoid double-counting

**New files:**
- `internal/recommender/analyzer_cooccurrence.go`
- `internal/persist/store.go` — `SignalCooccurrenceMatrix(since)`

**Impact:** Reduces effective FP rate by preventing correlated signals from artificially inflating scores. Improves precision of challenge/tarpit decisions.

---

### 3.4 Session Graph Analysis

**Problem:** Individual-request scoring misses coordinated attacks. An attacker using 20 IPs with the same JA4 fingerprint, systematically traversing the same paths in sequence, is invisible to per-IP analysis if each IP is below threshold.

**What it does:** Builds a lightweight graph in SQLite:
- Nodes: `client_id` values
- Edges: shared JA4 prefix, shared path sequence, overlapping timing windows
- Connected components with ≥ 3 nodes and ≥ 70% tarpitted events → fleet signal

**Detection outcome:** When a new client shares a JA4 prefix with a known fleet (even if their individual score is 15), they inherit a fleet_member signal (+20 points).

**Leverages existing:** `internal/detector/fleet.go` already tracks JA4 across IPs. This extends it to the recommender output.

**Impact:** Catches IP-rotating attacks that individually stay below thresholds. Particularly effective against LLM agent fleets using shared infrastructure.

---

### 3.5 Drift Detection

**Problem:** Attack patterns change. A signal that was 95% precise last month might be 40% precise today because attackers have adapted. Currently there is no alert for this.

**What it does:** On every background recommender cycle:
1. Compare each active signal's current 7-day precision against its 30-day average
2. If precision has dropped > 20 percentage points → `signal_degraded` alert in admin UI
3. If a previously inactive JA4 cluster suddenly appears in high volume → `new_attack_pattern` alert
4. Alerts surfaced on the recommender page and optionally via admin audit log

**New files:**
- `internal/recommender/drift.go` — `DriftDetector`

**Impact:** Operators are notified when the detection landscape changes. Prevents confidence from decaying silently.

---

### Phase 3 Summary

| Item | Effort | Detection delta | Strategic value |
|---|---|---|---|
| Community threat intel feed | Large | +25–35% | Network effect — compounds indefinitely |
| Auto-promote with safety guard | Medium | +5% (via speed) | Reduces operator burden 80% |
| Co-occurrence matrix | Medium | −2–3% FP | Better calibration |
| Session graph analysis | Large | +10–15% on fleet attacks | Catches IP-rotating attacks |
| Drift detection | Small | 0% direct | Prevents precision decay |
| **Phase 3 total** | **~2 months** | **+40–55% over Phase 2** | **Self-improving system** |

**Compounded Phase 1 + 2 + 3: ~8–10× baseline catch rate, FP rate under 0.5%.**

---

## Phase 4 — Moat (Year 1)

**Goal:** Features that are only possible because of the network and data accumulated in Phases 1–3. Competitors cannot replicate these without the same deployment base.

---

### 4.1 Adaptive Decoy Content (LLM-Generated)

**Problem:** Current tarpit responses are static. A sufficiently determined attacker learns to ignore them.

**What it does:** When a client is tarpitted, instead of returning a static slow response, an LLM generates contextually appropriate fake content based on the requested path and apparent attacker goal:

```
Attacker requests: GET /api/v1/users?limit=1000
LLM generates: 1000 fake user records with realistic names, emails, IDs
  └─ Each record contains a unique canary token embedded in a field value
  └─ Data format matches the real API schema (learned from blueprint)
  └─ Response is streamed slowly to maximize attacker dwell time

When attacker processes this data:
  └─ Canary tokens fire when the stolen data is used elsewhere
  └─ Attacker has wasted: download time + processing time + embedding cost
  └─ VeilGate has confirmation: this is a data exfiltration attempt
```

**Cost asymmetry:** 1 LLM call (cents) vs attacker processing 1000 records (minutes of compute). At scale, this makes VeilGate deployments economically hostile to automated attackers.

**Config addition:**
```yaml
tarpit:
  adaptive_decoys:
    enabled: false
    provider: "anthropic"        # or "openai", "local"
    model: "claude-haiku-4-5"    # Fast and cheap for decoy generation
    max_tokens: 4096
    embed_canary: true
```

**Impact:** Changes the economics of attacking VeilGate deployments. Detection rate becomes less critical when the cost of failing to evade detection is very high.

---

### 4.2 LLM Fingerprint Database

**Problem:** Every major LLM API provider (OpenAI, Anthropic, Google, Mistral) runs their inference on specific infrastructure with consistent JA4 fingerprints, IP ranges, and timing patterns. These are knowable and stable enough to maintain a curated database.

**What it does:** A maintained YAML file in `veilgate-rules` mapping known LLM provider fingerprints:

```yaml
# veilgate-rules/llm-fingerprints.yaml
providers:
  - name: openai_crawler
    ja4_prefixes: ["t13d1516h2", "t13d1517h2"]
    ua_patterns: ["GPTBot/", "ChatGPT-User/", "OAI-SearchBot/"]
    asn_ranges: ["AS14618", "AS16509"]  # AWS ASNs used by OpenAI
    pause_bucket: "3_5"
    points: 35

  - name: anthropic_claude
    ua_patterns: ["Claude-Web/", "anthropic-ai/"]
    pause_bucket: "5_8"
    points: 35

  - name: generic_llm_agent
    pause_bucket_pattern: "3_5|5_8"
    path_pattern: systematic_traversal
    points: 20
```

This becomes a first-class rule type that operators get out of the box, updated with each VeilGate release.

**Impact:** Zero-config LLM agent detection for the known provider fingerprints.

---

### 4.3 Signal Marketplace

**What it does:** A curated registry of high-quality detection rules contributed by the community, with metadata (author, severity, FP rate, tags, CVE references). Operators can browse, pull, and optionally contribute their own.

**Format:** Extends the existing `learned.yaml` schema with the `info:` block (already defined in the rules package):

```yaml
- id: VG-UA-0042
  feature: ua_token
  bucket: nuclei
  posterior: 0.999
  support: 12000
  active: false
  info:
    name: "Nuclei security scanner"
    author: "veilgate-community"
    severity: "high"
    description: "Default UA emitted by the Nuclei vulnerability scanner."
    tags: [scanner, nuclei, pentest]
    reference:
      - https://github.com/projectdiscovery/nuclei
    false_positive_rate: "very-low"
```

**Infrastructure:**
- `veilgate.dev/rules` — searchable registry
- `veilgate update-rules --marketplace` — pull curated rules
- Contributor workflow via GitHub PRs to `veilgate-rules`

**Impact:** Operators get detection coverage on day 1 that would take months to accumulate organically.

---

### Phase 4 Summary

| Item | Effort | Strategic value |
|---|---|---|
| Adaptive LLM decoys | Large | Changes attack economics — cost asymmetry |
| LLM fingerprint database | Medium | Zero-config LLM detection out of the box |
| Signal marketplace | Large | Community moat — quality compounds with contributors |

---

## Full Roadmap Summary

```
WEEK 1–2  ─── Phase 1: Foundation
              JA4 analyzer, query param analyzer, background caching,
              score-aware training labels
              Impact: 1.3× baseline, recommender never times out

MONTH 1–2 ─── Phase 2: Step Change
              Canary feedback loop, operator labeling UI, LLM behavioral
              analyzer, score correlation, adaptive weight cycle, temporal
              Impact: 3–4× baseline, hours to detect new patterns

MONTH 3–6 ─── Phase 3: Exponential
              Community threat intel feed, auto-promote, co-occurrence
              matrix, session graph analysis, drift detection
              Impact: 8–10× baseline, system improves automatically

YEAR 1    ─── Phase 4: Moat
              Adaptive LLM decoys, LLM fingerprint database, signal
              marketplace
              Impact: Economic deterrence, network-effect moat
```

---

## Implementation Priority Order

If only one item can be done at a time, in strict priority order:

1. **Background caching** — makes everything else feasible by enabling long analysis cycles
2. **Canary token feedback loop** — single highest ROI, turns honeypots into training data
3. **JA4 fingerprint analyzer** — highest precision new signal category
4. **Operator event labeling UI** — humans surface what ML can't infer
5. **LLM behavioral analyzer** — primary target class, nobody else has this
6. **Community threat intel feed** — creates compounding returns across all deployments

---

## Files to Create / Modify (by Phase)

### Phase 1
| File | Change |
|---|---|
| `internal/recommender/analyzer_ja4.go` | New file |
| `internal/recommender/analyzer_queryparam.go` | New file |
| `internal/recommender/recommender.go` | Register new analyzers |
| `internal/persist/store.go` | Add `TopJA4ByTarpit`, `LoadSuggestions` |
| `internal/rules/signal.go` | Add `ja4_prefix` condition type |
| `internal/detector/scorer_custom.go` | Handle `ja4_prefix` condition |
| `internal/admin/admin.go` | Spawn background recommender goroutine |
| `internal/admin/analytics.go` | Serve recommender from cache |

### Phase 2
| File | Change |
|---|---|
| `internal/recommender/analyzer_llm.go` | New file |
| `internal/recommender/analyzer_score_corr.go` | New file |
| `internal/recommender/analyzer_temporal.go` | New file |
| `internal/persist/store.go` | Add `MarkConfirmedAgent`, `MarkConfirmedHuman`, `LLMClientStats`, `SignalScoreStats` |
| `internal/persist/migrations.go` | Add `confirmed_agent`, `confirmed_human` columns |
| `internal/detector/scorer.go` | Call `MarkConfirmedAgent` on canary fire |
| `internal/admin/api.go` | Add `POST /api/events/:id/label` |
| `internal/admin/templates/pages/logs.html` | Add label buttons |
| `internal/rules/signal.go` | Add `pause_bucket_pattern`, `utc_hour_range` condition types |

### Phase 3
| File | Change |
|---|---|
| `internal/recommender/analyzer_cooccurrence.go` | New file |
| `internal/recommender/drift.go` | New file |
| `internal/detector/fleet.go` | Extend for graph analysis |
| `internal/community/` | New package — contribution + feed client |
| `cmd/veilgate/main.go` | Wire community client |
| `internal/rules/ml.go` | Add auto-promote config fields |
| `internal/persist/store.go` | Add graph analysis queries |

### Phase 4
| File | Change |
|---|---|
| `internal/tarpit/decoy.go` | LLM-generated adaptive content |
| `veilgate-rules/llm-fingerprints.yaml` | New rule file |
| `internal/rules/loader.go` | Load llm-fingerprints.yaml |

---

## Key Metrics to Track

Track these on the Analytics page to measure phase progress:

| Metric | Phase 1 target | Phase 2 target | Phase 3 target |
|---|---|---|---|
| Bot catch rate | 72% | 85% | 95% |
| False positive rate | 3–4% | 1.5–2% | < 0.5% |
| Confirmed labels / day | 0 | > 10 | > 50 |
| Recommender suggestions | 5–10 | 15–25 (incl. weight adjustments) | 30+ |
| Time to detect new tool | Days | Hours | < 1 hour (with community feed) |
| LLM agent catch rate | ~20% | 65% | 85% |
