# `rules/learned.yaml` and `rules/learned/`

Syntax:  learned rule candidate file (flat) or per-feature directory  
Default: `candidates: []`  
Context: ML miner workflow, community rules distribution

VeilGate maintains learned candidate rules in two complementary locations:

| Location | Owner | Purpose |
| --- | --- | --- |
| `<rules_dir>/learned.yaml` | ML miner | Local operator candidates, regenerated each miner tick |
| `<rules_dir>/learned/<feature>.yaml` | Community / operator | Pre-reviewed rules distributed via `veilgate update-rules` |

Both locations share the same YAML structure (`candidates: []`). `LoadLearned`
merges them at startup and on hot-reload. Active candidates from both sources
seed the Bayes classifier via `Scorer.SeedFromLearned` so that community rules
take effect immediately — before the local burn-in period fills from live traffic.

The miner **only** writes `learned.yaml` (root file). It never touches `learned/`.
Community rules files in `learned/` are static, human-reviewed, and distributed
as part of a release ZIP via `veilgate update-rules`.

## Directory Layout

```text
~/.veilgate/rules/
├── learned.yaml              ← miner output (auto-managed)
└── learned/
    ├── ua_token.yaml         ← community: user-agent bucket rules
    ├── path_ngram.yaml       ← community: URL path n-gram rules
    ├── ja4_prefix.yaml       ← community: JA4 TLS fingerprint rules
    ├── header_set_id.yaml    ← community: HTTP header combination rules
    ├── timing_bucket.yaml    ← community: inter-request timing rules
    └── method.yaml           ← community: HTTP method anomaly rules
```

## Example

**`learned.yaml`** (miner-managed, do not edit the full list):
```yaml
candidates:
  - feature: ua_token
    bucket: python-requests
    posterior: 0.98
    support: 47
    active: false
    proposed_at: "2026-05-16T10:00:00Z"
```

**`learned/ua_token.yaml`** (community-distributed, pre-reviewed, with full metadata):
```yaml
# Community-reviewed UA token rules — distributed via veilgate update-rules.
candidates:
  # Rule from miner output — observed traffic, posterior + support provided.
  - id: VG-UA-001
    feature: ua_token
    bucket: python-requests
    posterior: 0.98
    support: 312
    active: true
    info:
      name: Python requests library default User-Agent
      author: C0oki3s
      severity: medium
      description: |
        Default User-Agent emitted by the Python `requests` library when no
        custom UA is set (`python-requests/2.x.x`). Heavily used by automated
        scanners, API clients, and LLM agent toolchains. Legitimate browser
        traffic never emits this string.
      impact: |
        Traffic is almost certainly automated. Likely a scanner, scraper, or
        AI agent probing the application. High prior for injection payload
        delivery, credential stuffing, and LLM-assisted reconnaissance.
      remediation: |
        Enable `challenge` or `tarpit` mode with `score_challenge_threshold`
        set to 40 or lower. Combine with the `suspicious_user_agents` detector
        signal for defense-in-depth.
      tags: [ua_token, scanner, python, automation, llm-agent]
      reference:
        - https://requests.readthedocs.io/
        - https://github.com/C0oki3s/veilgate-rules
      metadata:
        verified: "true"
        source: community
        false_positive_rate: low
        tool: python-requests

  # Rule from miner output.
  - id: VG-UA-002
    feature: ua_token
    bucket: python-httpx/0.27
    posterior: 0.97
    support: 188
    active: true
    info:
      name: Python HTTPX async client default User-Agent
      author: C0oki3s
      severity: medium
      description: |
        Default UA from the HTTPX library, commonly used by modern LLM agent
        frameworks (LangChain, AutoGPT, CrewAI) and async Python automation.
      tags: [ua_token, scanner, python, httpx, llm-agent]
      metadata:
        verified: "true"
        source: community
        false_positive_rate: low
        tool: httpx

  # Rule from human knowledge / tool fingerprint research.
  # No observed traffic needed — posterior and support are omitted.
  # VeilGate seeds the Bayes classifier with synthetic defaults (posterior=0.99,
  # support=10) so the rule takes effect immediately.
  - id: VG-UA-003
    feature: ua_token
    bucket: nuclei/3
    active: true
    info:
      name: Nuclei scanner default User-Agent
      author: C0oki3s
      severity: high
      description: |
        Default User-Agent prefix emitted by the Nuclei vulnerability scanner
        (projectdiscovery). No legitimate user browser ever sends this string.
      impact: |
        Active vulnerability scanning. High confidence of automated probing;
        escalate immediately to tarpit.
      tags: [ua_token, scanner, nuclei, projectdiscovery]
      reference:
        - https://github.com/projectdiscovery/nuclei
      metadata:
        verified: "true"
        source: community
        false_positive_rate: low
        tool: nuclei
```

## Rule Format Reference

Every candidate entry supports the following fields:

```yaml
candidates:
  - id: <string>               # Unique rule ID, e.g. VG-UA-001. Optional but recommended.
    feature: <string>          # Required. Feature family (see Feature Families below).
    bucket: <string>           # Required. Exact bucket value to match.
    posterior: <float>         # Optional. P(agent|bucket) ∈ [0,1]. Omit for human-knowledge rules.
    support: <int>             # Optional. Observation count. Omit for human-knowledge rules.
    active: <bool>             # Required. true enables the rule; false is pending review.
    proposed_at: <string>      # Optional. RFC3339 timestamp. Written by miner; strip before contributing.

    info:                      # Optional block — never inspected by scoring engine.
      name: <string>           # Short human-readable label.
      author: <string>         # GitHub username or email.
      severity: <string>       # One of: info | low | medium | high | critical.
      description: |           # What traffic pattern this detects and why.
        ...
      impact: |                # What a matched client is likely attempting.
        ...
      remediation: |           # Tuning advice for the operator.
        ...
      tags:                    # Filter/search labels. No spaces; use hyphens.
        - scanner
        - python
      reference:               # URLs to threat intel, tool docs, CVEs.
        - https://...
      metadata:                # Free-form string→string quality/tooling signals.
        verified: "true"       # Tested against real agent traffic?
        source: community      # "community" | "miner" | "operator"
        false_positive_rate: low  # "low" | "medium" | "high"
        min_veilgate_version: "0.4.0"  # Earliest compatible release.
        tool: nuclei           # Tool or framework that generates this bucket.
```

### Feature Families

| `feature` | `bucket` format | Example |
| --- | --- | --- |
| `ua_token` | UA library substring | `python-requests`, `go-http-client/1.1` |
| `path_ngram` | URL path 1..n-gram | `admin/config`, `.git/config` |
| `ja4_prefix` | JA4 fingerprint prefix | `t13d1516h2_` |
| `header_set_id` | SHA1 of sorted header names | `a3f2c1...` |
| `timing_bucket` | Interval label | `le_0.1`, `gt_60` |
| `method` | HTTP method | `HEAD`, `TRACE` |

### Severity Guide

| Severity | When to use |
| --- | --- |
| `info` | Unusual but benign, or very low posterior |
| `low` | Weak signal; combine with other rules |
| `medium` | Typical scanner/automation UA or path |
| `high` | Strong agent signal with low FP risk |
| `critical` | Near-certain agent traffic; auto-promote safe |

## LLM Template Generation

The format is intentionally close to Nuclei so any LLM trained on security templates can generate rules from a short prompt. Copy and adapt the prompt below:

```
You are a VeilGate detection rule author. Write a learned candidate rule in YAML
for the following behavioral pattern:

  Feature: ua_token
  Bucket:  <the exact user-agent substring>
  Posterior: <estimated P(agent) from 0.0 to 1.0>
  Support: <how many observations>

Use this exact schema — all fields under `info:` are optional but include as many as
you know:

candidates:
  - id: VG-<FEATURE_ABBREV>-<NNN>
    feature: <feature>
    bucket: <bucket>
    posterior: <float>
    support: <int>
    active: true
    info:
      name: <short label>
      author: <your-github-username>
      severity: <info|low|medium|high|critical>
      description: |
        <1–3 sentences: what traffic this matches and why it is agent-indicative>
      impact: |
        <1–2 sentences: what the client is likely doing>
      tags: [<tag1>, <tag2>]
      reference:
        - <url if known>
      metadata:
        verified: "false"
        source: operator
        false_positive_rate: <low|medium|high>
        tool: <tool name if known>

Rules:
- Never fabricate posterior or support — use real observed values.
- active: true only after manual review.
- Strip proposed_at before contributing.
- Place the file in learned/<feature>.yaml in the veilgate-rules repo.
```

Paste this prompt into any LLM with the observed values and it will produce a
ready-to-review YAML entry consistent with the community schema.

## Fields

### Core fields (required / scoring-relevant)

| Field | Type | Purpose |
| --- | --- | --- |
| `id` | string | Optional unique rule ID (e.g. `VG-UA-001`). Recommended for community rules; omitted in miner output. |
| `feature` | string | Feature family: `ua_token`, `path_ngram`, `header_set_id`, `ja4_prefix`, `timing_bucket`, or `method`. |
| `bucket` | string | Concrete feature bucket to match. |
| `posterior` | float | P(agent \| bucket) ∈ [0,1]. From miner output. **Optional** — omit for human-knowledge rules; defaults to `0.99`. |
| `support` | int | Total observations (agent + human). **Optional** — omit for human-knowledge rules; defaults to `10`. |
| `active` | bool | `true` enables the candidate. Community files ship with `true`; miner output ships with `false` pending review. |
| `proposed_at` | string | RFC3339 timestamp written by the miner. Strip before contributing to the community repo. |

### `info` block (optional — not inspected by scoring engine)

| Field | Type | Purpose |
| --- | --- | --- |
| `info.name` | string | Short human-readable label. |
| `info.author` | string | GitHub username or email of the rule author. |
| `info.severity` | string | Risk level: `info`, `low`, `medium`, `high`, `critical`. |
| `info.description` | string | What traffic pattern this detects and why it is agent-indicative. |
| `info.impact` | string | What a matched client is likely attempting. |
| `info.remediation` | string | Tuning advice for the operator. |
| `info.tags` | list | Search/filter labels. No spaces; use hyphens. |
| `info.reference` | list | URLs to threat-intel reports, tool docs, CVEs. |
| `info.metadata.verified` | string | `"true"` if tested against real agent traffic. |
| `info.metadata.source` | string | `"community"`, `"miner"`, or `"operator"`. |
| `info.metadata.false_positive_rate` | string | `"low"`, `"medium"`, or `"high"`. |
| `info.metadata.min_veilgate_version` | string | Earliest compatible release, e.g. `"0.4.0"`. |
| `info.metadata.tool` | string | Tool or framework that generates this bucket value. |

## Where `posterior` and `support` Come From

You never compute or invent these values. The **ML miner produces them automatically** from live traffic. Here are all the ways to read them:

### Source 1 — `learned.yaml` (easiest)

The miner writes `posterior` and `support` directly into `learned.yaml` every hour (configurable). Just open the file:

```bash
cat ~/.veilgate/rules/learned.yaml
```

Output:
```yaml
candidates:
  - feature: ua_token
    bucket: python-requests
    posterior: 0.98
    support: 312
    active: false
    proposed_at: "2026-05-16T10:00:00Z"
```

`posterior` is the Bayesian estimate $P(\text{agent} \mid \text{bucket})$ computed as:

$$\text{posterior} = \frac{\text{agentCount} + 1}{\text{agentCount} + \text{humanCount} + 2}$$

The `+1` / `+2` are Beta(1,1) prior smoothing terms. `support` = `agentCount + humanCount`.

### Source 2 — SQLite `rule_candidates` table (most detail)

The miner also mirrors every candidate into the event store so the values survive even if `learned.yaml` is deleted:

```bash
sqlite3 ~/.veilgate/events.db \
  'SELECT feature, bucket, round(posterior,4) AS p, support, active
     FROM rule_candidates
     ORDER BY posterior DESC
     LIMIT 20'
```

```
feature     bucket                  p       support  active
----------  ----------------------  ------  -------  ------
ua_token    python-requests         0.9823  312      0
ua_token    python-httpx/0.27       0.9701  188      0
path_ngram  .git/config             0.9988   47      1
ja4_prefix  t13d1516h2_             0.9500   89      0
```

### Source 3 — Prometheus metrics (real-time, no disk access)

```bash
curl -s http://localhost:9090/metrics | grep veilgate_miner_candidates_total
```

This gives the total number of candidates above threshold — useful for CI health checks but not the per-bucket values.

### Source 4 — `go run ./cmd/mlsmoke` (offline validation)

Runs the production Bayes + miner stack against a scripted agent/human traffic mix and prints `learned.yaml`. Use it to test rule thresholds before touching a live deployment:

```bash
go run ./cmd/mlsmoke
```

---

### Timeline to get useful values

The miner fires once per `interval_minutes` (default 60) and only surfaces a bucket once it passes both `min_support` and `min_posterior` thresholds (defaults: 200 and 0.90):

| Traffic volume | Time to first candidate |
| --- | --- |
| 100 req/s | a few hours |
| 10 req/s | ~1 day |
| 1 req/s | ~1 week |
| < 1 req/s | lower `min_support` in `ml.yaml`, or never |

Once a candidate appears in `learned.yaml` with values you trust — high `posterior` (≥ 0.95) and meaningful `support` (≥ 30 after you've reviewed the traffic sample) — copy those exact numbers into your community rule. **Do not guess or round them.**



When `active: true`, a candidate is converted to synthetic Bayes counts at startup:

```
agentCount = round(posterior × support)
humanCount = support − agentCount
```

These are injected via `Bayes.Seed(feature, bucket, agentCount, humanCount)` which
calls `Scorer.SeedFromLearned(candidates)`.

`posterior` and `support` are **optional**. The seeding rules are:

| `posterior` | `support` | Rule type | Behaviour |
| --- | --- | --- | --- |
| `0.97` | `312` | Miner output | Normal: 303 agent + 9 human synthetic observations |
| `0.95` | *(omitted)* | Operator-specified confidence | Default support=10: 10 agent + 0 human |
| *(omitted)* | *(omitted)* | Human-knowledge / tool fingerprint | Defaults: posterior=0.99, support=10 → 10 agent + 0 human |
| *(omitted)* | `50` | Invalid — posterior required to compute ratio | Skipped |

A human-knowledge rule like `bucket: nuclei/3, active: true` with no numbers is
treated as "known bad, high confidence" and contributes a small but firm agent prior.
This is intentionally conservative — it avoids drowning out live traffic observations
while still biasing the classifier correctly from day one.

## Code Path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go) — `LoadLearned`, `loadLearnedDir`
- [`internal/ml/bayes.go`](../../../internal/ml/bayes.go) — `Bayes.Seed`
- [`internal/ml/scorer.go`](../../../internal/ml/scorer.go) — `Scorer.SeedFromLearned`
- [`internal/ml/miner.go`](../../../internal/ml/miner.go) — miner writes `learned.yaml`
- [`internal/rules/watcher.go`](../../../internal/rules/watcher.go) — `Watcher.AddSubdir` watches `learned/`
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) — startup seeding and watcher registration
- [`cmd/veilgate/update_rules.go`](../../../cmd/veilgate/update_rules.go) — ZIP extraction preserves `learned/` subdir

## Operational Notes

- The miner writes `learned.yaml` each tick. Do not hand-edit the full `candidates:` list; flip `active: true` on individual entries.
- Files in `learned/` are **hot-reloaded**: any `.yaml` change fires the `learned.yaml` watcher handler, which reseeds the classifier.
- The `learned/` subdirectory is also watched at startup if it already exists. If `update-rules` creates it after startup, restart veilgate once.
- Seeding is **additive**: existing runtime observations are not overwritten. Community priors blend with locally observed traffic.
- Strip `proposed_at` timestamps before contributing — they carry no value for downstream operators.

### Filesystem permissions

The miner writes `learned.yaml` by creating a `.tmp` file in `rules_dir` and
atomically renaming it. The process user must have **write permission** on the
rules directory.

**Linux (systemd):** The `veilgate` service user must own or have write access
to the `rules_dir`. With the packaged config, `~/.veilgate/rules` expands
under the service user's home directory, so install community rules there and
keep the directory writable by `veilgate`:

```bash
sudo -u veilgate veilgate update-rules --dir ~veilgate/.veilgate/rules
sudo chown -R veilgate:veilgate ~veilgate/.veilgate/rules
```

**Docker:** Mount the rules directory **without** `:ro`. The container runs as
`nonroot` (uid 65532); a read-only mount causes every miner tick to log:

```
WRN miner tick error="miner: write learned.yaml: open .../learned.yaml.tmp: read-only file system"
```

Correct mount — writable, with SELinux relabeling on RHEL/Fedora hosts:

```bash
-v ~/.veilgate/rules:/home/nonroot/.veilgate/rules:z
```

Incorrect mount — read-only, miner silently disabled:

```bash
-v ~/.veilgate/rules:/home/nonroot/.veilgate/rules:ro,z   # ❌
```

See [Deployment — Docker](../../deployment/README.md#docker--container) for the
full volume mount table.

## Sharing with the Community

Operators can contribute high-confidence, activated candidates back to the
community rules repository at
[github.com/C0oki3s/veilgate-rules](https://github.com/C0oki3s/veilgate-rules).
This lets patterns discovered on one deployment benefit every operator running
`veilgate update-rules`.

**Before sharing:**

1. Remove or anonymize any bucket values that may identify your application,
   internal paths, or user patterns.
2. Keep only entries with `active: true` and high `posterior` (≥ 0.95) and
   meaningful `support` (≥ 30).
3. Strip `proposed_at` timestamps.
4. Place entries in the appropriate feature-family file under `learned/`.

**Minimal shareable entry:**

```yaml
candidates:
  - feature: ua_token
    bucket: python-httpx/0.27
    posterior: 0.97
    support: 60
    active: true
```

**Contribution workflow:**

```bash
# 1. Export activated, high-confidence candidates
grep -A6 'active: true' ~/.veilgate/rules/learned.yaml \
  | grep -v proposed_at > /tmp/contrib-ua_token.yaml

# 2. Fork C0oki3s/veilgate-rules
# 3. Place entries in learned/<feature>.yaml
# 4. Open a PR describing the traffic pattern observed
```

Community-sourced entries are reviewed for quality and privacy before merge.
Once merged they are included in the next release and picked up automatically:

```bash
veilgate update-rules
```

See [Community Rules — Contributor Guide](../../community-rules-README.md) for
the full contribution and review process.

## Validation

```bash
# Check miner output
sed -n '1,40p' ~/.veilgate/rules/learned.yaml

# List community rule files
ls ~/.veilgate/rules/learned/

# Count active candidates across all sources
grep -c 'active: true' ~/.veilgate/rules/learned.yaml \
  ~/.veilgate/rules/learned/*.yaml 2>/dev/null

# Check seeding at startup
veilgate -config configs/veilgate.yaml 2>&1 | grep -E 'seeded|learned'

curl -sS http://127.0.0.1:9090/metrics | grep veilgate_miner_candidates_total
```

## Related

- [`rules/ml.yaml`](ml.md)
- [Promote learned rules](../../how-to/promote-learned-rules.md)
- [Install community rules](../../how-to/install-community-rules.md)
- [Community Rules — Contributor Guide](../../community-rules-README.md)
- [Module veilgate_ml](../../modules/veilgate_ml.md)

The `learned.yaml` file stores candidate rules proposed by the ML miner. The
miner writes candidates when support and posterior thresholds from
`rules/ml.yaml` are met. Operators review candidates and promote one by setting
`active: true`.

This file is miner-managed. Do not rewrite the whole `candidates:` list by
hand; review and activate individual entries.

## Example

```yaml
candidates:
  - feature: ua_token
    bucket: python-requests
    posterior: 0.98
    support: 47
    active: false
    proposed_at: "2026-05-16T10:00:00Z"
```

## Fields

| Field | Type | Purpose |
| --- | --- | --- |
| `feature` | string | Feature family, such as `ua_token`, `path_ngram`, `header_set_id`, `ja4_prefix`, `timing_bucket`, or `method`. |
| `bucket` | string | Concrete feature bucket proposed by the miner. |
| `posterior` | float | Estimated probability that the bucket belongs to agent traffic. |
| `support` | int | Number of observations supporting the candidate. |
| `active` | bool | Enables the candidate after operator review. |
| `proposed_at` | string | Optional timestamp written by the miner. |

## Code Path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/ml/miner.go`](../../../internal/ml/miner.go)
- [`internal/persist/store.go`](../../../internal/persist/store.go)

## Operational Notes

- Treat candidates as suggestions, not automatic policy.
- Review support, posterior, and examples before setting `active: true`.
- Learned candidates can reveal traffic patterns. Keep this file private.
- The miner may also mirror candidates into SQLite persistence when enabled.

## Sharing with the Community

Operators can contribute high-confidence, activated candidates back to the
community rules repository at
[github.com/C0oki3s/veilgate-rules](https://github.com/C0oki3s/veilgate-rules).
This lets patterns discovered on one deployment benefit every operator running
`veilgate update-rules`.

**Before sharing:**

1. Remove or anonymize any bucket values that may identify your application,
   internal paths, or user patterns.
2. Keep only entries with `active: true` and high `posterior` (≥ 0.95) and
   meaningful `support` (≥ 30).
3. Strip `proposed_at` timestamps — they carry no value for downstream operators.

**Minimal shareable entry:**

```yaml
candidates:
  - feature: ua_token
    bucket: python-httpx/0.27
    posterior: 0.97
    support: 60
    active: true
```

**Contribution workflow:**

```bash
# 1. Export activated, high-confidence candidates
grep -A6 'active: true' ~/.veilgate/rules/learned.yaml \
  | grep -v proposed_at > /tmp/contrib-learned.yaml

# 2. Fork and open a PR to C0oki3s/veilgate-rules
#    Place the entries in learned.yaml (or a named fragment in learned/)
#    with a brief comment describing the observed traffic pattern.
```

Community-sourced `learned.yaml` entries are reviewed for quality and privacy
before merge. Once merged, they are included in the next release and picked up
automatically by:

```bash
veilgate update-rules
```

See [Community Rules — Contributor Guide](../../community-rules-README.md) for
the full contribution and review process.

## Validation

```bash
sed -n '1,40p' ~/.veilgate/rules/learned.yaml
curl -sS http://127.0.0.1:9090/metrics | grep veilgate_miner_candidates_total
```

## Related

- [`rules/ml.yaml`](ml.md)
- [Promote learned rules](../../how-to/promote-learned-rules.md)
- [Install community rules](../../how-to/install-community-rules.md)
- [Community Rules — Contributor Guide](../../community-rules-README.md)
- [Module veilgate_ml](../../modules/veilgate_ml.md)
