# VeilGate Rule Authoring Skill

Use this skill whenever you are writing, reviewing, or generating a VeilGate
learned-rule YAML entry. It defines the strict schema, field semantics, quality
gates, and the step-by-step authoring workflow for both **human authors** and
**LLMs** producing rules from tool names, CVE identifiers, fingerprint research,
or observed traffic data.

---

## What a VeilGate Learned Rule Is

A learned rule is a YAML entry that tells the Bayes classifier: *"when a request
contains this (feature, bucket) pair, treat it as strong evidence of automated
agent traffic."*

Rules live in `<rules_dir>/learned/<feature>.yaml` (community rules) or
`<rules_dir>/learned.yaml` (miner output). The same YAML schema covers both.

Rules are **not** signatures. They are **probabilistic priors**: they shift the
Bayes classifier's opinion, they do not hard-block traffic. A single rule
contributes a small number of synthetic observations. The final tarpitting or
challenge decision always considers the full signal composite score.

---

## Strict Schema

Every rule entry **must** conform to this schema. Fields marked **required** must
be present. Fields marked **optional** may be omitted.

```yaml
candidates:
  - id: <string>          # REQUIRED for community rules. Format: VG-<FEATURE>-<NNN>.
                          # E.g. VG-UA-042, VG-JA4-007, VG-PATH-019.
                          # Omit in miner-generated output.

    feature: <string>     # REQUIRED. One of the six feature families (see below).

    bucket: <string>      # REQUIRED. The exact string the feature extractor
                          # produces for this traffic pattern. Case-sensitive.
                          # Never a regex — exact match only.

    posterior: <float>    # OPTIONAL. P(agent | bucket) ∈ [0.0, 1.0].
                          # Provide when you have real observed data (miner output).
                          # Omit for human-knowledge / tool-fingerprint rules.
                          # When omitted: seeded at 0.99.

    support: <int>        # OPTIONAL. Total observations (agent + human count).
                          # Provide when you have real observed data.
                          # Omit for human-knowledge rules.
                          # When omitted: seeded at 10.

    active: <bool>        # REQUIRED. true = rule is active. false = pending review.
                          # Community rules ship with true.
                          # Miner output ships with false.

    proposed_at: <string> # OPTIONAL. RFC3339 timestamp. Written by miner only.
                          # STRIP THIS FIELD before contributing to the community repo.

    info:                 # OPTIONAL block. Never read by the scoring engine.
                          # Required for community rules; encouraged for operator rules.

      name: <string>      # REQUIRED inside info. Short label, ≤ 80 chars.
                          # E.g. "Nuclei scanner default User-Agent"

      author: <string>    # REQUIRED inside info. GitHub username or email.

      severity: <string>  # REQUIRED inside info.
                          # One of: info | low | medium | high | critical
                          # (see Severity Guide below)

      description: |      # REQUIRED inside info. 1–4 sentences.
        ...               # What traffic this matches and why it is agent-indicative.
                          # No marketing language. Be precise.

      impact: |           # RECOMMENDED. 1–2 sentences.
        ...               # What a matched client is likely attempting.

      remediation: |      # RECOMMENDED. 1–2 sentences.
        ...               # Tuning advice for the operator.

      tags:               # REQUIRED inside info. At least one tag.
        - <tag>           # Lowercase, hyphen-separated. No spaces.
                          # Include the feature family as a tag.

      reference:          # RECOMMENDED. At least one URL when publicly documented.
        - <url>

      metadata:           # RECOMMENDED.
        verified: "true"  # "true" if tested against real or controlled agent traffic.
                          # "false" if derived from documentation / source code only.
        source: <string>  # "community" | "operator" | "miner"
        false_positive_rate: <string>  # "low" | "medium" | "high"
        tool: <string>    # Name of the tool or library that generates this bucket.
        min_veilgate_version: <string> # Optional. E.g. "0.4.0"
```

---

## Feature Families

You must use exactly one of these six values for `feature`:

| `feature` | What it matches | How `bucket` is formed |
| --- | --- | --- |
| `ua_token` | Substring of the HTTP `User-Agent` header | Lowercased UA token, e.g. `python-requests`, `nuclei/3`, `go-http-client/1.1` |
| `path_ngram` | 1..n-gram of URL path segments split on `/` | Joined with `/`, e.g. `.git/config`, `admin/users`, `phpmyadmin` |
| `ja4_prefix` | Prefix of a JA4 TLS fingerprint | First 10–14 chars of a JA4 string, e.g. `t13d1516h2_` |
| `header_set_id` | SHA-1 of the sorted set of request header names | 40-char hex string |
| `timing_bucket` | Inter-request gap interval label | One of `first`, `le_<N>`, `gt_<N>` where N is a float |
| `method` | HTTP method anomaly | Uppercase method string, e.g. `TRACE`, `HEAD`, `OPTIONS` |

**How to find the right bucket for a tool:**

- `ua_token`: run the tool against any HTTP server and capture `User-Agent`. Take the
  library name prefix before the first space or `/version` suffix.
- `path_ngram`: run a wordlist against a test server with access logging. The most
  frequent path segments are the buckets.
- `ja4_prefix`: use [https://github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4)
  or Wireshark with the JA4 plugin to capture the fingerprint.
- `header_set_id`: send a request with the target tool and compute
  `sha1(sorted(header_names).join(","))` — or read it from VeilGate's access log when
  `capture.enabled: true`.
- `timing_bucket`: the miner produces these automatically from observed inter-request
  timing distributions. Do not author timing rules by hand unless you have measurements.
- `method`: check the tool's HTTP client behaviour. Most scanners use `GET` exclusively;
  TRACE/HEAD/OPTIONS are fingerprints of reconnaissance or misconfiguration probing.

---

## Severity Guide

| Severity | Posterior range | Example |
| --- | --- | --- |
| `info` | < 0.70 | Unusual header combination seen occasionally in normal traffic |
| `low` | 0.70–0.84 | Scanner UA seen in small share of ambiguous sessions |
| `medium` | 0.85–0.94 | Known automation library; rare in browser traffic |
| `high` | 0.95–0.98 | Strong agent signal with documented false-positive rate < 1% |
| `critical` | ≥ 0.99 or human-knowledge only | Tool UA that no browser ever sends; zero FP in controlled tests |

---

## ID Numbering Convention

```
VG-<FEATURE_ABBREV>-<NNN>
```

| Feature | Abbreviation |
| --- | --- |
| `ua_token` | `UA` |
| `path_ngram` | `PATH` |
| `ja4_prefix` | `JA4` |
| `header_set_id` | `HDR` |
| `timing_bucket` | `TIME` |
| `method` | `MTH` |

Numbers are three-digit zero-padded and assigned sequentially within each feature
file in the community repo. Check the highest existing ID in
`learned/<feature>.yaml` before assigning one.

---

## Authoring Workflow

### Step 1 — Identify the traffic pattern

You need at minimum:

- The **tool name** (e.g. Nuclei, sqlmap, Burp Suite, python-requests).
- A **link** to the tool's documentation or GitHub repo.
- **Which feature family** best captures the pattern (usually `ua_token` for
  libraries, `path_ngram` for wordlist scanners, `ja4_prefix` for TLS clients).
- **The exact bucket string** (see Feature Families section above for how to find it).

### Step 2 — Assess posterior and support

| You have | What to put |
| --- | --- |
| Miner output from real traffic | Copy `posterior` and `support` verbatim from `learned.yaml` or the SQLite query. Do not round. |
| Controlled lab test (tool vs VeilGate test instance) | Run `go run ./cmd/mlsmoke` or capture to SQLite. Use the resulting values. |
| Tool documentation / source code only | **Omit both fields.** VeilGate uses `posterior=0.99, support=10` internally. |
| Intuition / guessing | **Never set posterior and support from a guess.** Omit them instead. |

### Step 3 — Fill the `info` block

Minimum required fields inside `info`:
- `name` — copy from the tool's own documentation.
- `author` — your GitHub username.
- `severity` — use the Severity Guide above.
- `description` — one sentence: what UA / path / fingerprint this is, and which tool
  emits it. One sentence: why no legitimate browser ever produces it.
- `tags` — include the feature name and at least one of: `scanner`, `automation`,
  `llm-agent`, `fuzzer`, `recon`, `exploit`, `fingerprint`.
- `metadata.verified` — set `"true"` only if you have observed the bucket in real
  or controlled traffic.
- `metadata.source` — `"community"` for PRs, `"operator"` for local-only rules.
- `metadata.tool` — the tool name, lowercase.

### Step 4 — Validate the entry

Before opening a PR, confirm:

```bash
# Parse the file — exits 0 if YAML is valid
python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" \
  learned/ua_token.yaml

# Confirm bucket is not already covered
grep -r 'bucket: <your-bucket>' ~/.veilgate/rules/learned/ \
  ~/.veilgate/rules/learned.yaml

# Run the smoke test to confirm the new entry seeds correctly
go run ./cmd/mlsmoke
```

### Step 5 — Place the file

- Put the entry in `learned/<feature>.yaml` in the
  [veilgate-rules](https://github.com/C0oki3s/veilgate-rules) repository.
- Do **not** put community rules in the root `learned.yaml` — that file is
  owned by the miner.
- One PR per feature file. Mix `ua_token` entries in one PR; open a separate PR
  for `ja4_prefix` entries.

---

## LLM Authoring Prompt

When using an LLM to generate a rule, use this exact prompt. Fill in the
bracketed values from your research; the LLM fills the rest.

```
You are a VeilGate rule author. Your job is to write a single YAML rule entry
for the VeilGate learned-rules system. The rule must conform exactly to the
schema in RULE-SKILL.md.

Input facts:
  Tool name: [TOOL NAME]
  Tool URL:  [TOOL GITHUB OR DOCS URL]
  Feature:   [ua_token | path_ngram | ja4_prefix | header_set_id | timing_bucket | method]
  Bucket:    [EXACT BUCKET STRING]
  Posterior: [value from miner, or omit]
  Support:   [value from miner, or omit]

Rules for the LLM:
1. Do not invent posterior or support. If not provided, omit both fields.
2. Set active: true.
3. Do not include proposed_at.
4. Assign the next available ID in format VG-<ABBREV>-<NNN>. Use NNN=001 if unknown.
5. Set metadata.verified to "false" unless explicitly told otherwise.
6. Set metadata.source to "community".
7. Write description in two sentences: (1) what the bucket identifies, (2) why
   no legitimate browser or server produces it.
8. Write impact in one sentence: what a client matching this rule is likely doing.
9. Choose severity from the guide: info/low/medium/high/critical.
10. Include at least one reference URL.

Output: a single YAML candidates entry, nothing else. No prose before or after.
```

**Example invocation — tool name and URL only:**

```
Tool name: Nuclei
Tool URL:  https://github.com/projectdiscovery/nuclei
Feature:   ua_token
Bucket:    nuclei/
```

**Expected LLM output:**

```yaml
- id: VG-UA-001
  feature: ua_token
  bucket: nuclei/
  active: true
  info:
    name: Nuclei vulnerability scanner User-Agent prefix
    author: community
    severity: critical
    description: |
      Default User-Agent prefix emitted by the Nuclei scanner
      (projectdiscovery/nuclei). No web browser, CDN, or legitimate API client
      ever sends a User-Agent beginning with "nuclei/".
    impact: |
      Active vulnerability scanning. The client is likely running a template
      suite; escalate to tarpit immediately.
    tags: [ua_token, scanner, nuclei, projectdiscovery, recon, exploit]
    reference:
      - https://github.com/projectdiscovery/nuclei
    metadata:
      verified: "false"
      source: community
      false_positive_rate: low
      tool: nuclei
```

---

## Quality Gates (PR checklist)

Before merging a community rule, reviewers check:

- [ ] `id` follows `VG-<ABBREV>-<NNN>` and is not already used in the file.
- [ ] `feature` is one of the six valid families.
- [ ] `bucket` is an exact string, not a glob or regex.
- [ ] `posterior` and `support` are either both present (from real data) or both absent.
- [ ] `active: true` is set.
- [ ] `proposed_at` is not present.
- [ ] `info.name`, `info.author`, `info.severity`, `info.description` are present.
- [ ] `info.tags` contains at least one tag.
- [ ] `info.metadata.verified` is set.
- [ ] `info.metadata.source` is `"community"`.
- [ ] No bucket is a broad string that would match legitimate browser traffic
      (e.g. `mozilla`, `chrome`, `safari` are not valid buckets).
- [ ] YAML is valid (`python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))"` passes).
- [ ] File is placed in `learned/<feature>.yaml`, not in `learned.yaml`.

---

## Anti-patterns to Reject

| Anti-pattern | Why | Fix |
| --- | --- | --- |
| `bucket: mozilla` | Matches all desktop browsers | Use a specific library token |
| `posterior: 0.95` with `support: 0` | Support=0 implies no observations | Omit both or provide real support |
| `bucket: /admin` | Path starts with `/`; extractor strips leading slash | Use `admin` |
| `feature: ua_substring` | Invalid family name | Use `ua_token` |
| `proposed_at: "2026-..."` in a PR | Miner-managed field | Strip before contributing |
| `active: false` in a community file | Community rules must ship active | Set `active: true` |
| Regex in `bucket` field | Exact match only; no regex engine | Break into multiple entries |
| `severity: critical` with `posterior < 0.90` | Severity contradicts the data | Lower severity or recheck data |

---