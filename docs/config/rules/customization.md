# Rule Customization Guide

The `veilgate_rules_customization` guide explains how to customize VeilGate rule
files safely. It follows the documentation pattern from
`DOCSskill.md`: directive-style fields, code paths, operational notes, and
validation commands.

Rules are security policy. They decide what scores, what gets challenged, what
gets tarpitted, what fake content is served, what TLS fingerprints mean, and
what the dashboard shows.

Repository: <https://github.com/C0oki3s/veilgate>

## Example Configuration

```yaml
listen: ":8080"
upstream: "http://localhost:3000"
mode: "observe"
rules_dir: "~/.veilgate/rules"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70

metrics:
  listen: "127.0.0.1:9090"
```

## Rule Loading Model

Syntax:  `rules_dir: "<directory>"`  
Default: empty, use embedded defaults  
Context: top-level `veilgate.yaml`

When `rules_dir` is empty, VeilGate uses rule files embedded into the binary.
When `rules_dir` is set, each supported loader reads
`<rules_dir>/<file>.yaml`. If that file is missing, that individual file falls
back to the embedded default.

The override is per-file replacement, not merge. If you provide
`rules/detector.yaml`, that file must contain every detector section you want
active. Empty lists are valid and mean "no entries".

### Code path

- [`internal/rules/loader.go`](../../../internal/rules/loader.go) loads detector,
  TLS fingerprints, and payload rules.
- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
  loads templates, fake data, vulnerabilities, injection strategy, challenge,
  ML, learned rules, and dashboard rules.
- [`internal/rules/watcher.go`](../../../internal/rules/watcher.go) implements
  fsnotify-based reload and `Holder[T]` atomic swaps.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) wires loaders and reload
  callbacks into runtime components.

### Operational notes

- Keep `rules/` in version control.
- Review rule changes as security changes.
- Start in `mode: "observe"` before enforcing new scores.
- Keep metrics and persistence private while testing rule changes.
- Use small, targeted changes and validate one behavior at a time.

## Hot Reload Matrix

| Rule file | Hot reload | Code callback | Notes |
| --- | --- | --- | --- |
| `detector.yaml` | yes | `scorer.SetRules()` | Affects signal weights and matchers. |
| `ip_reputation.yaml` | yes | `scorer.SetIPReputation()` | Affects CIDRs, fleet rotation, UA rotation. |
| `templates.yaml` | yes | `templatesHolder.Store()` | Affects future tarpit renders. |
| `fake_data.yaml` | yes | `fakeDataHolder.Store()` | New profiles use new pools; existing profiles keep selected values. |
| `vulnerabilities.yaml` | yes | `vulnHolder.Store()` | Affects tarpit route helpers and SQLi route matching. |
| `injection_strategy.yaml` | yes | `strategyHolder.Store()` | Affects tarpit route-to-template selection. |
| `challenge.yaml` | yes | `challengeHolder.Store()` | Affects challenge page, cookie, token, SPA behavior. |
| `ml.yaml` | yes | `mlHolder.Store()` | Affects ML scoring, redaction, miner settings. |
| `dashboard.yaml` | yes | `dashboardHolder.Store()` | Affects dashboard layout and charts. |
| `tls_fingerprints.yaml` | yes, when TLS DB exists | `tlsDB.Apply()` | Registered only when TLS fingerprinting is enabled. |
| `payloads.yaml` | no current watcher registration | loaded by `payloads.NewLibraryFromDir()` | Restart required for payload library changes. |
| `learned.yaml` | miner-managed | `ml.Miner` reads/writes | Active flags are picked up by miner workflow, not a generic watcher. |

## Rule File Reference

| File | Purpose | Main package |
| --- | --- | --- |
| `detector.yaml` | Rule-based detector signal weights and matchers. | `internal/detector`, `internal/rules` |
| `ip_reputation.yaml` | CIDR categories, public/private IP classification, fleet rotation, UA rotation. | `internal/rules`, `internal/detector/fleet.go` |
| `tls_fingerprints.yaml` | JA3/JA4 labels and categories. | `internal/tlsfp`, `internal/detector/tls.go` |
| `templates.yaml` | Tarpit response templates. | `internal/tarpit/renderer.go` |
| `injection_strategy.yaml` | Tarpit route matching and payload injection strategy. | `internal/tarpit/handler.go`, `internal/payloads` |
| `payloads.yaml` | Decoy and prompt-injection payload library. | `internal/payloads` |
| `fake_data.yaml` | Fake profile pools used by the tarpit. | `internal/tarpit/profile.go` |
| `vulnerabilities.yaml` | Tarpit SQLi and fake vulnerable path lists. | `internal/tarpit/handler.go` |
| `challenge.yaml` | Challenge HTML, cookie, token, verify endpoint, SPA response. | `internal/challenge` |
| `ml.yaml` | Online ML, path redaction, miner settings. | `internal/ml` |
| `dashboard.yaml` | Built-in dashboard layout and Prometheus panels. | `internal/telemetry/dashboard.go` |
| `learned.yaml` | Miner candidates and operator-promoted learned rules. | `internal/ml`, `internal/rules` |

## Customization Workflow

1. Copy the default rules into a controlled directory.
2. Set `rules_dir` to that directory.
3. Start VeilGate in `observe` mode.
4. Generate normal traffic and known scanner-shaped traffic.
5. Review metrics:
   - `veilgate_requests_total`;
   - `veilgate_signal_hits_total`;
   - `veilgate_score`;
   - `veilgate_score_by_decision`.
6. Edit one rule file at a time.
7. Wait for hot reload or restart when required.
8. Re-run validation traffic.
9. Commit the rule change with the observed effect.
10. Move to `challenge`, then `auto` or `tarpit`, only after false positives
    are understood.

Validation commands:

```bash
curl http://localhost:8080/
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl "http://localhost:8080/search?q=' union select"
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
curl http://127.0.0.1:9090/metrics | grep veilgate_score
```

## `rules/detector.yaml`

Syntax:  detector rule file  
Default: embedded detector rules  
Context: `rules_dir`

Controls deterministic detector signals: suspicious User-Agents, sparse browser
headers, empty User-Agent, toolchain sequencing, timing regularity, path
bruteforce, wordlist paths, injection markers, and OOB callback markers.

### Customizable sections

| Section | What to customize | Risk |
| --- | --- | --- |
| `suspicious_user_agents` | Add scanner or internal automation UA substrings and points. | Broad substrings can hit real browsers or app clients. |
| `browser_headers` | Adjust expected browser headers and missing-header tiers. | CDNs and mobile clients may strip or alter headers. |
| `empty_user_agent` | Tune score for no UA. | Low risk, but some health checks may omit UA. |
| `toolchain` | Add recon/probe/exploit path and query markers. | Overbroad markers can score normal API paths. |
| `timing` | Tune mean request gap and coefficient of variation thresholds. | Automated but legitimate jobs may be regular. |
| `path_bruteforce` | Tune distinct path thresholds and points. | Low-traffic APIs may need lower thresholds; large apps may need higher. |
| `wordlist_paths` | Add known scanner paths never served by your app. | Do not add real app routes. |
| `injection_markers` | Add payload substrings and scanned header names. | Header scanning can catch test payloads from security tools. |
| `oob_interaction` | Add callback domains used by OOB testing tools. | Low risk; OOB markers are high-confidence. |

### Example: add an internal scanner UA

```yaml
suspicious_user_agents:
  points: 20
  substrings:
    - company-redteam-scanner
    - python-requests
    - nuclei
```

Use a lower score for allowed internal test tooling if you want it visible but
not immediately tarpitted.

### Code path

- [`internal/rules/loader.go`](../../../internal/rules/loader.go) parses the file.
- [`internal/detector/scorer.go`](../../../internal/detector/scorer.go) consumes the
  parsed rules.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads the file with
  `scorer.SetRules()`.

### Validation

```bash
curl -A "company-redteam-scanner" http://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep suspicious_ua
```

## `rules/ip_reputation.yaml`

Syntax:  IP reputation and rotation rule file  
Default: embedded IP reputation rules  
Context: `rules_dir`

Controls CIDR category scoring, public/private classification, fleet rotation,
and UA rotation.

### Customizable sections

| Section | What to customize |
| --- | --- |
| `categories` | Add `tor_exit`, `anonymizer`, `cloud`, VPN, or customer-specific CIDRs. |
| `private_cidrs` | Define which ranges are not considered public internet clients. |
| `fleet_rotation` | Tune number of distinct IPs sharing one behavior fingerprint. |
| `ua_rotation` | Tune how many distinct UAs from one client should score. |

### Example: add a proxy provider range

```yaml
categories:
  - name: anonymizer
    points: 30
    cidrs:
      - 203.0.113.0/24
```

Put stronger, narrower categories before broad cloud ranges. First matching
category wins.

### Code path

- [`internal/rules/ip_reputation.go`](../../../internal/rules/ip_reputation.go)
  parses categories and rotation settings.
- [`internal/detector/scorer.go`](../../../internal/detector/scorer.go) scores IP
  reputation and UA rotation.
- [`internal/detector/fleet.go`](../../../internal/detector/fleet.go) tracks shared
  behavior fingerprints across IPs.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads with
  `scorer.SetIPReputation()`.

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_ip_reputation_hits_total
curl http://127.0.0.1:9090/metrics | grep veilgate_fleet_rotation_fires_total
```

## `rules/tls_fingerprints.yaml`

Syntax:  TLS fingerprint database  
Default: embedded TLS fingerprints  
Context: `rules_dir`

Maps JA4 exact values, JA4 prefixes, and JA3 exact hashes to a label,
category, and confidence. Categories influence detector signals.

### Customizable sections

| Section | Purpose |
| --- | --- |
| `ja4_exact` | High-confidence exact JA4 matches. |
| `ja4_prefix` | Version-tolerant browser or client-family matches. |
| `ja3_exact` | Legacy JA3 exact matches. |

### Example: add a known internal synthetic monitor

```yaml
ja4_exact:
  - hash: t13d1516h2_example_example
    label: internal-synthetic-monitor
    category: browser
    confidence: 80
```

### Code path

- [`internal/rules/loader.go`](../../../internal/rules/loader.go) parses the file.
- [`internal/tlsfp/database.go`](../../../internal/tlsfp/database.go) applies entries.
- [`internal/detector/tls.go`](../../../internal/detector/tls.go) scores classifier
  results.

### Operational notes

- TLS fingerprinting requires `tls.enabled: true`.
- If TLS is terminated before VeilGate, these rules will not affect requests.
- Treat `unknown` as a weak signal, not proof of automation.

### Validation

```bash
curl -k https://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep tls
```

## HTTP/2 fingerprint customization

Syntax:  code-wired HTTP/2 SETTINGS classifier  
Default: empty exact-match database  
Context: runtime

HTTP/2 fingerprinting is implemented by `internal/h2fp`, but the current
repository does not include a `rules/h2_fingerprints.yaml` file, loader, or
watcher registration. Do not add an operator rule file for HTTP/2 fingerprints
until the codebase also adds a loader in `internal/rules` and a watcher callback
in `cmd/veilgate/main.go`.

Current customization options:

| Option | Behavior |
| --- | --- |
| Tune detector thresholds | Changes how much `h2_*` points affect final challenge/tarpit decisions. |
| Tune neighboring protocol/header rules | Adjusts TLS, header, and browser-consistency evidence around HTTP/2 signals. |
| Apply entries in code | `h2fp.Database.Apply()` can install exact or pseudo-header matches for custom builds. |

### Code path

- [`internal/h2fp/h2fp.go`](../../../internal/h2fp/h2fp.go)
- [`internal/detector/scorer.go`](../../../internal/detector/scorer.go)
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go)

### Validation

```bash
curl -k --http2 https://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep h2
```

Related: [Module veilgate_http2_fingerprinting](../../modules/veilgate_http2_fingerprinting.md).

## `rules/templates.yaml`

Syntax:  tarpit template map  
Default: embedded templates  
Context: `rules_dir`

Defines named fake responses used by the tarpit. Each template can specify
status, content type, headers, and body. Bodies and header values are rendered
with Go templates.

### Customizable fields

| Field | Meaning |
| --- | --- |
| `status` | HTTP status returned by the tarpit response. |
| `content_type` | Response `Content-Type`. |
| `headers` | Additional response headers, templated. |
| `body` | Templated response body. |

### Available template data

Common values include `.Company`, `.Version`, `.Stack`, `.AdminUser`,
`.AdminPass`, `.Seed`, `.Visits`, `.Path`, `.Query`, `.TicketID`, and `.Slug`.

### Code path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
  parses templates.
- [`internal/tarpit/renderer.go`](../../../internal/tarpit/renderer.go) renders
  templates and helper functions.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads templates.

### Operational notes

- Never put real secrets in templates.
- Do not make fake content too close to production internals.
- Changes affect future renders after reload.

### Validation

```bash
curl -A "sqlmap/1.7" http://localhost:8080/.git/config
```

## `rules/injection_strategy.yaml`

Syntax:  tarpit route and injector strategy  
Default: embedded injection strategy  
Context: `rules_dir`

Controls which tarpit template is selected for a path and how many payloads
are injected into rendered content.

### Customizable sections

| Section | Meaning |
| --- | --- |
| `routes` | Ordered route table. First match wins. |
| `injector.max_payloads_per_response` | Maximum payloads inserted into one response. |
| `injector.visit_bucket_rotation` | Whether visit count influences payload choice. |
| `injector.style_weights` | Weights by content type and payload style. |
| `injector.category_order` | Preferred payload categories. |

### Route match types

| Match | Behavior |
| --- | --- |
| `exact` | Path equals one of `values`. |
| `prefix` | Path starts with one of `values`. |
| `contains` | Path contains one of `values`. |
| `regex` | Go regexp match. |
| `sqli` | Path or query contains SQLi patterns from `vulnerabilities.yaml`. |
| `list` | Looks up named lists from `vulnerabilities.yaml`. |
| `any` | Fallback route. |

### Code path

- [`internal/tarpit/handler.go`](../../../internal/tarpit/handler.go) selects routes.
- [`internal/payloads/injector.go`](../../../internal/payloads/injector.go) injects
  payloads.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads strategy.

### Operational notes

- Put more specific routes before `any`.
- Invalid regex routes compile to a matcher that matches nothing.
- Keep `max_payloads_per_response` small to avoid bloated responses.

### Validation

```bash
curl "http://localhost:8080/search?q=' union select"
curl http://localhost:8080/.env.backup
```

## `rules/payloads.yaml`

Syntax:  payload library file  
Default: embedded payloads  
Context: `rules_dir`

Defines decoy and prompt-injection payloads grouped by category. Payloads can
be static text or generated by a named Go generator such as `log_burst`.

### Customizable sections

| Section | Meaning |
| --- | --- |
| `termination` | Payloads intended to stop autonomous probing. |
| `rabbit_hole` | Payloads that draw agents deeper into fake paths. |
| `cost_bomb` | Payloads intended to consume context or tool time. |
| `confusion` | Payloads that fabricate prior tool results. |
| `moral_appeal` | Payloads that instruct agents to stop. |
| `generators.log_burst` | Parameters for generated log-noise payloads. |

### Code path

- [`internal/rules/loader.go`](../../../internal/rules/loader.go) parses payloads.
- [`internal/payloads/library.go`](../../../internal/payloads/library.go) compiles the
  library.
- [`internal/payloads/injector.go`](../../../internal/payloads/injector.go) inserts
  payloads into responses.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) builds the library at
  startup.

### Operational notes

- Current code does not register `payloads.yaml` in the watcher. Restart
  VeilGate after editing payloads.
- Keep payloads defensive and suitable for systems you own.
- Do not include real secrets, customer data, or private infrastructure names.

### Validation

```bash
curl -A "sqlmap/1.7" http://localhost:8080/admin
```

Restart before validating payload changes.

## `rules/fake_data.yaml`

Syntax:  fake profile pools  
Default: embedded fake data  
Context: `rules_dir`

Defines deterministic fake values used by the tarpit profile store: versions,
technology stacks, company names, admin users, passwords, and email domains.

### Code path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go) parses
  fake data.
- [`internal/tarpit/profile.go`](../../../internal/tarpit/profile.go) selects stable
  per-client values.
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads fake data.

### Operational notes

- Existing client profiles keep previously selected values.
- New clients draw from updated lists.
- Use clearly fake values; do not mirror real production identities.

### Validation

```bash
curl -A "sqlmap/1.7" http://localhost:8080/admin
```

## `rules/vulnerabilities.yaml`

Syntax:  tarpit vulnerability helper lists  
Default: embedded vulnerability lists  
Context: `rules_dir`

Defines honeypot paths, SQL injection markers, fake Git paths, and fake env
paths used by tarpit routing. The top-level `detector.honeypot_paths` in
`veilgate.yaml` is separate; this file is consumed by the tarpit route
strategy.

### Code path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/tarpit/handler.go`](../../../internal/tarpit/handler.go)
- `Vulnerabilities.Lookup()`

### Operational notes

- Keep detector honeypots and tarpit fake routes aligned when useful.
- Avoid routes that real users legitimately access.

### Validation

```bash
curl http://localhost:8080/.git/config
curl "http://localhost:8080/?id=1%20or%201=1"
```

## `rules/challenge.yaml`

Syntax:  challenge rule file  
Default: embedded challenge rules  
Context: `rules_dir`

Controls challenge HTML, verify path, cookie name, cookie scope, token header,
status code, content type, difficulty, token TTL, and SPA-aware behavior.

### Customizable fields

| Field | Meaning |
| --- | --- |
| `difficulty` | Proof-of-work leading-zero target. |
| `token_ttl_minutes` | Pass-token lifetime. |
| `cookie_name` | Challenge cookie name. |
| `status_code` | HTML challenge response status. |
| `content_type` | HTML challenge content type. |
| `verify_path` | Proof submission endpoint. |
| `cookie_domain` | Optional parent-domain cookie scope. |
| `cookie_same_site` | `strict`, `lax`, or `none`. |
| `token_header_name` | Header transport for SPA/API clients. |
| `spa_aware_response` | Return JSON 401 for fetch/XHR requests. |
| `html_template` | Challenge page template. |

### Code path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/challenge/challenge.go`](../../../internal/challenge/challenge.go)
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads challenge rules.

### Operational notes

- Set `VEILGATE_SECRET` before enforcing challenge or tarpit modes.
- Do not remove signed challenge metadata from the HTML template.
- Keep `verify_path` away from upstream routes.

### Validation

```bash
curl -i -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl -i -X POST http://localhost:8080/__veilgate/verify
```

## `rules/ml.yaml`

Syntax:  online ML and miner config  
Default: embedded ML rules  
Context: `rules_dir`

Controls optional ML scoring, Naive Bayes settings, Isolation Forest settings,
miner output, and path redaction.

### Customizable sections

| Section | Meaning |
| --- | --- |
| `enabled` | Enables `ml_agent_score`. |
| `score_max_points` | Maximum points ML can add. |
| `alpha` | Blend of Bayes and anomaly score. |
| `burn_in_events` | Minimum observed examples before scoring. |
| `min_confidence_to_fire` | Confidence floor before adding points. |
| `bayes` | N-gram and timing bucket behavior. |
| `iso_forest` | Tree count, sample size, refit cadence. |
| `miner` | Learned-rule candidate generation. |
| `path_redaction` | Redacts high-entropy path segments before feature storage. |

### Code path

- [`internal/ml/features.go`](../../../internal/ml/features.go)
- [`internal/ml/scorer.go`](../../../internal/ml/scorer.go)
- [`internal/ml/miner.go`](../../../internal/ml/miner.go)
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads ML rules and
  reapplies path redaction.

### Operational notes

- ML is additive, not the primary enforcement engine.
- Treat miner output as suggestions.
- Review `learned.yaml` before setting candidates active.
- Keep path redaction enabled in production.

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_ml
```

## `rules/dashboard.yaml`

Syntax:  dashboard configuration file  
Default: embedded dashboard rules  
Context: `rules_dir`

Controls the built-in dashboard: refresh cadence, stat cards, metric filters,
rotation panels, cardinality metrics, quick-search tags, graph definitions,
colors, and score display thresholds.

### Code path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/telemetry/dashboard.go`](../../../internal/telemetry/dashboard.go)
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go) hot-reloads dashboard rules.

### Operational notes

- Keep the dashboard listener private.
- Use a local Chart.js copy for air-gapped deployments.
- Dashboard rule mistakes affect visibility, not proxy enforcement.

### Validation

```bash
curl -i http://127.0.0.1:9090/
```

## `rules/learned.yaml`

Syntax:  learned-rule candidate file  
Default: embedded empty candidate list  
Context: miner workflow

Stores candidate feature buckets emitted by the ML miner. Operators promote a
candidate by setting `active: true`. Active flags are also mirrored into the
SQLite `rule_candidates` table when persistence is enabled.

### Code path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/ml/miner.go`](../../../internal/ml/miner.go)
- [`internal/persist/store.go`](../../../internal/persist/store.go)

### Operational notes

- Do not auto-promote unless you have a review process.
- Check support and posterior before activation.
- Learned candidates may expose path shapes or header patterns; treat the file
  as sensitive operational data.

### Validation

```bash
sed -n '1,40p' ~/.veilgate/rules/learned.yaml
curl http://127.0.0.1:9090/metrics | grep veilgate_miner_candidates_total
```

## Troubleshooting

### Rule edit did not take effect

Check:

- `rules_dir` points at the edited directory.
- The edited file is in the hot reload matrix.
- YAML parses successfully.
- For `payloads.yaml`, restart the process.
- For `tls_fingerprints.yaml`, TLS fingerprinting is enabled.

### Normal browser traffic is challenged

Check:

- `veilgate_signal_hits_total` by signal.
- `browser_headers` and `sec_fetch` expectations.
- CDN or proxy header stripping.
- `trusted_proxies`.
- accidental real paths in `honeypot_paths` or `wordlist_paths`.

### Tarpit response looks wrong

Check:

- `injection_strategy.yaml` route order.
- template name exists in `templates.yaml`;
- `vulnerabilities.yaml` list names match route `values`;
- payload changes were followed by restart.

## Related

- [Module veilgate_rules](../../modules/veilgate_rules.md)
- [How VeilGate Processes a Request](../../architecture/request-processing.md)
- [Configuration reference](../README.md)
- [Promote learned rules](../../how-to/promote-learned-rules.md)
