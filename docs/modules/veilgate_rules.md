# Module veilgate_rules

The `veilgate_rules` module documents external YAML rule files. These files
define detector weights, fingerprint classifications, tarpit templates, route
strategy, fake data, payloads, decoy paths, challenge behavior, ML settings,
and dashboard layout.

Rules are loaded from `rules_dir` when configured. **There are no embedded
defaults** — `rules_dir` must be set and point to a populated rules directory.
Use `veilgate update-rules` or `make install` to pull the community rule files
on first install and on every upgrade.

For a step-by-step operator workflow, see the
[Rule Customization Guide](../config/rules/customization.md).

## Example Configuration

```yaml
rules_dir: "~/.veilgate/rules"
```

## Directives

- `rules_dir`

Each rule type is a **directory**, not a single file. Drop additional `.yaml`
files into a subdirectory to extend any list without editing core files.

| Directory | Root config file | Community subdirs |
|---|---|---|
| `detector/` | `config.yaml` | `useragents/`, `paths/`, `attack/`, `tools/` |
| `ip_reputation/` | `config.yaml` | `cloud/`, `vpn/`, `tor/` |
| `payloads/` | `config.yaml` | _(any subdirectory)_ |
| `injection_strategy/` | _(none required)_ | `routes/` |
| `fake_data/` | _(none required)_ | `servers/`, `identities/` |
| `vulnerabilities/` | _(none required)_ | `honeypots/` |
| `tls_fingerprints/` | _(none required)_ | `tools/`, `browsers/` |
| `templates/` | `templates.yaml` _(optional)_ | _(any subdirectory)_ |
| `learned/` | `learned.yaml` _(optional)_ | `attack/`, `tools/`, etc. |

Single-file rules with community subdirectory support:

| File | Subdirectory | Purpose |
|---|---|---|
| `route-manifest.yaml` | `route-manifest/` | Bait endpoints published in `.well-known` and injected by browser/node SDKs as agent breadcrumbs |

Single-file rules (no community subdirectory):

- `challenge.yaml`
- `ml.yaml`
- `dashboard.yaml`

## `rules_dir`

Syntax:  `rules_dir: "<directory>"`  
Default: none — **must be set**  
Context: top-level

Defines the root directory that all rule loaders read from. Each rule type
walks its own subdirectory tree, so operators and the community can drop in
additional `.yaml` files without editing core files.

When `rules_dir` is set the watcher hot-reloads supported files.

### First install

```bash
# Build binary and pull community rules into ~/.veilgate/rules
make install

# Or pull to a custom directory
make update-rules RULES_DIR=/opt/veilgate/rules

# Or run the subcommand directly
./veilgate update-rules --dir ~/.veilgate/rules
./veilgate update-rules --dir ~/.veilgate/rules --version v1.2.3   # pin a release
./veilgate update-rules --list                           # list available releases
```

### Code path

- [`internal/rules/loader.go`](../../internal/rules/loader.go)
- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go)
- [`internal/rules/ip_reputation.go`](../../internal/rules/ip_reputation.go)
- [`internal/rules/watcher.go`](../../internal/rules/watcher.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)
- [`cmd/veilgate/update_rules.go`](../../cmd/veilgate/update_rules.go)

### Operational notes

- Treat rules as security policy — version and review changes.
- Mount read-only in production where possible.
- A bad reload keeps the previous in-memory rules active (parse errors are logged).
- Run `veilgate update-rules` in CI or as a cron job to pick up new community files.

### Validation

```bash
ls -la ~/.veilgate/rules
./veilgate update-rules --list
```

## Rule Directory Reference

| Directory | Purpose | Code area |
|---|---|---|
| `detector/` | Signal weights and matchers. `config.yaml` sets scalars; list files in subdirs append. | `internal/rules`, `internal/detector` |
| `ip_reputation/` | CIDR categories, fleet rotation, UA rotation. `config.yaml` sets scalars; `core-categories.yaml` and subdir files add/extend categories. | `internal/rules/ip_reputation.go`, `internal/detector` |
| `tls_fingerprints/` | JA3/JA4 exact and prefix classifications. All files merged. | `internal/tlsfp`, `internal/detector` |
| `templates/` | Tarpit response templates. All files merged; later files override same-key entries. | `internal/tarpit/renderer.go` |
| `injection_strategy/` | Tarpit route table and injector config. Community route files are prepended before the base routes so the `any` catch-all stays last. | `internal/tarpit/handler.go` |
| `payloads/` | Tarpit deception payload library. Categories: `termination`, `rabbit_hole`, `cost_bomb`, `confusion`, `moral_appeal`. `prompt_injection` category is present but empty by default since v1.1.5. `config.yaml` sets injector knobs and `generators`; other files add payload lists. | `internal/payloads` |
| `fake_data/` | Fake profile value pools. All list fields merged across files. | `internal/tarpit/profile.go` |
| `vulnerabilities/` | Fake vulnerability and honeypot path lists. All list fields merged across files. | `internal/tarpit/handler.go` |
| `challenge.yaml` | Challenge template, cookie, token, and verify settings. | `internal/challenge` |
| `ml.yaml` | Online ML and miner settings. | `internal/ml` |
| `dashboard.yaml` | Dashboard panels and charts. | `internal/telemetry/dashboard.go` |
| `learned/` (+ `learned.yaml`) | Miner-proposed or operator-promoted learned rules. Merged from both the root file and the subdirectory. | `internal/ml`, `internal/rules` |

## Extending Rules (Community Pattern)

Every rule type that manages lists follows the same merge pattern as `learned/`:

1. The **root directory** is walked recursively for `.yaml` / `.yml` files in
   lexicographic order.
2. **Scalar config** fields (points, tiers, timing knobs, injector settings)
   are set only when a file carries a non-zero value — the file that defines
   them wins; later files that omit them do not overwrite.
3. **List fields** (substrings, paths, CIDRs, payload templates) are always
   appended across all files.
4. **IP reputation categories** are merged by `name` — if two files define the
   same category name, their CIDRs are combined and the non-zero `points` value
   from any file wins.
5. **Injection strategy routes** from community files are prepended before the
   base routes so the generic `match: any` catch-all in the core file stays last.

### Recommended file layout

```
rules/
  detector/
    config.yaml               # scalar knobs only
    useragents/core.yaml      # core UA substrings
    useragents/<your>.yaml    # add more without editing core
    paths/core.yaml
    attack/core.yaml
    tools/llm-agents.yaml     # community: LLM pentesting UAs
  payloads/
    config.yaml               # injector knobs + log_burst generator
    core-deception.yaml
    core-rabbit-hole.yaml
    llm-agent-ops.yaml        # community: LLM-specific stops
  ip_reputation/
    config.yaml               # fleet_rotation, ua_rotation, private_cidrs
    core-categories.yaml      # tor, anonymizer, cloud, rfc1918_leak
    cloud/aws-gcp-azure-extended.yaml   # community extension
    vpn/residential-proxies.yaml
  injection_strategy/
    core-routes.yaml          # base route table
    routes/cloud-and-api.yaml # community: cloud metadata paths
  ...
  challenge.yaml              # single file (no subdir support)
  ml.yaml
  dashboard.yaml
```

## Hot Reload

Syntax:  automatic watcher for supported rule files  
Default: disabled when `rules_dir` is empty  
Context: runtime

VeilGate uses an `fsnotify` file watcher with a ~500 ms debounce to detect
changes. When a supported file changes, the watcher:

1. Waits for the debounce timer to expire (no further changes for 500 ms).
2. Calls the registered reload callback, which re-runs the full directory walk
   (`Load*` functions) and re-merges all files in the subtree.
3. On success: atomically updates the in-memory `Holder[T]` via
   `atomic.Pointer.Store()`.
4. On parse error: logs the error and keeps the previous in-memory rules active.

### `Holder[T]` pattern

Each hot-reloadable rule set is stored in a `Holder[T]` struct containing an
`atomic.Pointer[T]`. Request-path code calls `holder.Get()` on each request —
a single atomic load, no mutex, no blocking.

```go
// internal/rules/holder.go (schematic)
type Holder[T any] struct {
    ptr atomic.Pointer[T]
}

func (h *Holder[T]) Set(v *T) { h.ptr.Store(v) }
func (h *Holder[T]) Get() *T  { return h.ptr.Load() }
```

The watcher callback calls `holder.Set(newRules)` only on a successful parse.

```
File or subdir change on disk
    │
    ▼ (fsnotify event)
Watcher goroutine
    │
    ├── debounce ~500ms
    │
    ├── Load*(rulesDir)  ← full directory walk + merge
    │       ├── Error → log, keep old Holder contents
    │       └── OK → holder.Set(newRules)
    │
    └── Prometheus: veilgate_rule_reload_total{file, result}
```

### Code path

- [`internal/rules/watcher.go`](../../internal/rules/watcher.go) — `Watcher.Watch()`, `AddSubdir()`, debounce.
- [`internal/rules/holder.go`](../../internal/rules/holder.go) — `Holder[T]` generic type.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — registers reload callbacks per trigger file.

### Watcher registration table

The watcher trigger is a **filename** (legacy compatibility). When any file in
the corresponding directory subtree changes, the full `Load*` walk re-runs.

| Trigger file | Hot reload | Reload action |
|---|---|---|
| `detector.yaml` | yes | `LoadDetector(rulesDir)` → `scorer.SetRules()` |
| `signals.yaml` | yes (~500 ms) | `LoadSignals(rulesDir)` → `scorer.SetSignals()` — enable/disable/reweight signals, add custom signals |
| `api_blueprint.yaml` / `openapi.yaml` | yes | `LoadBlueprint(rulesDir)` → `scorer.SetBlueprint()` — enables `api_blueprint_miss` signal |
| `ip_reputation.yaml` | yes | `LoadIPReputation(rulesDir)` → `scorer.SetIPReputation()` |
| `templates.yaml` | yes | `LoadTemplates(rulesDir)` → `templatesHolder.Store()` |
| `fake_data.yaml` | yes | `LoadFakeData(rulesDir)` → `fakeDataHolder.Store()` |
| `vulnerabilities.yaml` | yes | `LoadVulnerabilities(rulesDir)` → `vulnHolder.Store()` |
| `injection_strategy.yaml` | yes | `LoadInjectionStrategy(rulesDir)` → `strategyHolder.Store()` |
| `challenge.yaml` | yes | `LoadChallenge(rulesDir)` → `challengeHolder.Store()` |
| `ml.yaml` | yes | `LoadML(rulesDir)` → `mlHolder.Store()` + path redaction rebuild |
| `dashboard.yaml` | yes | `LoadDashboard(rulesDir)` → `dashboardHolder.Store()` |
| `tls_fingerprints.yaml` | yes (TLS mode only) | `LoadTLS(rulesDir)` → `tlsDB.Apply()` |
| `payloads.yaml` / `payloads/` | **no — restart required** | `NewLibraryFromDir()` is startup-only |
| `learned.yaml` + `learned/` subdir | yes — subdir also watched via `AddSubdir` | `LoadLearned(rulesDir)` → `mlScorer.SeedFromLearned()` |

> **Note:** Editing any file inside a rule subdirectory (e.g. adding
> `detector/tools/my-tool.yaml`) does **not** auto-trigger a reload unless you
> also `touch` the corresponding trigger file. The `learned/` subdirectory is
> the only one currently registered with `AddSubdir` for automatic subdir
> watching. To hot-reload other rule subdirs without a restart, touch the
> trigger file:
> ```bash
> touch ~/.veilgate/rules/detector.yaml   # re-triggers LoadDetector walk
> touch ~/.veilgate/rules/payloads.yaml   # payloads require restart; touch has no effect
> ```

### Operational notes

- Hot reload is not a substitute for testing in staging.
- Keep a known-good rules revision for rollback (`git revert`).
- Parse errors leave previous rules active; logged at `warn` and counted in
  `veilgate_rule_reload_total{result="error"}`.

### Validation

```bash
# Trigger a hot reload after editing a rule file
touch ~/.veilgate/rules/detector.yaml

# Check reload metrics
curl http://127.0.0.1:9090/metrics | grep veilgate_rule_reload_total

# Trigger a known signal
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## Validation Commands

Trigger a known signal:

```bash
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

Check dashboard reload after editing dashboard rules:

```bash
curl -i http://127.0.0.1:9090/
```

## Related

- [Rule customization guide](../config/rules/customization.md)
- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_tarpit](veilgate_tarpit.md)
- [Module veilgate_ml](veilgate_ml.md)
- [Rules hot reload internals](../functionalities/rules-hot-reload.md)
