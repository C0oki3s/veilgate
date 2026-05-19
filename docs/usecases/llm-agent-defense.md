# Use case: LLM-agent defence

> **Summary:** When the threat model is autonomous AI pentest agents
> (Strix, HexStrike, PentAGI, CAI, PentestGPT, Claude Code on a leash),
> VeilGate runs in `tarpit` mode and actively burns the attacker's LLM
> token budget. This is the canonical use case the project was built for.

**On this page:**

1. [The problem](#the-problem)
2. [The VeilGate setup](#the-veilgate-setup)
3. [Why tarpit, not block](#why-tarpit-not-block)
4. [Metrics that prove it's working](#metrics-that-prove-its-working)
5. [Operational gotchas](#operational-gotchas)
6. [Related](#related)

## The problem

An autonomous AI pentest agent typically:

1. Probes the target with an HTTP library that has a recognisable JA3
   / JA4 fingerprint and a non-browser HTTP/2 SETTINGS frame.
2. Issues requests at LLM-paced intervals (~3–8 s reasoning gaps).
3. Walks through `recon → probe → exploit` stage by stage.
4. Retries failed attempts with a *different* request shape rather
   than retry-with-credentials (the human pattern).
5. Sometimes runs for hours or days before a human reviews output.

Blocking it is a poor strategy: the agent retries from a different IP,
or the operator iterates the prompt and tries again. Tarpitting it —
serving a coherent fake application full of fake bugs and prompt
injections — wastes the *attacker's* tokens.

## The VeilGate setup

Run in `tarpit` mode behind a WAF. Tune thresholds aggressively because
false-positive cost is low (real users sit at score 0; agents pile up
points across multiple signals).

### `/etc/veilgate/veilgate.yaml`

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
rules_dir: "~/.veilgate/rules"
mode: "tarpit"

detector:
  score_tarpit_threshold: 70
  score_challenge_threshold: 40
  window_seconds: 90

tls:
  enabled: true                    # JA3/JA4 require terminating TLS at VeilGate
  cert_file: /etc/veilgate/tls/fullchain.pem
  key_file:  /etc/veilgate/tls/privkey.pem

tarpit:
  min_latency_ms: 800
  max_latency_ms: 4000             # slow responses; LLM agents pay per second
  max_body_bytes: 102400

persist:
  enabled: true
  path: /var/lib/veilgate/events.db

metrics:
  listen: 127.0.0.1:9090
```

### `~/.veilgate/rules/ml.yaml`

```yaml
enabled: true
score_max_points: 40
alpha: 0.7
burn_in_events: 500
min_confidence_to_fire: 0.2

path_redaction:
  enabled: true

miner:
  enabled: true
  interval_minutes: 60
  min_support: 200
  min_posterior: 0.9
  auto_promote_confidence: 0.0     # operator review only
```

### `~/.veilgate/rules/injection_strategy.yaml`

```yaml
injector:
  max_payloads_per_response: 4     # heavier injection for LLM-agent traffic
  visit_bucket_rotation: true      # rotate styles so guardrails can't memorise

style_weights:
  default:
    termination: 3
    rabbit_hole: 3
    cost_bomb: 4                   # extra cost-bomb weight — burn their tokens
    confusion: 2
    moral_appeal: 2
```

## Why tarpit, not block

| Approach | Attacker response | Defender outcome |
| --- | --- | --- |
| **Block** at WAF | retry from new IP / iterate prompt | the attacker keeps trying |
| **Rate-limit** | slow down, distribute load | the attacker still progresses |
| **Tarpit** | LLM keeps reading hallucinated content | the attacker spends tokens learning nothing |

The economics of an LLM-driven attack reverse when every "successful"
probe returns a long, expensive-to-process response that contains a
prompt injection trying to make the agent stop. Even if the agent's
guardrails defeat one payload style, VeilGate rotates through five.

## Metrics that prove it's working

The headline metric is `veilgate_attacker_cost_usd_total` — a rough
estimate of the dollar cost imposed on the attacker, computed as
bytes-served × $0.003 / KiB (a token-cost proxy). Watch it climb when an
agent is actively probing.

Other key signals:

- `veilgate_signal_hits_total{signal="canary_replay"}` — non-zero means
  an attacker reused a tarpit-served credential. Near-perfect proof of
  agent-in-the-loop.
- `veilgate_signal_hits_total{signal="toolchain_hmm"}` — the recon →
  probe → exploit pattern.
- `veilgate_signal_hits_total{signal="reasoning_pause" or
  signal="pause_bucket"}` — LLM-cadence timing.
- `veilgate_score` histogram — should bimodal cleanly, with real users
  near 0 and agents above the tarpit threshold.

## Operational gotchas

- **TLS termination must be at VeilGate** for JA3/JA4 to work. If you
  terminate at a CDN, those signals are lost; you fall back to
  HTTP-layer detection only.
- **The dashboard `attacker_cost_usd` is an estimate, not a billable
  number.** It's a directional signal for "is the tarpit doing
  anything?", not a court exhibit.
- **Run in `observe` mode for at least a week first.** The score
  distribution on your real traffic determines where to set thresholds.
  Defaults are calibrated against a synthetic agent corpus — they will
  not match your traffic exactly.
- **Watch the canary table.** When a tarpit-served credential gets
  replayed, the audit log captures it. That's a high-confidence
  incident — investigate.

## Related

- [Bug-bounty triage](bug-bounty-triage.md) — when `tarpit` is too
  aggressive
- [How-to: Observe mode rollout](../how-to/observe-and-tune.md)
- [How-to: Promote learned rules](../how-to/promote-learned-rules.md)
- [Config: tarpit](../config/tarpit.md)
- [Config: rules/injection_strategy.yaml](../config/rules/injection-strategy.md)
- [Config: rules/payloads.yaml](../config/rules/payloads.md)

---

*Previous: [Bug-bounty triage](bug-bounty-triage.md) · Next: [API recon blocking](api-recon-blocking.md)*
