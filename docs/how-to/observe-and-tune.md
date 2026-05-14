# How to roll out observe mode and tune thresholds

> **Goal:** Move from "VeilGate is running" to "VeilGate is making correct
> decisions on my real traffic" without ever returning a wrong response
> to a real user.

**On this page:**

1. [Why observe first](#why-observe-first)
2. [Step 1 — start in observe mode](#step-1--start-in-observe-mode)
3. [Step 2 — watch the score histogram](#step-2--watch-the-score-histogram)
4. [Step 3 — pick thresholds](#step-3--pick-thresholds)
5. [Step 4 — flip to challenge](#step-4--flip-to-challenge)
6. [Step 5 — flip to tarpit](#step-5--flip-to-tarpit)
7. [How long should each step run?](#how-long-should-each-step-run)
8. [Related](#related)

## Why observe first

`mode: "observe"` runs the full detector and ML pipeline but never
diverts a request — every request is forwarded to the upstream
regardless of score. That gives you a week of free telemetry on your
real traffic before anything user-visible changes.

Skipping observe is the single biggest cause of operator regret.
Defaults are calibrated against a synthetic agent corpus; they will not
match your traffic exactly until you've watched it.

## Step 1 — start in observe mode

```yaml
# /etc/veilgate/veilgate.yaml
mode: "observe"
detector:
  score_tarpit_threshold: 70       # placeholders, ignored in observe
  score_challenge_threshold: 40
```

```bash
sudo systemctl reload veilgate     # rule files hot-reload; mode change needs restart
sudo systemctl restart veilgate
```

## Step 2 — watch the score histogram

Pull the score histogram from Prometheus:

```bash
curl -sS http://127.0.0.1:9090/metrics | grep -E '^veilgate_score'
```

Or in Grafana / promtool / `prometheus_client`:

```promql
sum by (le) (increase(veilgate_score_bucket[1h]))
```

A healthy site looks like this after a few hours:

| Score range | What it represents | Expected share |
| --- | --- | --- |
| 0 | clean traffic, no signals fired | 80–95 % |
| 1–30 | weak signals (one minor rule + ML noise) | 2–10 % |
| 30–60 | clear agent / scanner traffic | 1–5 % |
| 60–100 | obvious agents, multiple signals | 0.1–2 % |

Look for two specific signs of trouble:

- **A bump around scores 10–25 with browser UAs** — your `sec_fetch_*`
  rules are firing on a real-browser fixture missing one header. Check
  which signal hits dominate via `veilgate_signal_hits_total`.
- **A bump around 40–60 with `path_bruteforce` hits but no other
  signals** — your distinct-paths threshold is too low for your
  traffic shape (legitimate single-page apps walk many paths).

## Step 3 — pick thresholds

Two thresholds:

- `score_challenge_threshold` — score at or above which a JS PoW
  challenge is served. Defaults to `40`.
- `score_tarpit_threshold` — score at or above which the request is
  diverted to the tarpit. Defaults to `70`.

Pick them so:

- The challenge threshold sits above the tail of legitimate
  browser traffic (typically score 0 with occasional excursions to 5–15).
- The tarpit threshold sits at or above the score where multiple
  agent-leaning signals must combine. A request with a single signal
  should not tarpit.

Concrete rule of thumb:

```
challenge = p99 of legit-browser scores + 5
tarpit    = challenge + 25
```

Compute `p99` of legit traffic from the histogram:

```promql
histogram_quantile(0.99,
  sum by (le) (rate(veilgate_score_bucket[24h])))
```

## Step 4 — flip to challenge

```yaml
mode: "challenge"
detector:
  score_challenge_threshold: <your value>
  score_tarpit_threshold: 95         # very high — effectively tarpit-disabled for now
```

```bash
sudo systemctl restart veilgate
```

Watch for a week:

- `veilgate_requests_total{decision="challenge"}` — the rate at which
  you're issuing challenges. Should match the share of traffic above
  threshold from your histogram.
- Customer support tickets — if real users complain about JS being
  required, raise the challenge threshold.

## Step 5 — flip to tarpit

Once challenge mode has been stable for a week and you understand which
clients land in the challenge bucket and why, lower the tarpit threshold:

```yaml
mode: "tarpit"
detector:
  score_challenge_threshold: <your value>
  score_tarpit_threshold: <your value, typically 65–75>
```

Watch:

- `veilgate_requests_total{decision="tarpit"}` — should be tiny
  fraction of traffic. If it climbs above ~5 %, your tarpit threshold
  is too aggressive.
- `veilgate_attacker_cost_usd_total` — if you're tarpitting and this
  isn't moving, the agent isn't reading the responses (which means
  it's not a tarpit-class agent — re-examine the score signals).
- The audit log — every threshold change is recorded.

## How long should each step run?

| Step | Minimum dwell time | Why |
| --- | --- | --- |
| Observe | 1 traffic cycle (typically 1 week) | weekday + weekend + business-hours patterns |
| Challenge | 1 week after threshold change | catch low-volume long-tail UAs you didn't see in observe |
| Tarpit | indefinite | this is the steady state |

If your traffic has a strong monthly pattern (e.g. end-of-month batch
processing customers), wait at least one cycle of *that* pattern at the
observe and challenge stages.

## Related

- [Use case: Bug-bounty triage](../usecases/bug-bounty-triage.md) — when
  to *not* flip to tarpit
- [How-to: Promote learned rules](promote-learned-rules.md)
- [Config: detector thresholds](../config/detector.md)
- [Config: rules/ml.yaml](../config/rules/ml.md)

---

*Previous: [Install on Linux](install-on-linux.md) · Next: [Promote learned rules](promote-learned-rules.md)*
