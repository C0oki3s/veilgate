# Decision Flow

This page maps the proxy decision path to code.

## Inputs

| Input | Source |
| --- | --- |
| `mode` | `config.Config.Mode` |
| `score` | `detector.Scorer.Score()` |
| `score_challenge_threshold` | `config.Config.Detector.ScoreChallengeThreshold` |
| `score_tarpit_threshold` | `config.Config.Detector.ScoreTarpitThreshold` |
| verifier result | `verifier.Chain.Verify()` |
| challenge token | `challenge.Handler.Passed()` |

## Decision Function

`internal/proxy.Server.decide()` applies the mode and thresholds:

| Mode | Score band | Initial decision |
| --- | --- | --- |
| `observe` | any | `observe` |
| `challenge` | `< challenge` | `real` |
| `challenge` | `>= challenge` | `challenge` |
| `tarpit` | `< challenge` | `real` |
| `tarpit` | `>= challenge` and `< tarpit` | `challenge` |
| `tarpit` | `>= tarpit` | `tarpit` |
| `auto` | `< challenge` | `real` |
| `auto` | `>= challenge` and `< tarpit` | `challenge` |
| `auto` | `>= tarpit` | `tarpit` |

## Bypass Rule

After the initial decision, `proxy.Server.serve()` checks verifiers and
challenge tokens only when the decision is not `tarpit`.

This means:

- valid HMAC can change `challenge` to `real`;
- valid challenge token can change `challenge` to `real`;
- neither can change `tarpit` to `real`.

This is an intentional security invariant.

## Handler Dispatch

| Final decision | Handler |
| --- | --- |
| `real` | upstream reverse proxy |
| `observe` | upstream reverse proxy |
| `challenge` | `challenge.Handler` |
| `tarpit` | `tarpit.Handler` |

## Code Path

- [`internal/proxy/proxy.go#L163`](../../internal/proxy/proxy.go#L163)
- [`internal/proxy/proxy.go#L346`](../../internal/proxy/proxy.go#L346)
- [`internal/detector/scorer.go#L177`](../../internal/detector/scorer.go#L177)
- [`internal/verifier/verifier.go`](../../internal/verifier/verifier.go)
- [`internal/challenge/challenge.go#L74`](../../internal/challenge/challenge.go#L74)

## Validation

Use observe mode first:

```bash
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

Then review the signal and score metrics before changing mode.

