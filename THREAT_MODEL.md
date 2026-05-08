# Threat Model

VeilGate is a deception proxy. It reduces risk from automated probing by
classifying traffic and diverting high-confidence agent traffic away from the
real upstream application.

It is not a replacement for patching, authentication, WAF/rate-limit controls,
or secure application design.

## Assets

| Asset | Sensitivity | Notes |
| --- | --- | --- |
| Upstream application | High | The system VeilGate protects. |
| Challenge secret | High | Signs proof-of-work cookies. |
| Rule files | Medium | Detection and deception policy. |
| TLS private key | Critical | Used when VeilGate terminates TLS. |
| SQLite store | High | May contain request metadata, IPs, user agents, and paths. |
| Metrics endpoint | Medium | Reveals scoring and signal behavior. |

## Trust Boundaries

```text
client -> VeilGate listener -> upstream app
                    |
                    +-> metrics/dashboard listener
                    +-> rules/config filesystem
                    +-> SQLite persistence
```

## In-Scope Adversaries

- AI-assisted security agents.
- Scripted scanners such as sqlmap, nuclei, nikto, curl/httpx-based tooling.
- Commodity bots and credential stuffers.
- Operators or attackers with access to captured telemetry.

## Out Of Scope

- Large-scale volumetric DDoS.
- Exploits in the upstream application that are reached by clean, human-like
  traffic.
- Supply-chain compromise of the Go toolchain or dependencies.
- Protecting systems the operator does not own or have permission to defend.

## Key Threats And Mitigations

### Automated Scanner Reaches Real Upstream

Mitigations:

- Multi-signal scoring.
- Honeypot paths.
- TLS and HTTP/2 fingerprinting.
- Tarpit diversion above threshold.
- Observe-first rollout for threshold tuning.

Residual risk:

- Careful browser-driven agents can look like normal traffic.

### Spoofed Client IP Via Forwarded Headers

Mitigations:

- `X-Forwarded-For` is ignored unless the direct peer is in
  `detector.trusted_proxies`.
- Tarpit profile identity uses the direct peer address.

Residual risk:

- Misconfigured `trusted_proxies` can reintroduce spoofing.

### Challenge Cookie Forgery

Mitigations:

- Proof-of-work verify requests require signed challenge metadata.
- Cookies use HMAC.
- Startup refuses default challenge secret outside `observe`.
- `VEILGATE_SECRET` can inject the secret from a secret manager.

Residual risk:

- A leaked challenge secret allows cookie forgery until rotated.

### Rule File Tampering

Mitigations:

- Embedded defaults work without external files.
- Rule files should be mounted read-only in production.
- Rule files should be reviewed and versioned like security policy.

Residual risk:

- An attacker who can write rule files can alter detection and deception output.

### Telemetry Disclosure

Mitigations:

- JSONL capture is disabled by default.
- SQLite and capture paths use restrictive file permissions where created by
  VeilGate.
- Path redaction is enabled for ML features.
- Retention and dump settings are configurable.

Residual risk:

- Request metadata may still contain personal data or sensitive internal paths.

### Metrics Endpoint Disclosure

Mitigations:

- Bind `metrics.listen` to a private interface or localhost.
- Put dashboard/metrics behind VPN, auth, or an internal load balancer.

Residual risk:

- Public metrics reveal detector thresholds, signal hits, and attack activity.

### Tarpit Content Exposed To False Positives

Mitigations:

- Default mode is `observe`.
- Operators can tune thresholds before enforcement.
- Tarpit body size and latency are capped.

Residual risk:

- False positives can still receive deceptive content when `tarpit` is enabled.

## Operator Requirements

- Run `observe` before enforcement.
- Set `VEILGATE_SECRET`.
- Keep metrics private.
- Keep rules reviewed and read-only in production.
- Keep persistence and dumps under normal privacy controls.
- Tune thresholds from your own traffic.

## Non-Goals

VeilGate does not:

- fix vulnerabilities in the upstream app,
- parse every request body like a full WAF,
- rate-limit by itself,
- guarantee attribution,
- guarantee that agents will not detect the deception,
- make unauthorized defensive deployment lawful.
