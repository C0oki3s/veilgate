# Use case: Replace your WAF with VeilGate

> **Summary:** Traditional WAFs block on known signatures — they reject
> requests that look like CVE-YYYY-NNNN. VeilGate scores on *behaviour* —
> it identifies that a client is acting like an automated scanner before it
> finds anything. The two are not competitors; they are layers. But for teams
> that can't afford a commercial WAF, or whose WAF is producing more false
> positives than value, VeilGate can take over the automated-traffic
> problem entirely.

**On this page:**

1. [The problem with signature WAFs](#the-problem-with-signature-wafs)
2. [What VeilGate does differently](#what-veilgate-does-differently)
3. [Coverage map](#coverage-map)
4. [The VeilGate setup](#the-veilgate-setup)
5. [WebSocket and gRPC](#websocket-and-grpc)
6. [Metrics that prove it's working](#metrics-that-prove-its-working)
7. [What VeilGate does not replace](#what-veilgate-does-not-replace)
8. [Migration path from an existing WAF](#migration-path-from-an-existing-waf)
9. [Operational gotchas](#operational-gotchas)
10. [Related](#related)

---

## The problem with signature WAFs

A WAF rule fires when request content matches a pattern — `' OR 1=1`,
`<script>`, `../../../etc/passwd`. This works well for script-kiddie attacks
that use off-the-shelf payloads verbatim, but falls apart in three places:

**1. Evasion is trivial.** Encoding variations (`%27`, `\x27`, `' `),
parameter pollution, and chunked bodies all defeat most rulesets. A tooled
agent that rotates payloads and encodings per request has a very low
match rate against a signature WAF.

**2. False positives are constant.** Developers, pen testers, and security
researchers regularly trigger WAF rules with legitimate traffic. Every
false positive is a support ticket, a rule exception, or a decision to put
the WAF in log-only mode where it does nothing.

**3. New techniques aren't covered.** AI-driven pentest agents don't need to
match a known CVE. They probe creatively, vary their payloads, and pivot
based on responses. A rule written in 2022 doesn't catch a technique from
2025.

---

## What VeilGate does differently

VeilGate does not inspect payloads. It scores client *behaviour*:

| Signal | What it catches |
|---|---|
| Path fan-out | Automated recon scanning many endpoints |
| Request rate | High-volume probing |
| UA fingerprint | Known scanner toolchains (`nuclei`, `sqlmap`, `ffuf`, curl scripts) |
| IP reputation | Tor exit nodes, VPN ranges, cloud egress |
| IP fleet rotation | Coordinated multi-IP attacks |
| TLS/JA4 fingerprint | TLS clients that don't match claimed UA |
| HTTP/2 fingerprint | Browser-impersonation mismatches |
| Honeypot hits | Any request to a path that doesn't exist |
| ML isolation forest | Multivariate anomaly across all of the above |

A client that hits two or three of these signals crosses the challenge
threshold. A client that hits several more crosses the tarpit threshold and
gets consumed by a fake application surface for as long as it keeps probing.

The key property: **a human browsing your site doesn't trigger any of
these signals**. False positives from legitimate users are near zero.
The only false positive surface is automated tooling used by developers
or pen testers — and for those, the verifier chain (HMAC, bearer token,
JWT, callout) provides a bypass lane without touching the score system.

---

## Coverage map

| Threat class | WAF | VeilGate |
|---|---|---|
| SQL injection / XSS payload matching | ✓ | — (payload-agnostic by design) |
| OWASP Top 10 signature coverage | ✓ | Partial — path enumeration and known-tool detection |
| Automated scanning / recon | Partial | ✓ |
| AI-agent pentest probing | — | ✓ |
| Credential stuffing | — | ✓ (rate + IP fleet signals) |
| Bot traffic at scale | Partial | ✓ |
| Unknown/zero-day techniques | — | ✓ (behavioural, not signature-based) |
| WebSocket and gRPC traffic | WAF-dependent | ✓ |

VeilGate covers the automated-traffic problem. Signature coverage (OWASP Top 10
payload matching) still belongs in your application, in a WAF, or in an IDS. The
two layers are complementary, not competing.

---

## The VeilGate setup

### `/etc/veilgate/veilgate.yaml`

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
rules_dir: "~/.veilgate/rules"
mode: "observe"              # start here; switch to auto after baseline

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold:    70
  probe_paths:
    - "/.env"
    - "/.git/config"
    - "/wp-admin/install.php"
    - "/api/swagger.json"
    - "/actuator/env"
    - "/admin"
  window_seconds: 120

tarpit:
  min_latency_ms: 800
  max_latency_ms: 4000
  max_body_bytes: 65536

challenge:
  secret: "${VEILGATE_SECRET}"
  difficulty: 3
  ttl_minutes: 60

persist:
  enabled: true
  db_path: /var/lib/veilgate/events.db
  retention_days: 90
```

Add known internal tooling to the verifier chain so pen testers and CI
pipelines don't get tarpitted:

```yaml
verifiers:
  bearer:
    enabled:    true
    tokens_dir: /etc/veilgate/api-tokens
  hmac:
    enabled:    true
    clients_dir: /etc/veilgate/hmac-clients
```

### Rollout sequence

1. **Deploy in `observe` mode.** All traffic reaches upstream. Scoring and
   logging run but nothing is diverted.
2. **Run your normal traffic and a few scanner-shaped test requests:**
   ```bash
   # Simulate a scanner
   for path in /.env /.git/config /admin /api/v1/users /api/swagger.json; do
     curl -s -A "sqlmap/1.7" http://localhost:8080$path -o /dev/null
   done
   ```
3. **Review the score histogram:**
   ```bash
   curl -s http://127.0.0.1:9090/metrics | grep veilgate_score_histogram
   ```
4. **Confirm legitimate traffic scores below 40.** Adjust thresholds or
   exclusions if needed.
5. **Switch to `auto` mode.** Update `mode: auto` and reload:
   ```bash
   sudo systemctl reload veilgate
   ```
6. **Monitor false positives** for 24 hours via the dashboard and
   `veilgate_requests_total{decision="challenge"}`.
7. **Issue bypass tokens** for internal tools that probe legitimately:
   ```bash
   openssl rand -hex 32 | sudo tee /etc/veilgate/api-tokens/ci-pipeline.token
   sudo chmod 0400 /etc/veilgate/api-tokens/ci-pipeline.token
   sudo chown veilgate:veilgate /etc/veilgate/api-tokens/ci-pipeline.token
   ```

---

## WebSocket and gRPC

VeilGate proxies WebSocket and gRPC natively. No additional configuration is
required. The same scoring and decision pipeline applies; the only difference
is that the challenge response is machine-readable rather than an HTML page.

| Protocol | Challenged response | Tarpitted response |
|---|---|---|
| HTTP | HTML PoW challenge page | Slow fake application response |
| WebSocket | `503 {"error":"challenge_required"}` | `403 {"error":"forbidden"}` |
| gRPC / gRPC-Web | `grpc-status: 16` (UNAUTHENTICATED) | `grpc-status: 7` (PERMISSION_DENIED) |

**Tarpitted WebSocket and gRPC connections get an immediate rejection, not a
slow tarpit response.** Slow-draining a bidirectional tunnel is not practical.
The tarpit's value (consuming scanner time with plausible fake content) applies
only to HTTP.

For socket.io or similar libraries that use WebSocket over a separate origin,
use the `/_g/start` iframe interstitial to pre-solve the PoW challenge
before connecting. See
[`/_g/start` reference](../reference/endpoints/start.md).

---

## Metrics that prove it's working

```bash
# Decision breakdown
curl -s http://127.0.0.1:9090/metrics \
  | grep veilgate_requests_total

# Top scoring signals
curl -s http://127.0.0.1:9090/metrics \
  | grep veilgate_signal_hits_total \
  | sort -t= -k2 -rn \
  | head -10

# IP fleet rotation events (coordinated multi-IP attacks)
curl -s http://127.0.0.1:9090/metrics \
  | grep veilgate_fleet_rotation_fires_total

# ML anomaly scores (requires burn-in of ~500 events)
curl -s http://127.0.0.1:9090/metrics \
  | grep veilgate_ml_score
```

Expected steady state after a day of real traffic:

- `veilgate_requests_total{decision="real"}` — the large majority
- `veilgate_requests_total{decision="tarpit"}` — scanner traffic;
  ideally a small but non-zero number (zero means nothing is probing)
- `veilgate_requests_total{decision="challenge"}` — borderline traffic
  that needs to solve the PoW; should be low for normal audiences

---

## What VeilGate does not replace

VeilGate is **not** a substitute for:

- **Patching.** A known CVE in your application or dependencies is a code
  problem, not a traffic problem. VeilGate can slow down the attacker but
  cannot fix the vulnerability.
- **Authentication and authorisation.** Access control belongs in the
  application. VeilGate does not inspect session tokens or enforce ACLs.
- **Rate limiting.** VeilGate's rate signals inform the score, but it does
  not have a generic rate-limiter. Combine it with a dedicated rate-limiter
  (nginx `limit_req`, API gateway quotas) for hard per-client limits.
- **Payload inspection / OWASP Top 10 matching.** VeilGate is behaviour-first.
  If you have a regulatory requirement for OWASP Top 10 signature coverage,
  keep a WAF or IDS in the stack alongside VeilGate. The layers coexist: WAF
  on Cloudflare or at the load balancer, VeilGate at the origin.
- **DDoS mitigation.** VeilGate adds per-request overhead. It is not designed
  to absorb flood-scale volumetric attacks. Place it behind a CDN or DDoS
  scrubbing layer.

---

## Migration path from an existing WAF

If you are replacing or supplementing a WAF, the recommended sequence is:

1. **Run both in parallel.** Place VeilGate behind your existing WAF. Run in
   `observe` mode for two weeks.
2. **Compare coverage.** Check which requests the WAF blocked that VeilGate
   also flagged (high score), and which VeilGate flagged that the WAF missed.
3. **Tune VeilGate thresholds** to match the false-positive rate you can
   accept.
4. **Switch VeilGate to `auto`.** Keep the WAF running.
5. **Evaluate WAF value.** If the WAF is now only blocking requests that
   VeilGate has already tarpitted, consider retiring it from the hot path or
   moving it to log-only mode for signature-evidence collection.

---

## Operational gotchas

**Scan traffic from legitimate tooling.** Internal security scanning
(`nessus`, `burp`, `nuclei` from a known IP) will score high and be
tarpitted if not excluded. Add a bearer token or HMAC credential for any
internal scanner, or add the scanner's egress IPs to `detector.trusted_ips`.

**CDN IP ranges.** If your CDN (Cloudflare, Fastly, etc.) is in front of
VeilGate, configure `detector.trusted_proxies` with the CDN's IP ranges so
VeilGate uses the real client IP from `X-Forwarded-For` instead of the CDN
IP. Without this, all traffic appears to come from the same IP and the
fleet-rotation signal misfires.

```yaml
detector:
  trusted_proxies:
    - 103.21.244.0/22    # Cloudflare example range
    - 103.22.200.0/22
    # ... full list from https://www.cloudflare.com/ips/
```

**New deployments need warm-up.** The ML isolation-forest model requires a
burn-in period (default 500 events) before it contributes to scores. During
the first hour of traffic, ML scores are zero and only rule-based signals
fire. This is normal and expected.

**Observe mode produces no false positives — by design.** The most common
"it's not blocking anything" report comes from operators who deployed in
`observe` mode and never switched to `auto`. Check `mode:` in
`/etc/veilgate/veilgate.yaml`.

---

## Related

- [LLM-agent defence](llm-agent-defense.md) — more detail on AI-driven pen
  test agent behaviour
- [API recon blocking](api-recon-blocking.md) — tuning for API surfaces
- [WebSocket and gRPC proxying](../functionalities/websocket-grpc-proxy.md)
- [Observe and tune guide](../how-to/observe-and-tune.md)
- [Bearer verifier](../reference/verifiers/bearer.md) — bypass lane for internal tooling
- [Operations overview](../operations/README.md)

---

*Previous: [Compliance & audit evidence](compliance-evidence.md) | Next: [Use cases index](README.md)*
