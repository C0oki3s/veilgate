# Rollout Guide

This page covers the recommended sequence for deploying VeilGate in front of
a production application. The sequence is designed to minimize false positives
and allow the operator to build confidence in the detector before enabling
enforcement.

---

## Overview

The rollout has four stages:

| Stage | Mode | Duration | Goal |
| --- | --- | --- | --- |
| 1 | `observe` | days 1–7+ | Baseline traffic and identify false positives |
| 2 | `challenge` | days 7–14+ | Validate challenge flow and user impact |
| 3 | `tarpit` or `auto` | ongoing | Full enforcement after threshold confidence |
| 4 | — | ongoing | Monitor, tune, and maintain rule files |

Do not skip stages. Moving directly to `tarpit` mode without an observe-mode
baseline is the most common cause of false positives in production.

---

## Prerequisites

Before deployment, complete the following:

1. **Set `VEILGATE_SECRET`.**

   ```bash
   export VEILGATE_SECRET="$(openssl rand -hex 32)"
   ```

   VeilGate refuses to start outside `observe` mode when the placeholder
   challenge secret is still in place. Store the secret in a systemd drop-in,
   a secret manager, or the deployment's secret injection mechanism. Do not
   commit it to the repository.

2. **Prepare TLS certificates** if VeilGate will terminate TLS for
   fingerprinting:

   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
     -days 365 -nodes -subj "/CN=yourhost.example.com"
   ```

   For production, use a certificate from a recognized CA or from Let's Encrypt.

3. **Create the data directory:**

   ```bash
   mkdir -p ./data/dumps
   chmod 700 ./data
   ```

4. **Copy and review the rule files:**

   ```bash
   cp -r rules/ /etc/veilgate/rules/
   chmod -R 600 /etc/veilgate/rules/*.yaml
   ```

   Review each file before deployment. The rules define your security policy.

---

## Stage 1: Observe Mode

### Minimal starting configuration

```yaml
# /etc/veilgate/veilgate.yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
mode: "observe"
rules_dir: "/etc/veilgate/rules"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  window_seconds: 90
  trusted_ips: []
  trusted_proxies: []
  honeypot_paths:
    - "/.git/config"
    - "/.env.backup"
    - "/wp-admin-old"
    - "/phpmyadmin-backup"

persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
  retention_days: 30
  queue_size: 4096
  dump_path: "/var/lib/veilgate/dumps"
  cache_size_kb: 65536

metrics:
  listen: "127.0.0.1:9090"

tls:
  enabled: false
```

### Start the service

```bash
# systemd
systemctl start veilgate

# or directly
VEILGATE_SECRET="<your-secret>" ./veilgate -config /etc/veilgate/veilgate.yaml
```

### Generate representative traffic

Send a mix of known-clean and known-scanner traffic during the observation
period:

```bash
# Known clean: simulate a browser request
curl -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  http://localhost:8080/

# Known scanner: sqlmap-like request
curl -A "sqlmap/1.7" "http://localhost:8080/login?id=1%27%20OR%201=1--"

# Honeypot hit test
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
```

### Review metrics daily

```bash
# Score distribution
curl -s http://127.0.0.1:9090/metrics | grep veilgate_score_bucket

# Top signals
curl -s http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total | sort -t= -k3 -nr | head -20

# Decision distribution
curl -s http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

Or add VeilGate as a Prometheus scrape target and use the PromQL queries from
[Prometheus Queries](prometheus-queries.md).

### Criteria to exit Stage 1

Before proceeding to Stage 2, verify:

- The score histogram shows a clear separation between normal traffic and
  scanner-shaped traffic.
- No legitimate business requests consistently score above
  `score_challenge_threshold`.
- You have identified and resolved any false-positive signals.
- `veilgate_signal_hits_total{signal="honeypot_hit"}` is incrementing only for
  known-scanner traffic.

---

## Stage 2: Challenge Mode

### Update mode

```yaml
mode: "challenge"

challenge:
  secret: "${VEILGATE_SECRET}"
  difficulty: 4
  ttl_minutes: 30
```

Restart VeilGate after changing `mode`.

### Verify the challenge flow

```bash
# A browser-like request should NOT be challenged
curl -A "Mozilla/5.0 (X11; Linux x86_64) Chrome/124.0.0.0 Safari/537.36" \
  -H "Accept-Language: en-US" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Dest: document" \
  http://localhost:8080/

# A scanner-like request SHOULD be challenged
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
```

The second request should return a `200` with the PoW challenge HTML instead of
the actual application response.

### Monitor user impact

Watch for increases in user-visible challenge pages:

```bash
curl -s http://127.0.0.1:9090/metrics | grep 'decision="challenge"'
```

If legitimate users are receiving the challenge at a significant rate, return to
the signal analysis from Stage 1 and tune before proceeding.

### Criteria to exit Stage 2

- Challenge page is not shown to legitimate browsers during normal usage.
- Known scanner traffic consistently receives the challenge.
- `challenge.ttl_minutes` is set appropriately for your session duration.
- No reports of broken SPA flows or API clients being challenged. (If API
  clients exist, consider the HMAC verifier — see
  [Module veilgate_verifier](../modules/veilgate_verifier.md).)

---

## Stage 3: Tarpit or Auto Mode

### Choose between `tarpit` and `auto`

| Mode | Use when |
| --- | --- |
| `tarpit` | You want high-confidence traffic to the tarpit; middle band also challenged. |
| `auto` | Below challenge goes upstream; middle band challenged; high-confidence tarpitted. |

`auto` is the most operationally useful mode for most deployments because it
applies graduated responses across the full score range.

### Update mode

```yaml
mode: "auto"

tarpit:
  min_latency_ms: 500
  max_latency_ms: 3000
  max_body_bytes: 102400
```

Restart VeilGate.

### Verify tarpit behavior

```bash
# Should receive tarpit response with delay
time curl -A "sqlmap/1.7" http://localhost:8080/.git/config
```

The response should:
- Take at least `min_latency_ms` milliseconds.
- Return fake application content (not the real app's 404).
- Not reveal the real application's structure.

### Monitor tarpit metrics

```bash
# Bytes served to tarpitted clients
curl -s http://127.0.0.1:9090/metrics | grep veilgate_tarpit_bytes_served_total

# Estimated attacker cost
curl -s http://127.0.0.1:9090/metrics | grep veilgate_attacker_cost_usd_total

# Tarpit decision rate
curl -s http://127.0.0.1:9090/metrics | grep 'decision="tarpit"'
```

---

## Stage 4: Ongoing Operations

### Rule file maintenance

```bash
# Review rule changes before applying
diff rules/detector.yaml /etc/veilgate/rules/detector.yaml

# Apply and reload (hot reload triggers within ~500ms)
cp rules/detector.yaml /etc/veilgate/rules/detector.yaml
```

Rule files inside `rules_dir` support hot reload via `fsnotify`. Threshold and
mode values in `veilgate.yaml` require a restart.

### Threshold tuning workflow

1. Run `observe` for a new traffic segment.
2. Export score histogram:
   ```promql
   histogram_quantile(0.95, sum by (le) (rate(veilgate_score_bucket[1h])))
   ```
3. Identify the 95th-percentile score for clean traffic.
4. Set `score_challenge_threshold` to at least `p95_clean_score + 10`.
5. Set `score_tarpit_threshold` to `score_challenge_threshold + 20` or higher.

### Promote learned rules

After accumulating ML observations:

```bash
# Review miner candidates
go run ./cmd/mlsmoke

# Promote to learned.yaml after review
# See: docs/how-to/promote-learned-rules.md
```

### Secret rotation

Rotate `VEILGATE_SECRET` if it is suspected of being leaked. Rotation
invalidates all outstanding challenge tokens; clients in the middle of solving
a challenge will need to re-solve.

```bash
export VEILGATE_SECRET="$(openssl rand -hex 32)"
systemctl restart veilgate
```

---

## Rollback

If VeilGate causes unexpected application behavior:

1. Switch to `observe` mode immediately (requires restart):
   ```bash
   sed -i 's/^mode:.*/mode: "observe"/' /etc/veilgate/veilgate.yaml
   systemctl restart veilgate
   ```
2. Collect logs and metrics to identify the cause.
3. Adjust rules or thresholds before re-enabling enforcement.

In observe mode, all traffic flows to the upstream application with no
diversion. The detector continues scoring and recording, so you can review
what triggered the problem.

---

## Security Checklist Before Going Live

See [Security Hardening](security_hardening.md) for the full checklist. The
minimum before enabling enforcement:

- [ ] `VEILGATE_SECRET` is set and not the placeholder value.
- [ ] `metrics.listen` is bound to `127.0.0.1` or a private network.
- [ ] `tls.key_file` is readable only by the VeilGate service user.
- [ ] `persist.path` permissions are `600`.
- [ ] `trusted_proxies` contains only proxies you operate.
- [ ] `trusted_ips` does not contain `127.0.0.1` unless intentional.
- [ ] Rule files are versioned in a repository.

---

## Related

- [Troubleshooting](troubleshooting.md)
- [Security Hardening](security_hardening.md)
- [Module veilgate_core](../modules/veilgate_core.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
