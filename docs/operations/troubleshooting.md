# Troubleshooting

This page covers diagnostic steps for common operational problems. For each
issue, follow the checklist in order before changing configuration.

---

## Reinstall keeps using stale files or permissions

**Symptom:** After rerunning the installer, VeilGate still uses an old binary,
old systemd unit, old rules directory, or old config permissions.

Use a clean reinstall when an earlier install left stale state behind:

```bash
sudo systemctl disable --now veilgate 2>/dev/null || true
sudo rm -f /etc/systemd/system/veilgate.service
sudo systemctl daemon-reload
sudo systemctl reset-failed veilgate 2>/dev/null || true

sudo rm -f /usr/local/bin/veilgate
sudo rm -rf /etc/veilgate /var/lib/veilgate /var/log/veilgate
sudo userdel veilgate 2>/dev/null || true
```

Then reinstall:

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

Verify the installed binary and service state:

```bash
/usr/local/bin/veilgate -version
sudo systemctl status veilgate --no-pager
```

---

## Permission denied reading `/etc/veilgate/veilgate.yaml`

**Symptom:** The service exits at startup with:

```text
FTL load config error="read config: open /etc/veilgate/veilgate.yaml: permission denied"
```

The systemd service runs as user/group `veilgate`, so `/etc/veilgate` must be
searchable by that group and the config must be group-readable:

```bash
sudo chown root:veilgate /etc/veilgate
sudo chmod 750 /etc/veilgate
sudo chown root:veilgate /etc/veilgate/veilgate.yaml
sudo chmod 640 /etc/veilgate/veilgate.yaml
sudo restorecon -Rv /etc/veilgate 2>/dev/null || true
```

Confirm the service user can read the config:

```bash
sudo -u veilgate test -r /etc/veilgate/veilgate.yaml && echo config-ok
sudo systemctl restart veilgate
```

On SELinux hosts such as Fedora or RHEL, if the direct read test passes but
systemd still logs permission errors, check AVC denials:

```bash
sudo ausearch -m avc -ts recent | tail -40
```

---

## `update-rules` or miner cannot write rules

**Symptom:** `veilgate update-rules` fails with permission errors, or logs show
the miner cannot write `learned.yaml`.

The packaged config uses `rules_dir: "~/.veilgate/rules"`. Under systemd, that
resolves to `/var/lib/veilgate/.veilgate/rules` because the `veilgate` user's
home is `/var/lib/veilgate`.

Fix ownership and modes:

```bash
sudo install -d -o veilgate -g veilgate -m 0750 /var/lib/veilgate/.veilgate/rules
sudo chown -R veilgate:veilgate /var/lib/veilgate/.veilgate
sudo find /var/lib/veilgate/.veilgate/rules -type d -exec chmod 0750 {} +
sudo find /var/lib/veilgate/.veilgate/rules -type f -exec chmod 0640 {} +
```

Run updates as the same user that runs the service:

```bash
sudo -u veilgate /usr/local/bin/veilgate update-rules --dir /var/lib/veilgate/.veilgate/rules --no-backup
```

If `update-rules` reports `download failed: download: HTTP 415`, the installed
binary predates the GitHub zipball Accept-header fix. Install a newer VeilGate
release or a locally built binary that includes that fix.

---

## Docker rules mount is read-only or mislabeled

**Symptom:** Container logs show miner write errors, rules do not update, or
Fedora/RHEL hosts show permission denied for mounted rules.

The rules mount must be writable. Do not use `:ro` for it:

```bash
docker run -d --name veilgate \
  --network host \
  -v /etc/veilgate/veilgate.yaml:/etc/veilgate/veilgate.yaml:ro \
  -v ~/.veilgate/rules:/home/nonroot/.veilgate/rules \
  -e VEILGATE_SECRET=$(openssl rand -hex 32) \
  ghcr.io/c0oki3s/veilgate:latest -config /etc/veilgate/veilgate.yaml
```

On SELinux hosts, add `z` relabel flags:

```bash
docker run -d --name veilgate \
  --network host \
  -v /etc/veilgate/veilgate.yaml:/etc/veilgate/veilgate.yaml:ro,z \
  -v ~/.veilgate/rules:/home/nonroot/.veilgate/rules:z \
  -e VEILGATE_SECRET=$(openssl rand -hex 32) \
  ghcr.io/c0oki3s/veilgate:latest -config /etc/veilgate/veilgate.yaml
```

---

## Normal browser traffic is challenged or tarpitted

**Symptom:** Real users receive the proof-of-work challenge page or see
unexpected application behavior consistent with tarpit responses.

**Step 1: Check which signals fired.**

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

Identify signals firing at high volume relative to request rate.

**Step 2: Check the score histogram.**

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_score_bucket
```

If a large fraction of requests score above `score_challenge_threshold`, the
signals or thresholds need tuning.

**Step 3: Identify the false-positive signal.**

Use the structured logs (`zerolog` JSON output):

```json
{
  "level": "info",
  "client": "203.0.113.10",
  "method": "GET",
  "path": "/",
  "score": 42,
  "decision": "challenge",
  "signals": [{"Name":"sparse_headers","Points":14,"Reason":"..."},...]
}
```

**Step 4: Evaluate whether the signal is correct.**

| Signal | Likely false-positive cause |
| --- | --- |
| `sparse_headers` | CDN strips `Accept-Language`, `Sec-Fetch-*` headers |
| `suspicious_ua` | Internal API client or CI pipeline with a library UA |
| `ip_reputation` | Legitimate office egress on a cloud IP block |
| `honeypot_hit` | Honeypot path accidentally matches a real route |
| `tls_agent` | TLS fingerprint of a legitimate client library |

**Step 5: Apply the targeted fix.**

- `sparse_headers` from CDN: verify CDN is forwarding headers; add CDN IP to
  `trusted_proxies` if it is the direct TCP peer.
- `suspicious_ua` from internal system: add client ID to `trusted_ips` or
  tune the UA match list in `rules/detector.yaml`.
- `ip_reputation` false positive: adjust the CIDR list in
  `rules/ip_reputation.yaml`.
- `honeypot_hit` false positive: remove the path from `honeypot_paths`.
- Protocol fingerprint: update `rules/tls_fingerprints.yaml` classification.

**Do not raise thresholds globally** as a first response. Identify and fix
the specific signal.

---

## No TLS fingerprints are firing

**Symptom:** `veilgate_signal_hits_total{signal="tls_agent"}` is always zero,
even when connecting with a known non-browser client.

**Checklist:**

1. Confirm `tls.enabled: true` in `veilgate.yaml`.
2. Confirm clients connect to `https://` and VeilGate's port.
3. Confirm TLS is **not** terminated before VeilGate (check whether a load
   balancer, CDN, or NGINX proxy sits in front).
4. Confirm `tls.cert_file` and `tls.key_file` are readable by the VeilGate
   process user.
5. Check startup logs for TLS errors.

**Verification:**

```bash
# Check that VeilGate is actually terminating TLS
openssl s_client -connect localhost:8080 2>&1 | head -20
```

If you see the certificate VeilGate was configured with, TLS termination is
working. If you see a certificate from another system, TLS is being terminated
upstream.

---

## Metrics listener is accessible from the public internet

**Symptom:** `curl https://your-domain:9090/metrics` returns data from an
external network.

**Fix:**

```yaml
# veilgate.yaml
metrics:
  listen: "127.0.0.1:9090"
```

This binds the metrics listener to loopback only. Restart VeilGate after
changing this.

**Access from a remote workstation using SSH tunnel:**

```bash
ssh -L 9090:127.0.0.1:9090 user@yourhost
# Then access: http://localhost:9090/metrics
```

Do not use `0.0.0.0:9090` in production. The metrics endpoint exposes
detection thresholds, signal weights, and active attack data.

---

## SQLite file grows too large

**Symptom:** `./data/events.db` or the WAL file exceeds expected size.

**Checklist:**

1. Confirm `persist.retention_days` is set and is not too large:
   ```yaml
   persist:
     retention_days: 30
   ```
2. Verify the trim job is running. Retention runs every 6 hours. If the
   process has been running for less than 6 hours, no trim has occurred yet.
3. Check whether `dump_path` is writing dump files that are themselves growing:
   ```bash
   ls -lh ./data/dumps/
   ```
4. If dumps are not needed, set `dump_path: ""` to trim directly.
5. Check for a WAL file accumulation:
   ```bash
   ls -lh ./data/events.db-wal
   ```
   A large WAL file indicates the flusher goroutine is not committing frequently
   enough. Under very high request volume, increase `persist.queue_size`.

**Monitor database size:**

```bash
du -sh ./data/events.db ./data/events.db-wal
```

---

## `X-Forwarded-For` spoofing suspected

**Symptom:** Requests appear to come from trusted or private IPs that should
not be present in normal traffic. Scores are unexpectedly low for sources that
should be high-scoring.

**Explanation:** VeilGate only trusts `X-Forwarded-For` when the direct TCP
peer is inside `detector.trusted_proxies`. Scanners commonly inject values like
`127.0.0.1` or `10.0.0.1` into the `X-Forwarded-For` header to spoof an
allowlisted address.

**Step 1: Verify what VeilGate is using as the client ID.**

Check the structured log output. The `client` field is the resolved client ID
after `resolveClientIP()`.

**Step 2: Verify `trusted_proxies` is correctly scoped.**

```yaml
detector:
  trusted_proxies:
    - "10.0.0.0/8"   # only if your load balancer is on this range
```

Do not add public internet ranges. Do not add `0.0.0.0/0`.

**Step 3: Send a test with a spoofed header.**

```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:8080/
```

Check the log: the `client` field should be the real remote address, not
`127.0.0.1`, unless the direct peer is in `trusted_proxies`.

**Step 4: Check for non-IP injection strings.**

Scanners like nuclei inject Log4Shell JNDI strings or XSS payloads into
`X-Forwarded-For`. VeilGate ignores non-IP values when walking the XFF chain:

```go
// internal/proxy/proxy.go
parsed := net.ParseIP(h)
if parsed == nil {
    continue // Non-IP junk in header. Ignore it entirely.
}
```

---

## High score but incorrect decision

**Symptom:** A request scores at or above `score_tarpit_threshold` but the
decision is `real` instead of `tarpit`.

**Checklist:**

1. Confirm `mode` is not `observe`. In observe mode, the decision is always
   `observe` (forwarded to upstream) regardless of score:
   ```bash
   grep "^mode:" configs/veilgate.yaml
   ```
2. Confirm mode is `tarpit` or `auto`, not `challenge`. In `challenge` mode,
   even very high scores only receive the challenge handler, not tarpit.
3. Check whether a verifier or challenge token is bypassing the challenge
   decision. Tarpit decisions cannot be bypassed by verifiers or challenge
   tokens — check logs for `verifier accepted request` entries.
4. Verify the `score_tarpit_threshold` value:
   ```bash
   curl http://127.0.0.1:9090/metrics | grep veilgate_config
   ```

---

## Challenge token not being accepted

**Symptom:** A client that solved the PoW challenge is still being challenged
on subsequent requests.

**Checklist:**

1. Confirm `challenge.secret` or `VEILGATE_SECRET` is set and is not the
   placeholder value.
2. Confirm `challenge.ttl_minutes` is long enough. A very short TTL (e.g.,
   `1`) means the token expires quickly.
3. Confirm the challenge cookie (`veilgate_challenge` by default) is being
   sent by the client on subsequent requests. Check with browser developer
   tools or:
   ```bash
   curl -v --cookie-jar /tmp/cookies.txt http://localhost:8080/__veilgate/verify
   curl -v --cookie /tmp/cookies.txt http://localhost:8080/
   ```
4. Confirm the request's score is not crossing `score_tarpit_threshold`. Tarpit
   decisions are not bypassed by a valid challenge token.

---

## Persistence queue drops occurring

**Symptom:** `veilgate_persist_queue_depth` is consistently near `queue_size`,
or `s.dropped` counter is increasing.

**Checklist:**

1. Increase `persist.queue_size`:
   ```yaml
   persist:
     queue_size: 8192
   ```
2. Check disk write latency. The flush goroutine commits every 1 second; if
   the disk is slow, commits may fall behind.
3. Check whether `persist.path` is on a network filesystem (NFS, SMB). SQLite
   WAL requires reliable byte-range locking. Move to local disk.
4. Monitor WAL file size. A growing WAL suggests commits are not completing:
   ```bash
   ls -lh ./data/events.db-wal
   ```

---

## ML signal not firing

**Symptom:** `veilgate_signal_hits_total{signal="ml_agent_score"}` is always
zero.

**Checklist:**

1. Confirm `rules/ml.yaml` has `enabled: true`.
2. Confirm `rules_dir` points to the directory containing `ml.yaml`:
   ```yaml
   rules_dir: "~/.veilgate/rules"
   ```
3. Confirm `min_confidence_to_fire` is not set too high. The default is `0.2`.
4. Confirm the ML scorer has received enough training observations. Check
   `veilgate_ml_fits_total` to verify the model has been fit at least once.
5. The ML model starts from a near-uniform prior. It requires several hundred
   labeled observations before the posterior probability meaningfully departs
   from `0.5`. Run in `observe` mode to accumulate observations.

---

## Hot reload not taking effect

**Symptom:** Changes to `rules/detector.yaml` or other rule files do not
change VeilGate's behavior.

**Checklist:**

1. Confirm `rules_dir` is set in `veilgate.yaml`:
   ```yaml
   rules_dir: "~/.veilgate/rules"
   ```
2. Confirm the file was written and saved. Some editors write to a temp file
   then rename; `fsnotify` handles rename events, but confirm the watcher
   received the event in logs.
3. Confirm the file parses correctly. A parse error causes the reload to be
   skipped (keeping the last good in-memory rules). Look for log entries at
   `warn` level from the watcher.
4. Note: `detect.score_challenge_threshold`, `detect.score_tarpit_threshold`,
   `listen`, `upstream`, `mode`, and `tls.*` require a restart. Only files
   inside `rules_dir` support hot reload.

---

## Related

- [Operations README](README.md)
- [Rollout Guide](rollout.md)
- [Security Hardening](security_hardening.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_proxy](../modules/veilgate_proxy.md)
- [Detector Signal Flow](../internals/detector_signal_flow.md)
