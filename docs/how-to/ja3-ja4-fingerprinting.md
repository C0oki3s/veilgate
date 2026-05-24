# JA3 / JA4 TLS Fingerprinting

TLS fingerprinting is one of the strongest signals in VeilGate's detector
stack. A human visiting your site in Chrome produces a very different TLS
ClientHello than a Python `requests` script or a nuclei scanner — and that
difference is measurable before a single byte of HTTP is exchanged.

**On this page:**

- [What JA3 and JA4 are](#what-ja3-and-ja4-are)
- [What signals fingerprinting adds to the detector](#what-signals-fingerprinting-adds-to-the-detector)
- [Requirement: VeilGate must terminate TLS](#requirement-veilgate-must-terminate-tls)
- [Enable TLS termination](#enable-tls-termination)
- [Verify fingerprinting is active](#verify-fingerprinting-is-active)
- [Read fingerprints from live traffic](#read-fingerprints-from-live-traffic)
- [Extend the fingerprint database](#extend-the-fingerprint-database)
- [HTTP/2 fingerprinting alongside TLS](#http2-fingerprinting-alongside-tls)
- [What you lose behind a CDN](#what-you-lose-behind-a-cdn)
- [Tuning and false positives](#tuning-and-false-positives)

---

## What JA3 and JA4 are

When a TLS client opens a connection it sends a **ClientHello** message
advertising its supported cipher suites, TLS extensions, elliptic curves, and
compression methods. The server has no influence over this advertisement — it
comes from the client library or browser.

**JA3** (2017) hashes a subset of those fields into an MD5 fingerprint:

```
JA3 = MD5(TLSVersion, CipherSuites, Extensions, EllipticCurves, ECPointFormats)
```

Example JA3: `e7d705a3286e19ea42f587b344ee6865` (curl 7.85)

**JA4** (2023) improves on JA3 with a structured, human-readable format that
is more stable across library versions and easier to analyse:

```
JA4 = t<protocol><num_ciphers><num_extensions><alpn>_<cipher_hash>_<extension_hash>
```

Example JA4: `t13d1517h2_8daaf6152771_b186095e22b6` (python-httpx)

The JA4 **prefix** (`t13d1517h2` in the example) covers the TLS version,
number of ciphers, number of extensions, and ALPN. It is stable across minor
library version bumps, making it the right tool for broad category matching
("this is a Python HTTP library") even when the exact full hash changes.

### Why fingerprints are hard to spoof

Spoofing requires the attacker to reproduce the exact cipher suite list, TLS
extension set, ordering, and elliptic curve preferences of a real browser.
Most HTTP libraries do not expose this level of control. Tools like `curl` and
`python-requests` use OpenSSL or GnuTLS defaults that differ from browser
fingerprints in a dozen observable dimensions simultaneously.

---

## What signals fingerprinting adds to the detector

When VeilGate recognises a client's JA3 or JA4:

| Signal | Meaning | Score added |
|---|---|---|
| `tls_agent` | Fingerprint matches a known HTTP library or scanner (high confidence ≥ 80) | +45 |
| `tls_agent` | Fingerprint matches a known HTTP library or scanner (lower confidence) | +30 |
| `tls_bot` | Fingerprint matches a known bot | +25 |
| `tls_non_browser` | JA4 prefix does not match any known browser entry | +20 |

These stack with HTTP-layer signals. A request that hits `tls_agent` (+45)
plus `suspicious_user_agent` (+30) plus `recon_path` (+25) scores 100 — well
into tarpit territory — without any body inspection or ML involvement.

In `observe` mode all signals are recorded but nothing is blocked. Check
metric counters to see how much fingerprint-driven scoring is happening on your
traffic before enabling enforcement.

```bash
curl -s http://127.0.0.1:9090/metrics | grep 'veilgate_signal_hits_total.*tls'
```

---

## Requirement: VeilGate must terminate TLS

VeilGate peeks at the raw TLS record **before** Go's stdlib consumes it. If
any intermediate hop — nginx, Envoy, Cloudflare, an AWS ALB — terminates TLS
first, VeilGate receives a plaintext connection and has nothing to parse.

```
# Fingerprinting works:
Browser ──TLS──► VeilGate ──plaintext──► upstream

# Fingerprinting does NOT work:
Browser ──TLS──► nginx/CDN ──TLS──► VeilGate ──plaintext──► upstream
                                    ↑ VeilGate sees its own TLS session,
                                      not the browser's ClientHello
```

If you are behind Cloudflare or another CDN, see
[What you lose behind a CDN](#what-you-lose-behind-a-cdn) below.

---

## Enable TLS termination

Follow [TLS setup](tls-setup.md) to place a cert at `/etc/veilgate/tls/` and
configure VeilGate to use it. The minimum config:

```yaml
# /etc/veilgate/veilgate.yaml
listen: ":443"
upstream: "http://127.0.0.1:3000"
rules_dir: "~veilgate/.veilgate/rules"
mode: "challenge"

tls:
  enabled:   true
  cert_file: /etc/veilgate/tls/cert.pem
  key_file:  /etc/veilgate/tls/key.pem
```

```bash
sudo systemctl restart veilgate
```

The fingerprint database is loaded from
`~veilgate/.veilgate/rules/tls_fingerprints/` (community rules) and
`~veilgate/.veilgate/rules/tls_fingerprints.yaml` (your local overrides). Both
hot-reload — no restart needed after editing them.

---

## Verify fingerprinting is active

Send a test HTTPS request and check the metrics:

```bash
# 1. Hit the proxy over HTTPS.
curl -k https://localhost:443/

# 2. Check the fingerprint counter incremented.
curl -s http://127.0.0.1:9090/metrics | grep tls_fingerprints_total
# Expect: veilgate_tls_fingerprints_total{result="..."} <non-zero>

# 3. Send a request from a known agent library and check for the signal.
python3 -c "import urllib.request; urllib.request.urlopen('https://localhost:443/', context=__import__('ssl')._create_unverified_context())"
curl -s http://127.0.0.1:9090/metrics | grep 'signal_hits_total.*tls_agent'
```

If the counter stays at zero:

- Check `tls.enabled: true` is in your config.
- Confirm clients are actually connecting over `https://` — HTTP requests skip the TLS peek.
- Confirm nothing else is terminating TLS before VeilGate (check with
  `ss -tlnp | grep 443`).

---

## Read fingerprints from live traffic

After running in `observe` mode for a day or more, query the event store to
see what JA4s are hitting your API:

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT ja4, ja3, user_agent, COUNT(*) AS n
     FROM events
     WHERE ja4 != ''
     GROUP BY ja4
     ORDER BY n DESC
     LIMIT 30;"
```

For each high-volume JA4 you do not recognise:

1. Cross-reference the `user_agent` column — the library often identifies itself.
2. Look the JA4 up at [https://ja4db.com](https://ja4db.com) for community attribution.
3. Decide the category and add it to your local override file (see below).

To see only fingerprints that are not in your database (unclassified):

```bash
sudo -u veilgate sqlite3 /var/lib/veilgate/events.db \
  "SELECT ja4, user_agent, COUNT(*) AS n
     FROM events
     WHERE ja4 != ''
       AND tls_label = ''
     GROUP BY ja4
     ORDER BY n DESC
     LIMIT 20;"
```

---

## Extend the fingerprint database

The community rules ship with fingerprints for common libraries. You will
encounter clients not yet in the database. Add them to a local override file
that the community rules never touch:

```bash
sudo -u veilgate tee -a ~veilgate/.veilgate/rules/tls_fingerprints.yaml
```

File format:

```yaml
# Exact JA4 matches — highest confidence, use for stable library fingerprints.
ja4_exact:
  - hash: t13d1715h2_acb858a92679_5e10d2a5810e
    label: chrome-130
    category: browser
    confidence: 100

  - hash: t13d1517h2_8daaf6152771_b186095e22b6
    label: python-httpx-0.27
    category: agent
    confidence: 95

# JA4 prefix matches — use when the exact hash drifts across minor versions.
# The prefix covers TLS version + cipher count + extension count + ALPN.
ja4_prefix:
  - prefix: t13d1715h2
    label: chrome-stable
    category: browser
    confidence: 90

  - prefix: t13d1517h2
    label: python-httpx
    category: agent
    confidence: 85

  - prefix: t13d301h2
    label: go-net-http
    category: agent
    confidence: 85

# Legacy JA3 MD5 exact matches.
# Use for older clients not yet fingerprinted in JA4.
ja3_exact:
  - hash: e7d705a3286e19ea42f587b344ee6865
    label: curl-7.85
    category: agent
    confidence: 90

  - hash: 19e29534fd49dd27d09234e639c4057e
    label: nikto
    category: scanner
    confidence: 95
```

### Category values and their effect on scoring

| `category` | When to use | Signal raised | Points |
|---|---|---|---|
| `browser` | Known real browser | none | 0 |
| `agent` | HTTP client library | `tls_agent` | +30 to +45 |
| `scanner` | Security scanner | `tls_agent` | +30 to +45 |
| `bot` | Known crawler/bot | `tls_bot` | +25 |
| `unknown` | Cannot classify | `tls_non_browser` | +20 |

Set `confidence` to the percentage certainty the label is correct. Confidence
below 80 drops `tls_agent` from +45 to +30 points.

The file hot-reloads approximately 500 ms after you save. Watch the log:

```bash
journalctl -u veilgate -f | grep "tls_fingerprints"
# Expect: rules reloaded file=tls_fingerprints.yaml
```

### Known JA4 prefixes for common libraries

| Prefix | Library |
|---|---|
| `t13d1715h2` | Chrome (recent stable) |
| `t13d1516h2` | Firefox (recent stable) |
| `t13d1517h2` | python-httpx |
| `t13d191h2` | python-requests / urllib3 |
| `t13d301h2` | Go `net/http` |
| `t13d201h1` | curl (OpenSSL) |
| `t13d881h2` | Java HttpClient |
| `t13d360h2` | Node.js fetch / undici |

Prefixes drift with TLS library updates. Verify against live traffic using the
query above rather than trusting this table alone.

---

## HTTP/2 fingerprinting alongside TLS

When clients use HTTP/2, VeilGate also captures the **SETTINGS frame** sent
immediately after the TLS handshake. The SETTINGS values (initial window size,
max frame size, header table size) and pseudo-header order are characteristic
of different HTTP stacks and complement the TLS fingerprint.

HTTP/2 fingerprinting is automatic when TLS is enabled and the client
negotiates `h2` via ALPN. No additional config is required.

| Signal | Meaning | Points |
|---|---|---|
| `h2_agent` | H2 SETTINGS match a known agent or scanner | +22 to +35 |
| `h2_bot` | H2 SETTINGS match a known bot | +18 |
| `h2_non_browser` | SETTINGS look library-shaped | +15 |

Check H2 fingerprint metrics:

```bash
curl -s http://127.0.0.1:9090/metrics | grep 'signal_hits_total.*h2'

# Send an H2 request to generate a sample.
curl -k --http2 https://localhost:443/
```

---

## What you lose behind a CDN

When Cloudflare, Fastly, Akamai, or any CDN terminates TLS before VeilGate,
the signals affected are:

| Signal | Available | Notes |
|---|---|---|
| `tls_agent` | No | Cloudflare's ClientHello is classified, not the client's |
| `tls_bot` | No | Same reason |
| `tls_non_browser` | No | Same reason |
| `h2_agent` | No | CDN repackages the H2 connection |
| `h2_bot` | No | Same reason |
| `h2_non_browser` | No | Same reason |
| All HTTP-layer signals | Yes | User-Agent, path, headers, etc. are unaffected |
| IP reputation | Yes | Requires `trusted_proxies` set to Cloudflare CIDRs |
| ML / behavioral | Yes | Pattern-based, not fingerprint-based |

If fingerprinting is important to you and you are also using Cloudflare, one
option is to put VeilGate between Cloudflare and your origin with a second TLS
session — but Cloudflare will present its own fingerprint, not the client's.
The only way to get real client fingerprints is to let VeilGate be the first
TLS terminator. See [Cloudflare + VeilGate setup](cloudflare-setup.md) for the
full topology options and trade-offs.

---

## Tuning and false positives

### "My mobile app is being fingerprinted as an agent"

Mobile apps using native TLS stacks (iOS `URLSession`, Android `OkHttp`) have
fingerprints that differ from browser stacks but are not malicious. Add them as
`category: browser` with your measured confidence:

```yaml
ja4_prefix:
  - prefix: t13d391h2     # OkHttp on Android
    label: okhttp-android
    category: browser
    confidence: 85
```

Check which prefix your app produces by querying the event store after a test
run from the app.

### "Legitimate partners are being scored too high"

Partners running server-side SDKs will show agent fingerprints. Two options:

1. Add them to `detector.trusted_ips` if their IP range is stable.
2. Issue them an HMAC client credential so they bypass the PoW tier
   entirely — see [Setup: server-to-server](setup-server-to-server.md).

### "I want to score a specific fingerprint differently from its category"

The database does not support per-entry score overrides — scoring is driven by
`(category, confidence)`. To tune scoring for a specific client:

1. Add it as `category: browser` to suppress all TLS signals.
2. Or add it to `detector.trusted_ips` to suppress all signals for those IPs.
3. Or adjust the global threshold (`detector.score_challenge_threshold`) if you
   want a blanket change.

---

## Related

- [TLS setup](tls-setup.md) — cert creation, Cloudflare Origin CA, AD cert import
- [Cloudflare + VeilGate setup](cloudflare-setup.md) — topology, TLS modes, trade-offs
- [Configuration reference: `rules/tls_fingerprints.yaml`](../config/rules/tls-fingerprints.md)
- [Configuration reference: `tls:`](../config/tls.md)
- [Detection signals](../functionalities/detection-signals.md)
