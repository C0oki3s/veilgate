# CDN Fingerprinting

When a CDN or reverse proxy terminates TLS before VeilGate, VeilGate cannot
compute JA3/JA4 fingerprints from the raw ClientHello. Most production CDNs
solve this by injecting the fingerprint as an HTTP header on the connection
from the CDN edge to your origin. VeilGate reads these headers via `cdn_mode`.

**On this page:**

- [Why CDN fingerprinting matters](#why-cdn-fingerprinting-matters)
- [How it works](#how-it-works)
- [Security model](#security-model)
- [Provider setup](#provider-setup)
  - [Cloudflare](#cloudflare)
  - [AWS CloudFront](#aws-cloudfront)
  - [Akamai](#akamai)
  - [Fastly](#fastly)
  - [Azure Front Door](#azure-front-door)
  - [Google Cloud CDN](#google-cloud-cdn)
  - [nginx](#nginx)
  - [HAProxy](#haproxy)
  - [Auto mode](#auto-mode)
- [What you lose vs self-TLS](#what-you-lose-vs-self-tls)
- [Verifying the setup](#verifying-the-setup)
- [Related](#related)

---

## Why CDN fingerprinting matters

Without CDN fingerprint forwarding, any JA4-dependent capability goes dark when
a CDN sits in front:

| Capability | No CDN mode | With `cdn_mode` |
|---|---|---|
| `tls_agent`, `tls_bot`, `tls_non_browser` signals | Silent (no JA4 data) | Active |
| `ja4_prefix` custom signal conditions | No matches | Full JA4 |
| ML JA4 feature column | Always blank | Populated |
| Recommender JA4 patterns | No candidates | Learns from traffic |
| Real client IP | CDN edge IP | CDN-provided IP header |

The `tls_non_browser` signal alone typically contributes 30–40 pts to a bot's
score. Without JA4 data, a scripted client using a non-browser TLS stack goes
undetected at the TLS layer and must be caught by HTTP signals alone.

---

## How it works

VeilGate wraps every inbound request in `FingerprintMiddleware` before it
reaches the scorer. The middleware:

1. Checks the local TLS fingerprint store (self-TLS path — zero overhead when
   VeilGate terminated the TLS itself).
2. If the store has no entry **and** the TCP source address is inside a
   `trusted_proxies` CIDR, checks CDN-specific fingerprint headers in priority
   order.
3. Sets `X-Veilgate-JA4` on the request before passing it to the scorer.

The scorer, ML pipeline, and recommender all read `X-Veilgate-JA4`. Setting
`cdn_mode` is the only change required — no other code paths need updating.

CDN real-IP headers (e.g. `CF-Connecting-IP`) are read by `resolveClientIP`
using the same trusted-proxy gate.

---

## Security model

**The only reliable defence against header forgery is network-level
isolation.** An attacker who can reach your origin IP directly (bypassing the
CDN) can forge any header.

VeilGate enforces a two-layer gate:

1. **`trusted_proxies` CIDR check** — fingerprint and real-IP headers are only
   honoured when the TCP connection's source IP is inside one of the declared
   CIDRs. A direct-connection forger cannot pass this gate.
2. **IP validation** — CDN real-IP header values are parsed with `net.ParseIP`;
   non-IP strings are rejected to prevent injection attacks.

Add a firewall rule or cloud security group that blocks port 443 from all IPs
except your CDN's published ranges. CDN-level mTLS (Authenticated Origin
Pulls for Cloudflare, AWS OAC for CloudFront) provides an additional layer.

**Fastly-Client-IP** is not trusted even in `cdn_mode: fastly` because Fastly
explicitly documents it as forgeable by clients. Use XFF or configure a custom
header in VCL.

---

## Provider setup

### Cloudflare

**JA4 header:** `cf-ja4` (requires **Enterprise Bot Management**)  
**Real-IP header:** `CF-Connecting-IP`

```yaml
detector:
  trusted_proxies:
    - 173.245.48.0/20
    - 103.21.244.0/22
    - 103.22.200.0/22
    - 103.31.4.0/22
    - 141.101.64.0/18
    - 108.162.192.0/18
    - 190.93.240.0/20
    - 188.114.96.0/20
    - 197.234.240.0/22
    - 198.41.128.0/17
    - 162.158.0.0/15
    - 104.16.0.0/13
    - 104.24.0.0/14
    - 172.64.0.0/13
    - 131.0.72.0/22
    - 2400:cb00::/32
    - 2606:4700::/32
    - 2803:f800::/32
    - 2405:b500::/32
    - 2405:8100::/32
    - 2a06:98c0::/29
    - 2c0f:f248::/32
  cdn_mode: cloudflare
```

> Keep the IP list current from [cloudflare.com/ips](https://www.cloudflare.com/ips/).

Without Enterprise Bot Management, `cf-ja4` is absent. VeilGate still recovers
the real client IP from `CF-Connecting-IP` and all HTTP-layer signals work.

See [Cloudflare + VeilGate setup](cloudflare-setup.md) for the full cert and
Authenticated Origin Pulls walkthrough.

---

### AWS CloudFront

**JA4 header:** `CloudFront-Viewer-JA4-Fingerprint` (opt-in origin request policy)  
**Real-IP header:** `CloudFront-Viewer-Address` (`{ip}:{port}` format; port is stripped automatically)

CloudFront strips all `CloudFront-*` headers from incoming client requests, so
these cannot be forged without bypassing CloudFront.

**Enable in CloudFront:**

1. Open your distribution → **Behaviors → Edit**.
2. Under **Origin request policy**, create or select a policy that includes
   **CloudFront-Viewer-JA4-Fingerprint** and **CloudFront-Viewer-Address**.
3. Attach the policy to your origin.

```yaml
detector:
  trusted_proxies:
    - 13.32.0.0/15       # CloudFront IP ranges (partial example)
    - 54.230.0.0/16      # use the full list from ip-ranges.amazonaws.com
  cdn_mode: cloudfront
```

Get the full CloudFront IP list:

```bash
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json \
  | jq -r '.prefixes[] | select(.service=="CLOUDFRONT") | .ip_prefix'
```

---

### Akamai

**JA4 header:** None — Akamai consumes fingerprints internally in Bot Manager
and does not forward them to origin.  
**Real-IP header:** `True-Client-IP` (requires "Send True Client IP Header" in
your property rules)

```yaml
detector:
  trusted_proxies:
    - 23.32.0.0/11       # Akamai edge ranges — use the authoritative list
  cdn_mode: akamai
```

With `cdn_mode: akamai`, VeilGate recovers the real client IP from
`True-Client-IP` but does not attempt to read a JA4 header. TLS-layer signals
(`tls_agent`, `tls_bot`) are not available. HTTP signals are unaffected.

---

### Fastly

**JA4 header:** None by default — requires VCL configuration.  
**Real-IP header:** `Fastly-Client-IP` is **not trusted** (Fastly documents it
as forgeable by clients). Use XFF.

**To enable JA4 forwarding via VCL:**

In your Fastly service, add to your `recv` subroutine:

```vcl
set bereq.http.X-JA4 = tls.client.ja4;
```

Then configure VeilGate to read `X-JA4`:

```yaml
detector:
  trusted_proxies:
    - 151.101.0.0/16    # Fastly edge ranges
  cdn_mode: fastly
```

> `cdn_mode: fastly` reads `X-JA4` if your VCL sets it, and falls back to XFF
> for real-IP resolution. `Fastly-Client-IP` is always ignored.

---

### Azure Front Door

**JA4 header:** `X-Azure-JA4-Fingerprint` (included by default on Standard/Premium as of 2025)  
**Real-IP header:** `X-Azure-ClientIP`

Azure Front Door strips all `X-Azure-*`, `X-FD-*`, and `X-Azure-Ref` headers
from client requests, so these cannot be forged at the application layer.

**Validate with X-Azure-FDID (recommended):**

Azure also injects `X-Azure-FDID` with your specific Front Door GUID. You can
add a probe-path or custom signal rule to reject requests missing the correct
FDID, preventing origin bypass from IPs that slip through network rules.

```yaml
detector:
  trusted_proxies:
    - 147.243.0.0/16    # Azure Front Door ranges — get from docs.microsoft.com
  cdn_mode: azure
```

---

### Google Cloud CDN

**JA4 header:** `X-JA4` — not set automatically; requires a custom header rule.  
**Real-IP header:** None standard; use XFF.

**Configure in GCP Load Balancer:**

In your backend service HTTP header policy, add a custom request header:

```
X-JA4: {tls_ja4_fingerprint}
```

Available GCP header variables also include `{tls_ja3_fingerprint}`,
`{client_ip_address}`, `{tls_version}`, and `{tls_cipher_suite}`.

```yaml
detector:
  trusted_proxies:
    - 34.64.0.0/10      # Google Cloud IP ranges
  cdn_mode: gcp
```

---

### nginx

**JA4 header:** `X-JA4` (requires a JA4 fingerprinting module)  
**Real-IP header:** `X-Real-IP`

**Modules:**

- [`nginx-ssl-fingerprint`](https://github.com/phuslu/nginx-ssl-fingerprint) (passive peek, like VeilGate)
- `ngx_ssl_fingerprint_module` (OpenResty)

**nginx config:**

```nginx
# After loading the fingerprint module:
proxy_set_header X-JA4      $ssl_ja4;
proxy_set_header X-Real-IP  $remote_addr;
```

```yaml
detector:
  trusted_proxies:
    - 192.168.0.0/16    # nginx is typically on the same network
  cdn_mode: nginx
```

---

### HAProxy

**JA4 header:** `X-SSL-JA3N` (via `haproxy-ja3n-fingerprint` Lua plugin)  
**Real-IP header:** `X-Real-IP`

**HAProxy config:**

```
frontend https_in
    bind :443 ssl crt /etc/ssl/cert.pem
    # Require the Lua plugin for JA3N; set header for origin
    http-request set-header X-SSL-JA3N %[ssl_c_der,lua.ja3n_fingerprint]
    http-request set-header X-Real-IP  %[src]
    default_backend veilgate
```

```yaml
detector:
  trusted_proxies:
    - 10.0.0.0/8
  cdn_mode: haproxy
```

---

### Auto mode

`cdn_mode: auto` tries all known CDN fingerprint headers in priority order:

1. `cf-ja4` (Cloudflare)
2. `cf-ja3-hash` (Cloudflare JA3 fallback)
3. `X-Azure-JA4-Fingerprint` (Azure Front Door)
4. `CloudFront-Viewer-JA4-Fingerprint` (CloudFront)
5. `CloudFront-Viewer-JA3-Fingerprint` (CloudFront JA3 fallback)
6. `X-JA4` (GCP / nginx / HAProxy)
7. `X-JA3-Hash` (nginx / HAProxy fallback)
8. `X-SSL-JA3N` (HAProxy Lua)

Use `auto` when you have mixed infrastructure or are not sure which provider
sets which header. It is slightly less efficient than a named mode but adds no
meaningful latency.

Real-IP resolution is not available in `auto` mode because VeilGate cannot
determine which provider's real-IP header is authoritative. XFF is still
processed normally via `trusted_proxies`.

---

## What you lose vs self-TLS

| Aspect | Self-TLS | CDN mode |
|---|---|---|
| Fingerprint source | Raw ClientHello (unforgeable) | CDN-injected header (forgeable if origin IP exposed) |
| Fingerprint accuracy | 100% — exact ClientHello bytes | Depends on CDN accuracy; most providers are accurate |
| `h2_agent`, `h2_bot` signals | Available | Not available (HTTP/2 framing not forwarded) |
| `tls_non_browser` | Available | Available when CDN forwards JA4 |
| Real client IP | TCP source (unforgeable) | CDN header (requires `trusted_proxies` gate) |
| DDoS protection | VeilGate only | CDN DDoS layer + VeilGate |
| TLS complexity | VeilGate manages cert + renewal | CDN manages cert; simpler origin TLS |

For most deployments behind a major CDN, the CDN's DDoS protection and global
PoP network outweigh the fingerprint quality trade-off. HTTP-layer signals,
IP reputation, and ML detection remain fully effective in all CDN topologies.

---

## Verifying the setup

**Check that CDN mode is active:**

```bash
# Look for the CDN mode in the startup log.
journalctl -u veilgate | grep -i cdn
```

**Check JA4 is being injected:**

```bash
# Run a test request through your CDN and check the event log.
# In the admin dashboard: Events → filter by the test IP → check the ja4 column.
# Or query the events DB directly:
sqlite3 ~/.veilgate/events.db \
  "SELECT ja4, path, decision FROM events ORDER BY ts DESC LIMIT 5;"
```

**Check real client IP is recovered:**

```bash
# Your real IP should appear in logs, not the CDN edge IP.
journalctl -u veilgate -n 10 | grep remote_ip
```

**Test forgery prevention:**

```bash
# Direct connection (not through CDN) — header should be ignored.
curl -sk https://<your-origin-ip>/ \
  -H "cf-ja4: t13d....." \
  -H "CF-Connecting-IP: 1.2.3.4" \
  -v 2>&1 | grep -i ja4
# VeilGate ignores the headers because the source IP is not in trusted_proxies.
```

---

## Related

- [Cloudflare + VeilGate setup](cloudflare-setup.md) — full Cloudflare walkthrough
- [TLS fingerprinting](../functionalities/tls-fingerprinting.md) — how fingerprinting works
- [Configuration: `detector.cdn_mode`](../config/detector.md#cdn_mode)
- [Custom signals: `ja4_prefix`](../functionalities/detection-signals.md) — block specific TLS stacks
