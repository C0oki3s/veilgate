# Cloudflare + VeilGate Setup

Cloudflare sits in front of many production APIs. This guide explains how to
configure Cloudflare and VeilGate together correctly, what you gain and what
you lose at each SSL/TLS mode, how to issue and install an Origin CA cert, and
how to lock down your origin so only Cloudflare can reach it.

**On this page:**

- [How traffic flows](#how-traffic-flows)
- [SSL/TLS mode: which to pick](#ssltls-mode-which-to-pick)
- [Step 1 — Issue a Cloudflare Origin CA cert](#step-1--issue-a-cloudflare-origin-ca-cert)
- [Step 2 — Install the cert on your VeilGate server](#step-2--install-the-cert-on-your-veilgate-server)
- [Step 3 — Configure VeilGate](#step-3--configure-veilgate)
- [Step 4 — Set Cloudflare to Full (Strict)](#step-4--set-cloudflare-to-full-strict)
- [Step 5 — Trust Cloudflare IPs in VeilGate](#step-5--trust-cloudflare-ips-in-veilgate)
- [Step 6 — Lock the origin with Authenticated Origin Pulls](#step-6--lock-the-origin-with-authenticated-origin-pulls)
- [JA3/JA4 fingerprinting trade-off](#ja3ja4-fingerprinting-trade-off)
- [Cloudflare Turnstile as a complement](#cloudflare-turnstile-as-a-complement)
- [Verify the full setup](#verify-the-full-setup)
- [Common pitfalls](#common-pitfalls)

---

## How traffic flows

```
Browser ──TLS──► Cloudflare edge ──TLS──► VeilGate ──plaintext──► your API
                 (terminates               (terminates the
                  client TLS)               Cloudflare→origin
                                            TLS session)
```

Cloudflare terminates the browser's TLS session at its edge. It opens a
separate TLS session to your origin (VeilGate). This means:

- **VeilGate sees Cloudflare's IP, not the client's IP.** Fix this with
  `trusted_proxies` (Step 5).
- **VeilGate sees Cloudflare's ClientHello, not the browser's.** JA3/JA4
  fingerprints reflect Cloudflare's TLS stack, not the real client.
  See [JA3/JA4 trade-off](#ja3ja4-fingerprinting-trade-off).

---

## SSL/TLS mode: which to pick

Configure this in the Cloudflare dashboard under **SSL/TLS → Overview**.

| Mode | What it does | Use for VeilGate? |
|---|---|---|
| **Off** | No TLS anywhere. HTTP only. | Never |
| **Flexible** | Cloudflare↔browser is HTTPS; Cloudflare↔origin is HTTP. Origin cert not needed. | No — your origin traffic is unencrypted |
| **Full** | Both connections are TLS. Origin cert can be self-signed. | Acceptable for dev/lab only |
| **Full (Strict)** | Both connections are TLS. Origin cert must be valid (Cloudflare CA or public CA). | Yes — use this in production |

Use **Full (Strict)**. It ensures Cloudflare verifies your origin cert before
forwarding traffic, preventing downgrade attacks or MITM between Cloudflare and
your server.

---

## Step 1 — Issue a Cloudflare Origin CA cert

Cloudflare Origin CA certs are trusted by Cloudflare's edge but not by public
browsers. They are perfect for the Cloudflare-to-origin connection.

1. Log in to [dash.cloudflare.com](https://dash.cloudflare.com) and select
   your domain.
2. Go to **SSL/TLS → Origin Server**.
3. Click **Create Certificate**.
4. Choose **Let Cloudflare generate a private key and a CSR**.
5. Under **Hostnames**, add:
   - `api.example.com`
   - Optionally `*.example.com` (wildcard, covers all subdomains)
6. Choose a validity period. **15 years** is fine for an Origin CA cert —
   unlike public CA certs, there is no benefit to short expiry here because
   this cert is only trusted by Cloudflare.
7. Click **Create**.

Cloudflare displays the **Origin Certificate** and **Private Key** once.
Copy both before closing the dialog — the private key is not stored by
Cloudflare and cannot be retrieved later.

---

## Step 2 — Install the cert on your VeilGate server

SSH into your API server and paste the cert and key:

```bash
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls

# Paste the Origin Certificate Cloudflare showed you.
sudo tee /etc/veilgate/tls/cert.pem <<'EOF'
-----BEGIN CERTIFICATE-----
<paste Cloudflare Origin Certificate here>
-----END CERTIFICATE-----
EOF

# Paste the Private Key Cloudflare showed you.
sudo tee /etc/veilgate/tls/key.pem <<'EOF'
-----BEGIN PRIVATE KEY-----
<paste private key here>
-----END PRIVATE KEY-----
EOF

sudo chown root:veilgate /etc/veilgate/tls/*.pem
sudo chmod 0640 /etc/veilgate/tls/cert.pem
sudo chmod 0640 /etc/veilgate/tls/key.pem
```

Verify the cert is valid and the key matches:

```bash
openssl x509 -noout -text -in /etc/veilgate/tls/cert.pem \
  | grep -E "Subject:|Issuer:|Not After"

# Modulus hashes must match.
openssl x509 -noout -modulus -in /etc/veilgate/tls/cert.pem | md5sum
openssl rsa  -noout -modulus -in /etc/veilgate/tls/key.pem  | md5sum
```

---

## Step 3 — Configure VeilGate

In `/etc/veilgate/veilgate.yaml`:

```yaml
listen: ":443"
upstream: "http://127.0.0.1:3000"
rules_dir: "~veilgate/.veilgate/rules"
mode: "challenge"

tls:
  enabled:   true
  cert_file: /etc/veilgate/tls/cert.pem
  key_file:  /etc/veilgate/tls/key.pem

# Tell VeilGate that requests arriving from Cloudflare IPs have already
# been through a trusted proxy. VeilGate will read the real client IP
# from CF-Connecting-IP or X-Forwarded-For instead of the source IP.
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
    # IPv6
    - 2400:cb00::/32
    - 2606:4700::/32
    - 2803:f800::/32
    - 2405:b500::/32
    - 2405:8100::/32
    - 2a06:98c0::/29
    - 2c0f:f248::/32
```

> The Cloudflare IP ranges above are current as of the documentation date.
> Keep them up to date from [cloudflare.com/ips](https://www.cloudflare.com/ips/).
> Cloudflare also publishes machine-readable lists at
> `https://www.cloudflare.com/ips-v4` and
> `https://www.cloudflare.com/ips-v6`.

Grant VeilGate permission to bind port 443 and restart:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/veilgate
sudo systemctl edit veilgate
# Add: AmbientCapabilities=CAP_NET_BIND_SERVICE
sudo systemctl daemon-reload
sudo systemctl restart veilgate
journalctl -u veilgate -n 20
# Expect: tls listener started addr=:443
```

---

## Step 4 — Set Cloudflare to Full (Strict)

In the Cloudflare dashboard:

1. Go to **SSL/TLS → Overview**.
2. Select **Full (Strict)**.

Cloudflare now verifies your Origin CA cert before connecting to your server.
Any request that reaches your server without going through Cloudflare will
either be blocked (if you complete Step 6) or will arrive without the
`CF-Connecting-IP` header that VeilGate uses for real IP attribution.

---

## Step 5 — Trust Cloudflare IPs in VeilGate

The `detector.trusted_proxies` block (added in Step 3) tells VeilGate two
things:

1. Requests from these CIDRs arrive via a trusted proxy.
2. Read the real client IP from the `CF-Connecting-IP` header (Cloudflare sets
   this) or `X-Forwarded-For` rather than the TCP source address.

Without this, VeilGate sees all traffic as coming from Cloudflare edge IPs and
cannot do effective IP-based scoring or rate-limiting.

Verify the header is being received:

```bash
curl -s http://127.0.0.1:9090/metrics | grep veilgate_real_ip
# Should show your real external IP being counted, not Cloudflare IPs.
```

---

## Step 6 — Lock the origin with Authenticated Origin Pulls

By default, anyone who discovers your server's IP can bypass Cloudflare
entirely and hit VeilGate directly — without Cloudflare's bot management,
DDoS protection, or the `CF-Connecting-IP` header.

Cloudflare's **Authenticated Origin Pulls** (mTLS) fixes this: Cloudflare
sends a client certificate with every request to your origin, and your origin
rejects connections that do not present it.

### Enable Authenticated Origin Pulls in Cloudflare

1. Go to **SSL/TLS → Origin Server**.
2. Scroll to **Authenticated Origin Pulls** and toggle it **On**.

### Download Cloudflare's client CA cert

Cloudflare signs its origin pull cert with a specific CA:

```bash
curl -o /etc/veilgate/tls/cloudflare-origin-pull-ca.pem \
  https://developers.cloudflare.com/ssl/static/authenticated_origin_pull_ca.pem
```

Verify the download:

```bash
openssl x509 -noout -text \
  -in /etc/veilgate/tls/cloudflare-origin-pull-ca.pem \
  | grep -E "Subject:|Issuer:|Not After"
# Expect: CN=Cloudflare CA
```

### Configure VeilGate to require the client cert

In `/etc/veilgate/veilgate.yaml`:

```yaml
tls:
  enabled:   true
  cert_file: /etc/veilgate/tls/cert.pem
  key_file:  /etc/veilgate/tls/key.pem
  client_ca: /etc/veilgate/tls/cloudflare-origin-pull-ca.pem
```

Restart VeilGate. After this, any direct connection to your server that does
not present the Cloudflare client cert will be rejected at the TLS handshake
level.

### Firewall as a belt-and-suspenders measure

Even with mTLS, restrict port 443 inbound to Cloudflare IPs at the firewall:

**UFW (Ubuntu/Debian):**

```bash
sudo ufw default deny incoming
sudo ufw allow ssh

# Cloudflare IPv4 ranges (add all from cloudflare.com/ips-v4).
for cidr in \
  173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
  141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 \
  197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 \
  104.24.0.0/14 172.64.0.0/13 131.0.72.0/22; do
  sudo ufw allow from "$cidr" to any port 443
done

sudo ufw enable
```

**firewalld (RHEL/Rocky/Alma):**

```bash
# Create a Cloudflare zone.
sudo firewall-cmd --permanent --new-zone=cloudflare

for cidr in \
  173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 \
  141.101.64.0/18 108.162.192.0/18; do
  sudo firewall-cmd --permanent --zone=cloudflare --add-source="$cidr"
done

sudo firewall-cmd --permanent --zone=cloudflare --add-service=https
sudo firewall-cmd --permanent --zone=public --remove-service=https
sudo firewall-cmd --reload
```

---

## JA3/JA4 fingerprinting with Cloudflare

Because Cloudflare terminates TLS at the edge, VeilGate never sees the raw
browser ClientHello directly. However, Cloudflare can forward the client's JA4
fingerprint as an HTTP header, and VeilGate reads it securely via `cdn_mode`.

### Enable CDN mode

Add `cdn_mode: cloudflare` to the `detector:` block (the `trusted_proxies` list
from Step 5 is the required security gate — it gates header trust to Cloudflare
IPs only):

```yaml
detector:
  trusted_proxies:
    - 173.245.48.0/20
    # ... full list from cloudflare.com/ips
  cdn_mode: cloudflare
```

Restart VeilGate. After this:

- `X-Veilgate-JA4` is injected from `cf-ja4` before every request reaches the
  scorer.
- `tls_agent`, `tls_bot`, `tls_non_browser`, and `ja4_prefix` custom signals
  become active for traffic where Cloudflare forwards the fingerprint.
- Real client IP is recovered from `CF-Connecting-IP`.

### Enterprise Bot Management requirement

`cf-ja4` is only forwarded when **Cloudflare Enterprise Bot Management** is
enabled on your zone. Without it, `cdn_mode: cloudflare` still recovers the
real client IP, and all HTTP-layer and IP reputation signals remain effective.

If you do not have Enterprise Bot Management, the HTTP-layer + IP reputation +
ML signals are sufficient for most deployments, and Cloudflare's DDoS
protection is worth that trade-off.

### Direct-bypass topology

If JA4 fingerprint quality is the top priority and Enterprise Bot Management is
not available, the alternative is to disable Cloudflare proxy mode (grey cloud)
and let VeilGate terminate TLS directly. In this topology fingerprints are
computed from the raw ClientHello and are unforgeable.

See [CDN fingerprinting how-to](cdn-fingerprinting.md) for the full provider
matrix and security model.

---

## Cloudflare Turnstile as a complement

Cloudflare Turnstile is a CAPTCHA alternative that runs in the browser and
issues a short-lived token. If you already use Turnstile for human verification
at a form or login, you can configure VeilGate's bearer verifier to accept
verified Turnstile tokens, letting proven-human requests bypass the PoW tier.

This is a complementary strategy, not a replacement for VeilGate's detection:
Turnstile runs at pages you configure; VeilGate covers all API traffic including
paths Turnstile never sees.

---

## Verify the full setup

**Check Cloudflare is connecting over TLS:**

```bash
# On your server, watch the TLS handshake log.
journalctl -u veilgate -f | grep tls
# Should show TLS connections from Cloudflare IPs.
```

**Check the real client IP is being recovered:**

```bash
# From your own machine, hit the API through Cloudflare.
curl -si https://api.example.com/api/health \
  -H "User-Agent: python-requests/2.31.0"

# On the server, check the scored IP is your real IP, not a Cloudflare IP.
journalctl -u veilgate -n 5 | grep "remote_ip"
```

**Check authenticated origin pulls are enforced:**

```bash
# This should be rejected — no Cloudflare client cert presented.
curl -sk https://<your-server-ip>/ -v 2>&1 | grep -E "alert|handshake|SSL"
# Expect: TLS handshake failure or connection reset.
```

**Check end-to-end challenge flow:**

```bash
curl -si https://api.example.com/api/health \
  -H "Sec-Fetch-Dest: empty" \
  -H "User-Agent: python-requests/2.31.0"
# Expect:
#   HTTP/2 401
#   content-type: application/json
#   {"error":"challenge_required",...}
```

---

## Common pitfalls

**"VeilGate is logging Cloudflare IPs as client IPs"**

`detector.trusted_proxies` is not set or the Cloudflare CIDR list is out of
date. Update it from [cloudflare.com/ips](https://www.cloudflare.com/ips) and
restart VeilGate.

**"Full (Strict) gives a 526 error from Cloudflare"**

Error 526 means Cloudflare could not validate your origin cert. Check:
- The cert in `/etc/veilgate/tls/cert.pem` is the full chain (cert + any
  intermediates), not just the leaf.
- The cert has not expired: `openssl x509 -noout -dates -in /etc/veilgate/tls/cert.pem`
- VeilGate is actually running and listening on port 443:
  `ss -tlnp | grep 443`

**"Authenticated Origin Pulls is on but direct requests still reach VeilGate"**

Cloudflare's mTLS only works when Cloudflare's edge connects to your origin.
If your origin IP is reachable directly, a TLS client without the client cert
still completes a regular TLS handshake. Ensure `tls.client_ca` is configured
in VeilGate so it requires the client cert, and add the firewall rules.

**"JA3/JA4 metrics stay at zero"**

If `cdn_mode` is not set: expected — VeilGate sees Cloudflare's ClientHello,
not the real client's. Set `cdn_mode: cloudflare` and ensure `trusted_proxies`
includes all Cloudflare CIDRs (see Step 5).

If `cdn_mode: cloudflare` is set: `cf-ja4` requires Cloudflare Enterprise Bot
Management. Without that add-on the header is not forwarded and JA4 signals
will not fire. HTTP and IP signals are unaffected.

---

## Related

- [TLS setup](tls-setup.md) — cert creation, enterprise CA, permissions
- [JA3/JA4 fingerprinting setup](ja3-ja4-fingerprinting.md) — what the signals mean, how to extend the database
- [CDN fingerprinting how-to](cdn-fingerprinting.md) — full provider matrix, security model, Fastly VCL
- [Setup: SPA on CDN](setup-spa-cdn.md) — Vercel/Netlify/CloudFront deployment
- [Configuration reference: `tls:`](../config/tls.md)
- [Configuration reference: `detector:`](../config/detector.md)
