# `verifiers:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `verifiers:`
> **Reload:** restart required for the block itself; client secrets
> hot-reload on file mtime change.

Configures the **alternate-authenticator chain** that VeilGate
consults before falling back to the score system. Verifiers cover
clients that can't (or shouldn't have to) solve a JavaScript
proof-of-work challenge: server-to-server traffic, native mobile
apps, internal microservices, and partner integrations.

The chain is **short-circuit**: the first verifier that accepts a
request flips its decision from Challenge to Real, and processing
moves on. If no verifier accepts, the request falls through to the
existing PoW cookie check, and then to the score system if that also
declines.

**On this page:**

- [Why a verifier chain](#why-a-verifier-chain)
- [Tarpit override](#tarpit-override)
- [`hmac:`](#hmac)
- [`bearer:`](#bearer)
- [`cookies:`](#cookies)
- [`headers:`](#headers)
- [Example](#example)
- [Related](#related)

## Why a verifier chain

The PoW challenge tier is designed for **anonymous browser traffic**.
It works well for that population - humans solve it transparently in
under a second, and the cheap stateless tooling that VeilGate exists
to filter never solves it at all. But there's a long tail of
legitimate non-browser clients:

- An iOS/Android app calling your API. No JS runtime; can't solve the
  PoW.
- An internal microservice (`payment-service`) calling another
  internal microservice (`fraud-service`). Server-to-server; no
  user-agent context.
- A partner's webhook receiver POSTing to your `/api/webhooks/...`
  endpoint. They have a shared secret with you, not a browser.
- A scheduled job (`cron`-driven cleanup, batch processing). No
  interactivity.

Each of these has its own credential - an API key, a signed JWT, a
shared HMAC secret, or an mTLS client cert. VeilGate does not force you
to pick one universal scheme; it provides a chain so you can stack
multiple verifiers and let the operator decide which credential
applies where.

The chain ships four verifier blocks: `hmac:`, `bearer:`, `cookies:`, and
`headers:`. All are documented below.

## Tarpit override

The single most important invariant: **verifier acceptance never
bypasses tarpit**. If the behavioral score for a request lands >=
`detector.score_tarpit_threshold` (default 70), the request is
tarpitted regardless of how many verifiers accepted it.

The reason is straightforward. A leaked HMAC secret, a stolen JWT, or
a compromised mTLS key shouldn't be a full bypass - at that point the
operator is at the mercy of whatever credential rotation cadence they
have. The score system is the failsafe: if the *behavior* of the
attacker shifts into honeypot probing or injection-marker territory,
they get tarpitted regardless of credential. That puts a hard ceiling
on the damage a leaked secret can do.

The flip side: **verifier acceptance does demote Challenge to Real**.
A request the HMAC verifier accepted with a valid signature, whose
behavioral score sits in the 40-69 challenge band, skips the
challenge tier and reaches upstream. This is the normal mode for
legitimate non-browser traffic.

## `hmac:`

Verifies requests carrying a Stripe-style HMAC signature header.

### Wire format

```http
X-Veilgate-Signature: t=<unix-ts>,v1=<hex-sha256>
X-Veilgate-Client:    payment-service
```

where:

```
v1 = HMAC_SHA256(secret, "<t>.<method>.<path>.<sha256(body)>")
```

The canonical string covers the timestamp, the HTTP method, the URL
path (no query string), and the SHA-256 of the request body. So:

- A stolen signature can't be replayed against a different endpoint
  (`/api/charge` vs `/api/data` produce different signatures).
- A stolen signature can't be replayed with a tampered body - the
  body-hash is part of what's signed.
- The query string is NOT covered by the signature. **If you need
  security-relevant parameters bound to the signature, put them in
  the body** or move to a path-based URL scheme.

### Parameters

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | feature flag; nothing else in this block matters when false |
| `header_signature` | string | `X-Veilgate-Signature` | request header carrying `t=...,v1=...` |
| `header_client` | string | `X-Veilgate-Client` | request header naming which client secret to look up |
| `clock_skew_sec` | int | `300` | +/- window around now within which `t` must fall |
| `max_body_bytes` | int | `1048576` (1 MiB) | cap on body bytes hashed; protects against memory-exhaustion |
| `clients_dir` | string | required when enabled | one file per client: `<client>.secret` |

### Client-secret files

Each registered client gets a file at `clients_dir/<client>.secret`
containing the shared secret. VeilGate reads them lazily and caches
by mtime - operators rotate by overwriting the file, no restart
needed.

```bash
# Create a client
sudo install -o veilgate -g veilgate -m 0400 /dev/null \
  /etc/veilgate/clients/payment-service.secret
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/payment-service.secret'

# Rotate the same client
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/payment-service.secret'
# (next request from this client uses the new secret; the cache
#  invalidates on file mtime change)
```

**Filename = client identifier.** Client names submitted via
`X-Veilgate-Client` are validated as filename-safe (alphanumerics,
dash, underscore, dot only; no `..`) before any filesystem access.
Path-traversal attempts are rejected before the verifier ever touches
disk.

### Skew window

The `clock_skew_sec` window (default 5 min) gives some tolerance for
clock drift between the client and the proxy. If your clients are
geographically distributed or you've seen NTP issues, raise it; if
your traffic is all in-data center, you can safely drop it to 60 s for
tighter replay protection.

A request with a timestamp wildly in the future or past is rejected
as `timestamp outside skew window` - this is your replay-protection
ceiling.

### Body-size cap

`max_body_bytes` (default 1 MiB) is a memory-exhaustion ceiling. A
malicious client could otherwise ship a 10 GB body to consume the
proxy's RAM during the hash computation. Requests with bodies larger
than the cap fail signature verification (because the body-hash
doesn't match) - they don't OOM the proxy. Set this higher only if
you have legitimate large uploads going through the verifier path.

## `bearer:`

Accepts opaque static tokens carried in a request header (GitHub PAT / Stripe
API key model). Tokens are compared via SHA-256 — no per-request replay
protection; rely on TLS and rotate on compromise.

Full reference: [`docs/reference/verifiers/bearer.md`](../reference/verifiers/bearer.md)

| Key | Type | Default | Purpose |
|-----|------|---------|---------|
| `enabled` | bool | `false` | Install the verifier when `true`. |
| `header` | string | `Authorization` | Request header carrying the credential. |
| `scheme` | string | `Bearer` (auto when `header=Authorization`) | Prefix stripped before lookup. Set to `""` for raw-token headers with no scheme. |
| `tokens_dir` | string | required | One `.token` file per client. Hot-reloaded on directory mtime change. |

```yaml
verifiers:
  bearer:
    enabled:    true
    header:     Authorization
    scheme:     Bearer
    tokens_dir: /etc/veilgate/tokens
```

---

## `cookies:`

A list of cookie verifiers. Each entry binds a cookie name to a validator;
entries are evaluated in declaration order and the first acceptance wins.

Full reference: [`docs/reference/verifiers/cookie.md`](../reference/verifiers/cookie.md)

### Fields per entry

| Field | Default | Notes |
|-------|---------|-------|
| `name` | required | Cookie name. Case-sensitive, exact match. |
| `validator` | `opaque` | `opaque`, `jwt`, or `callout`. |
| `tokens_dir` | required when `validator: opaque` | Same layout as bearer's `tokens_dir`. |
| `jwks_url` | required when `validator: jwt` | JWKS endpoint URL. |
| `issuer` | — | Expected `iss` claim (JWT). |
| `audience` | — | Expected `aud` claim (JWT). |
| `client_claim` | — | JWT claim used as the client id in audit logs. |
| `algorithms` | — | Allowed signing algorithms; HS\* always stripped. |
| `refresh_interval` | `1h` | How often to re-fetch the JWKS. |
| `url` | required when `validator: callout` | HTTP endpoint to call. |
| `cache_ttl` | `30s` | How long to cache a positive callout response. |
| `timeout` | `5s` | Per-callout HTTP timeout. |
| `auth_header` | — | Header to add to outbound callout requests. |
| `auth_value` | — | Value for `auth_header`. |

```yaml
verifiers:
  cookies:
    - name:       SESSION
      validator:  opaque
      tokens_dir: /etc/veilgate/sessions

    - name:       AUTH_JWT
      validator:  jwt
      jwks_url:   https://auth.example.com/.well-known/jwks.json
      audience:   veilgate
```

---

## `headers:`

A list of header verifiers. Each entry binds a request header name to a
validator. The header name is canonicalised — `X-Foo`, `x-foo`, and `X-FOO`
all match. Fields are identical to [`cookies:`](#cookies) entries, substituting
`name` for the header name instead of a cookie name.

Full reference: [`docs/reference/verifiers/header.md`](../reference/verifiers/header.md)

```yaml
verifiers:
  headers:
    - name:       CF-Access-Jwt-Assertion
      validator:  jwt
      jwks_url:   https://team.cloudflareaccess.com/cdn-cgi/access/certs

    - name:       X-Internal-Service-Token
      validator:  opaque
      tokens_dir: /etc/veilgate/services
```

---

## Example

A production deployment with one client (`payment-service`) accepting
HMAC-signed requests to its internal API:

```yaml
# /etc/veilgate/veilgate.yaml
mode: auto
listen: ":8080"
upstream: "http://internal-api.svc.cluster.local:9000"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold:    70

challenge:
  secret: ${VEILGATE_SECRET}

verifiers:
  hmac:
    enabled: true
    header_signature: "X-Veilgate-Signature"
    header_client:    "X-Veilgate-Client"
    clock_skew_sec:   300
    max_body_bytes:   1048576
    clients_dir:      "/etc/veilgate/clients"
```

```bash
# Operator setup at deploy time
sudo install -d -m 0700 -o veilgate -g veilgate /etc/veilgate/clients
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/payment-service.secret'
sudo chmod 0400 /etc/veilgate/clients/payment-service.secret
sudo chown veilgate:veilgate /etc/veilgate/clients/payment-service.secret
```

Client-side signing in Go:

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net/http"
    "strconv"
    "time"
)

func signRequest(req *http.Request, secret, client string, body []byte) {
    ts := strconv.FormatInt(time.Now().Unix(), 10)
    bodySum := sha256.Sum256(body)
    canonical := ts + "." + req.Method + "." + req.URL.Path + "." +
        hex.EncodeToString(bodySum[:])
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(canonical))
    req.Header.Set("X-Veilgate-Signature",
        fmt.Sprintf("t=%s,v1=%s", ts, hex.EncodeToString(mac.Sum(nil))))
    req.Header.Set("X-Veilgate-Client", client)
}
```

Same pattern in Python:

```python
import hmac, hashlib, time

def sign(secret: bytes, method: str, path: str, body: bytes) -> str:
    ts = int(time.time())
    body_sum = hashlib.sha256(body).hexdigest()
    canonical = f"{ts}.{method}.{path}.{body_sum}".encode()
    mac = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"  # signature header value
```

## Related

- [Bearer verifier reference](../reference/verifiers/bearer.md)
- [Cookie verifier reference](../reference/verifiers/cookie.md)
- [Header verifier reference](../reference/verifiers/header.md)
- [JWT validator reference](../reference/verifiers/jwt-validator.md)
- [Callout validator reference](../reference/verifiers/callout-validator.md)
- [How-to: Server-to-server HMAC](../how-to/server-to-server-hmac.md)
  - task-oriented walkthrough including secret rotation
- [How-to: Multi-origin SPA](../how-to/protect-multi-origin.md)
  - for cross-subdomain frontend + backend deployments
- [`rules/challenge.yaml`](rules/challenge.md) - cookie/header
  token transport, the *other* credential path
- [`detector.score_tarpit_threshold`](detector.md#score_tarpit_threshold)
  - the threshold that bounds verifier bypass
- [Credential verifiers — design tracker](../design/credential-verifiers.md)
- [docs/security/challenge-solution-design.md](../security/challenge-solution-design.md)
  - the design context for why this exists

---

*Previous: [`capture:`](capture.md) | Next: [Configuration reference](README.md)*
