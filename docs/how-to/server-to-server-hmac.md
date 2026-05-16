# Authenticate server-to-server callers with HMAC

> **Audience:** Operators with internal services, partner webhooks, or
> native mobile apps that need to reach a veilgate-protected API
> without solving a JavaScript proof-of-work.

The PoW challenge tier filters browser-shaped traffic. Anything that
doesn't execute JavaScript — service-to-service traffic, mobile apps,
partner webhooks, cron jobs — needs a different credential.
veilgate's verifier chain accepts operator-issued **HMAC signatures**
(Stripe-webhook shape) as a substitute.

**On this page:**

- [When to use this](#when-to-use-this)
- [Step 1 — register a client](#step-1--register-a-client)
- [Step 2 — enable the verifier](#step-2--enable-the-verifier)
- [Step 3 — sign requests from the client](#step-3--sign-requests-from-the-client)
- [Verifying it works](#verifying-it-works)
- [Rotating a client secret](#rotating-a-client-secret)
- [Revoking a client](#revoking-a-client)
- [Common pitfalls](#common-pitfalls)
- [Related](#related)

## When to use this

Pick HMAC verifier auth when:

- You control both ends of the request (your own services or partners
  you have a shared-secret relationship with).
- The caller doesn't run a JS runtime — Go/Python/Java services,
  mobile apps, CLI tools, cron-scheduled batch jobs.
- You want body-bound signatures so a stolen credential can't be
  replayed with a tampered body.
- You prefer no PKI — single shared secret per client, no JWKS or
  cert rotation infrastructure.

If your callers already issue JWTs (e.g. you have a corporate SSO
that mints them), wait for the JWT verifier — sketched in the
[design doc](../security/challenge-solution-design.md#the-server-to-server-solution)
but not yet implemented. For now, HMAC is the path.

## Step 1 — register a client

veilgate's HMAC verifier reads one file per client from a configured
directory. The filename (sans extension) is the client identifier;
the file contents is the shared secret.

```bash
# Create the clients dir with restrictive perms.
sudo install -d -m 0700 -o veilgate -g veilgate /etc/veilgate/clients

# Generate a secret for "payment-service".
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/payment-service.secret'
sudo chmod 0400 /etc/veilgate/clients/payment-service.secret
sudo chown veilgate:veilgate /etc/veilgate/clients/payment-service.secret

# Distribute the secret to the client out-of-band — vault, KMS, etc.
sudo cat /etc/veilgate/clients/payment-service.secret
```

**Filename conventions:** the client name must match
`[A-Za-z0-9._-]+` and must not contain `..`. Path-traversal attempts
are rejected before any filesystem access — but stick to plain
alphanumeric names anyway, with optional dashes/underscores for
readability.

**One secret per client, please.** It's tempting to reuse one secret
across all your services. Don't — when a leak happens, you'll want
to revoke one client without affecting the others. The
file-per-client model makes that one `rm` away.

## Step 2 — enable the verifier

Add a `verifiers:` block to `/etc/veilgate/veilgate.yaml`:

```yaml
verifiers:
  hmac:
    enabled: true
    header_signature: "X-Veilgate-Signature"
    header_client:    "X-Veilgate-Client"
    clock_skew_sec:   300       # ± 5 min replay window
    max_body_bytes:   1048576   # 1 MiB cap on hashed bodies
    clients_dir:      "/etc/veilgate/clients"
```

Restart veilgate to pick up the new block:

```bash
sudo systemctl restart veilgate
```

Verify the chain is installed:

```bash
sudo journalctl -u veilgate -n 20 | grep verifier
# Expect:
#   hmac verifier enabled clients_dir=/etc/veilgate/clients
#   authenticator chain installed verifiers=1
```

> The `verifiers:` block itself needs a restart to take effect.
> Individual *secret files* hot-reload — see [Rotating](#rotating-a-client-secret)
> below.

## Step 3 — sign requests from the client

The signature covers a canonical string:

```
v1 = HMAC_SHA256(secret, "<t>.<method>.<path>.<sha256(body)>")
```

where `<t>` is the unix timestamp, `<method>` is the uppercase HTTP
method, `<path>` is the URL path (no query string), and the body
hash is the hex SHA-256 of the request body (or the empty-string hash
for empty bodies).

Two headers go on every signed request:

```http
X-Veilgate-Signature: t=1715817600,v1=a3b1f5…
X-Veilgate-Client:    payment-service
```

### Go

```go
package veilgateauth

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "strconv"
    "time"
)

func SignRequest(req *http.Request, secret []byte, client string) error {
    var body []byte
    if req.Body != nil {
        b, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        body = b
        req.Body = io.NopCloser(bytesReader(b))
    }
    ts := time.Now().Unix()
    bodySum := sha256.Sum256(body)
    canonical := fmt.Sprintf("%d.%s.%s.%s",
        ts, req.Method, req.URL.Path, hex.EncodeToString(bodySum[:]))
    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(canonical))
    req.Header.Set("X-Veilgate-Signature",
        fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil))))
    req.Header.Set("X-Veilgate-Client", client)
    return nil
}
```

### Python

```python
import hashlib, hmac, time
import requests

def sign(secret: bytes, method: str, path: str, body: bytes) -> dict[str, str]:
    ts = int(time.time())
    body_sum = hashlib.sha256(body).hexdigest()
    canonical = f"{ts}.{method}.{path}.{body_sum}".encode()
    mac = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
    return {
        "X-Veilgate-Signature": f"t={ts},v1={mac}",
        "X-Veilgate-Client":    "payment-service",
    }

# Example use:
body = b'{"amount":1000}'
headers = sign(SECRET, "POST", "/api/charge", body)
headers["Content-Type"] = "application/json"
r = requests.post("https://api.example.com/api/charge", headers=headers, data=body)
```

### curl

```bash
SECRET="$(cat ~/.veilgate/payment-service.secret)"
TS=$(date +%s)
BODY='{"amount":1000}'
BODY_SUM=$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $2}')
CANONICAL="${TS}.POST./api/charge.${BODY_SUM}"
SIG=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -X POST https://api.example.com/api/charge \
  -H "Content-Type: application/json" \
  -H "X-Veilgate-Signature: t=${TS},v1=${SIG}" \
  -H "X-Veilgate-Client: payment-service" \
  -d "$BODY"
```

## Verifying it works

```bash
# A correctly signed request reaches your upstream.
SECRET=$(cat /etc/veilgate/clients/payment-service.secret)
TS=$(date +%s)
SIG=$(printf '%s.%s.%s.%s' "$TS" "GET" "/api/health" "$(printf '' | openssl dgst -sha256 -hex | awk '{print $2}')" \
  | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -i \
  -H "X-Veilgate-Signature: t=${TS},v1=${SIG}" \
  -H "X-Veilgate-Client: payment-service" \
  https://api.example.com/api/health
# Expect: response from your real upstream

# An incorrect signature falls through to the score system.
curl -i \
  -H "X-Veilgate-Signature: t=0,v1=deadbeef" \
  -H "X-Veilgate-Client: payment-service" \
  https://api.example.com/api/health
# Expect: 503 challenge HTML or 401 JSON depending on score
```

Watch the logs to confirm acceptance:

```bash
sudo journalctl -u veilgate -f | grep verifier
# On accept:
#   verifier accepted request verifier=hmac client=payment-service reason="valid HMAC signature"
```

## Rotating a client secret

The cache invalidates on file mtime change — no restart needed.

```bash
# Overwrite the existing file with a new secret.
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/payment-service.secret'

# Distribute the new secret to the client out-of-band.
# Next request after the file's mtime advances picks up the new secret.
```

For coordinated rotation (you want both old and new secrets to be
valid during the cutover), the HMAC verifier doesn't natively
support multi-secret. Workaround: **register a temporary second
client** with the new secret, point the calling service at the new
client name during the cutover, then remove the old client file
when ready.

```bash
# 1. Add the new client.
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/payment-service-v2.secret'
sudo chmod 0400 /etc/veilgate/clients/payment-service-v2.secret

# 2. Calling service: switch X-Veilgate-Client header to
#    "payment-service-v2" and use the new secret.

# 3. After all callers have switched:
sudo rm /etc/veilgate/clients/payment-service.secret
```

## Revoking a client

`rm` the secret file. The cache will be invalidated by the next
`os.Stat` call, and any request with that client name will be
rejected as `unknown client`.

```bash
sudo rm /etc/veilgate/clients/compromised-service.secret
# Next request → verifier rejects with reason "unknown client".
# Request then flows through the score system as if the credential
# hadn't been presented at all.
```

There is currently no in-band "revoke a specific signature" — if you
need to block a *signed* request that's already been issued, your
options are:

- Rotate the secret (above) — invalidates all outstanding signatures
  for that client.
- Move the client behind a stricter score threshold by setting
  honeypot paths or wordlist patterns that match the caller's
  expected request shape — but this is heavy-handed and usually
  means the design has drifted from the use case.

## Common pitfalls

### "My signature is rejected even though I generated it correctly"

Most often: the body bytes that go into the signature don't match the
bytes that get sent on the wire. Watch for:

- The body has been re-serialised between signing and sending. JSON
  in particular: `{"a":1,"b":2}` and `{"b":2,"a":1}` produce
  different signatures. Sign the exact bytes you will transmit.

- Your HTTP library is adding `charset=utf-8` to the request body
  automatically. The body bytes are still the same, but if you
  computed the hash on the string and your library transmits as
  UTF-8 with a BOM, you've added bytes that aren't in your hash.

- Chunked transfer encoding rewriting the body. If you don't control
  this, capture the request with `tcpdump` or a sniffer to see what
  bytes were actually sent, and hash those.

### "The clock keeps drifting and I'm getting 'timestamp outside skew window'"

Either fix the NTP setup or raise `clock_skew_sec`. Don't lower the
skew below ~60 s in production — clock drift inside a data centre is
usually <1 s, but cross-region/cross-cloud can hit 10s of seconds
occasionally. 300 s (5 min, the default) is a reasonable balance.

### "I want to authenticate without the X-Veilgate-Client header"

You can't, today. The chain needs the header to know which secret to
look up. If you have one client, you could symlink every common
prefix in `clients_dir` to the same secret file, but that's worse
than just setting the one header.

### "How do I make this work with mTLS instead?"

The verifier interface is built to accept mTLS. The implementation
is sketched in [docs/security/challenge-solution-design.md](../security/challenge-solution-design.md#tier-5--mtls-verifier-half-day)
but not yet shipped. For now, terminate mTLS at your TLS terminator
(nginx, Envoy, ALB) and either propagate the cert fingerprint
through a trusted header that the next layer of auth honors, or
script the HMAC verifier configuration based on the cert subject.

## Related

- [`verifiers:`](../config/verifiers.md) — config reference
- [How-to: Multi-origin SPA](protect-multi-origin.md) — for browser
  callers, which use the cookie/header token transport instead of HMAC
- [docs/security/challenge-solution-design.md §The server-to-server solution](../security/challenge-solution-design.md#the-server-to-server-solution)
  — design rationale

---

*Previous: [How-to: Multi-origin SPA](protect-multi-origin.md) ·
Next: [Configuration reference](../config/README.md)*
