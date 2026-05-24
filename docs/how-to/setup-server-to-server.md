# Setup: Server-to-server (HMAC)

**When to use this:** A backend service, cron job, mobile app, or CLI tool
needs to call a VeilGate-protected API. There is no browser and no JavaScript
runtime to solve a proof-of-work challenge.

VeilGate's HMAC verifier accepts operator-issued signed headers as a credential
that bypasses the PoW tier entirely.

**Traffic flow:**

```
Your service / cron / mobile app
  └─► VeilGate (validates HMAC headers) ──► your API
```

---

## Step 1 — Install VeilGate on the API server

If VeilGate is not already running:

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

Set a secret before enabling `challenge` or `tarpit` mode:

```bash
sudo systemctl edit veilgate
# [Service]
# Environment=VEILGATE_SECRET=<openssl rand -hex 32>
sudo systemctl restart veilgate
```

---

## Step 2 — Create a secret for your calling service

VeilGate reads one file per client from a directory you configure. The
filename (without extension) is the client identifier.

```bash
# Create the clients directory with restrictive permissions.
sudo install -d -m 0700 -o veilgate -g veilgate /etc/veilgate/clients

# Generate a secret for your service. Replace "my-service" with a
# descriptive name: "payment-worker", "analytics-cron", etc.
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/my-service.secret'
sudo chmod 0400 /etc/veilgate/clients/my-service.secret
sudo chown veilgate:veilgate /etc/veilgate/clients/my-service.secret

# Display it so you can distribute it to the calling service.
sudo cat /etc/veilgate/clients/my-service.secret
```

Create one file per calling service. Sharing a secret across services means
you cannot revoke one without affecting the others.

---

## Step 3 — Enable the HMAC verifier

In `/etc/veilgate/veilgate.yaml`:

```yaml
listen: ":443"
upstream: "http://127.0.0.1:3000"
rules_dir: "~veilgate/.veilgate/rules"
mode: "challenge"

verifiers:
  hmac:
    enabled: true
    header_signature: "X-Veilgate-Signature"
    header_client:    "X-Veilgate-Client"
    clock_skew_sec:   300        # ±5 min replay window
    max_body_bytes:   1048576    # 1 MiB cap on hashed bodies
    clients_dir:      "/etc/veilgate/clients"
```

Restart and confirm the verifier is active:

```bash
sudo systemctl restart veilgate
journalctl -u veilgate -n 20 | grep verifier
# Expect:
#   hmac verifier enabled clients_dir=/etc/veilgate/clients
#   authenticator chain installed verifiers=1
```

> The `verifiers:` block needs a restart to take effect. Individual secret
> files hot-reload on `mtime` change — see [Rotating a secret](#rotating-a-secret).

---

## Step 4 — Sign requests from your calling service

The signature covers:

```
HMAC-SHA256(secret, "<unix-timestamp>.<METHOD>.<path>.<sha256-hex(body)>")
```

Two headers go on every request:

```
X-Veilgate-Signature: t=<unix-timestamp>,v1=<hex-mac>
X-Veilgate-Client:    my-service
```

### Python

```python
import hashlib, hmac, time, requests

SECRET = b"<secret-from-step-2>"

def signed_headers(method: str, path: str, body: bytes) -> dict:
    ts = int(time.time())
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{ts}.{method}.{path}.{body_hash}".encode()
    sig = hmac.new(SECRET, canonical, hashlib.sha256).hexdigest()
    return {
        "X-Veilgate-Signature": f"t={ts},v1={sig}",
        "X-Veilgate-Client":    "my-service",
    }

body = b'{"amount": 1000}'
headers = signed_headers("POST", "/api/charge", body)
headers["Content-Type"] = "application/json"

r = requests.post("https://api.example.com/api/charge", headers=headers, data=body)
```

### Go

```go
package veilgateauth

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "io"
    "net/http"
    "time"
)

func SignRequest(req *http.Request, secret []byte, clientName string) error {
    var body []byte
    if req.Body != nil {
        b, err := io.ReadAll(req.Body)
        if err != nil {
            return err
        }
        body = b
        req.Body = io.NopCloser(bytes.NewReader(b))
    }

    ts := time.Now().Unix()
    sum := sha256.Sum256(body)
    canonical := fmt.Sprintf("%d.%s.%s.%s",
        ts, req.Method, req.URL.Path, hex.EncodeToString(sum[:]))

    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(canonical))

    req.Header.Set("X-Veilgate-Signature",
        fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil))))
    req.Header.Set("X-Veilgate-Client", clientName)
    return nil
}
```

### Node.js

```js
import { createHmac, createHash } from "node:crypto";

const SECRET = Buffer.from("<secret-from-step-2>", "utf8");

function signedHeaders(method, path, body = Buffer.alloc(0)) {
  const ts = Math.floor(Date.now() / 1000);
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const canonical = `${ts}.${method}.${path}.${bodyHash}`;
  const sig = createHmac("sha256", SECRET).update(canonical).digest("hex");
  return {
    "X-Veilgate-Signature": `t=${ts},v1=${sig}`,
    "X-Veilgate-Client": "my-service",
  };
}

const body = Buffer.from(JSON.stringify({ amount: 1000 }));
const headers = {
  ...signedHeaders("POST", "/api/charge", body),
  "Content-Type": "application/json",
};

const res = await fetch("https://api.example.com/api/charge", {
  method: "POST",
  headers,
  body,
});
```

### curl (for testing)

```bash
SECRET="$(cat /etc/veilgate/clients/my-service.secret)"
TS=$(date +%s)
BODY='{"amount":1000}'
BODY_SUM=$(printf '%s' "$BODY" | openssl dgst -sha256 -hex | awk '{print $2}')
CANONICAL="${TS}.POST./api/charge.${BODY_SUM}"
SIG=$(printf '%s' "$CANONICAL" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')

curl -X POST https://api.example.com/api/charge \
  -H "Content-Type: application/json" \
  -H "X-Veilgate-Signature: t=${TS},v1=${SIG}" \
  -H "X-Veilgate-Client: my-service" \
  -d "$BODY"
```

---

## Step 5 — Verify it works

A correctly signed request should reach your upstream:

```bash
journalctl -u veilgate -f | grep verifier
# On accept:
#   verifier accepted request verifier=hmac client=my-service reason="valid HMAC signature"
```

An unsigned request from the same caller flows through the normal score system
and may be challenged or tarpitted depending on its score.

Test a bad signature to confirm rejection:

```bash
curl -i \
  -H "X-Veilgate-Signature: t=0,v1=deadbeef" \
  -H "X-Veilgate-Client: my-service" \
  https://api.example.com/api/health
# Expect: 401 or 503 (treated as suspicious, not as a verified caller)
```

---

## Rotating a secret

Secret files hot-reload on `mtime` change — no VeilGate restart needed.

```bash
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/my-service.secret'
# Distribute the new value to the calling service out-of-band (Vault, KMS, etc.).
# The next request after the file's mtime changes picks up the new secret.
```

For a zero-downtime cutover where both old and new secrets must be valid
briefly, register a second client, switch the caller, then remove the old one:

```bash
# 1. Add a second client with a new secret.
sudo sh -c 'openssl rand -hex 32 > /etc/veilgate/clients/my-service-v2.secret'
sudo chmod 0400 /etc/veilgate/clients/my-service-v2.secret

# 2. Update the calling service to use "my-service-v2" + the new secret.

# 3. Once all callers are on v2, remove the old client.
sudo rm /etc/veilgate/clients/my-service.secret
```

---

## Revoking a client

```bash
sudo rm /etc/veilgate/clients/my-service.secret
# Next request from that client: rejected as "unknown client".
```

The rejected request then flows through the score system as if the credential
was never presented.

---

## Common pitfalls

**"Signature rejected even though I computed it correctly"**

Almost always a body mismatch. The bytes that go into the hash must be exactly
the bytes sent on the wire:
- Sign the raw bytes, not a re-serialised copy. JSON key order matters — `{"a":1,"b":2}` and `{"b":2,"a":1}` produce different signatures.
- Watch for libraries that add a `charset=utf-8` suffix or a BOM transparently.
- If your HTTP library uses chunked transfer encoding, capture the actual bytes with `tcpdump` and hash those.

**"Timestamp outside skew window"**

Raise `clock_skew_sec` or fix NTP. The default 300 s (±5 min) handles
nearly all clock drift inside a data centre and most cross-region calls.
Don't lower it below ~60 s in production.

**"I want to authenticate without `X-Veilgate-Client`"**

Not supported. The verifier needs the client name to know which secret file to
open. If you have a single internal caller, the overhead of one header is worth
it for the revocation granularity you get.

---

## Related

- [Authenticate server-to-server callers with HMAC](server-to-server-hmac.md) — full reference with rotation, revocation, and mTLS notes
- [Setup: SPA on CDN](setup-spa-cdn.md) — browser callers on a separate CDN host
- [Setup: same-origin](setup-same-origin.md) — browser callers on the same host as the API
- [Configuration reference: verifiers](../config/verifiers.md)
