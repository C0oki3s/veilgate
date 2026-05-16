# Module veilgate_verifier

The `veilgate_verifier` module documents optional request verifier chains. The
current implemented verifier is HMAC-SHA256, following the Stripe webhook
signature pattern. A successful verifier result upgrades a `challenge` decision
to `real`, allowing trusted internal services to pass through without completing
a PoW challenge.

Verifier acceptance does not override a tarpit decision. A valid HMAC signature
can only bypass the challenge tier. This prevents a leaked secret from providing
a full bypass against high-confidence attack-tier behavior.

## Signature Protocol

The sender computes:

1. Take the current Unix timestamp `T`.
2. Build the canonical string: `<T>.<METHOD>.<PATH>.<hex-SHA-256(body)>`
3. Compute HMAC-SHA256 of the canonical string using the client secret.
4. Add two headers:
   - `X-Veilgate-Client: <client-name>`
   - `X-Veilgate-Signature: t=<T>,v1=<hex-HMAC>`

The verifier:
1. Reads `X-Veilgate-Client`, looks up secret file `clients_dir/<client>.secret`.
2. Parses `t=` and `v1=` from `X-Veilgate-Signature`.
3. Checks `|now - T| <= clock_skew_sec` (replay protection).
4. Reads and hashes the body (up to `max_body_bytes`).
5. Recomputes canonical string and HMAC.
6. Compares in constant time with `hmac.Equal`.
7. On match: returns `Result{Accepted: true}`.

```
Canonical string:
  "<unix_timestamp>.<METHOD>.<PATH>.<hex(SHA-256(body))>"

Example (GET /api/status, empty body):
  "1705318200.GET./api/status.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
```

## Example Configuration

```yaml
verifiers:
  hmac:
    enabled: true
    header_signature: "X-Veilgate-Signature"
    header_client: "X-Veilgate-Client"
    clock_skew_sec: 300
    max_body_bytes: 1048576
    clients_dir: "/etc/veilgate/clients"
```

## Directives

- `verifiers.hmac.enabled`
- `verifiers.hmac.header_signature`
- `verifiers.hmac.header_client`
- `verifiers.hmac.clock_skew_sec`
- `verifiers.hmac.max_body_bytes`
- `verifiers.hmac.clients_dir`

## `verifiers.hmac.enabled`

Syntax:  `enabled: true | false`  
Default: `false`  
Context: `verifiers.hmac`

Enables HMAC request signature verification. When enabled, the verifier is
added to the proxy verifier chain at startup. The chain is consulted after
normal scoring, before returning the final decision for non-tarpit requests.

```go
// internal/proxy/proxy.go
if decision != DecisionTarpit {
    if s.verifiers != nil {
        if res := s.verifiers.Verify(r); res.Accepted {
            decision = DecisionReal
        }
    }
}
```

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — builds the verifier chain.
- [`internal/verifier/verifier.go`](../../internal/verifier/verifier.go) — `Chain.Verify()`.
- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) — `HMACVerifier.Verify()`.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) — chain invocation.

### Operational notes

- This is not a universal bypass. It only promotes `challenge` to `real`.
- Tarpit decisions remain controlled by score regardless of verifier result.
- Only enable when you have internal service-to-service traffic that must not
  receive challenge pages.

## `verifiers.hmac.header_signature`

Syntax:  `header_signature: "<header-name>"`  
Default: `"X-Veilgate-Signature"`  
Context: `verifiers.hmac`

Names the header containing the timestamp and HMAC:

```
X-Veilgate-Signature: t=1705318200,v1=a3f2b8e1c9d5...
```

`parseSigHeader()` in `internal/verifier/hmac.go` parses the `t=` and `v1=`
fields. Extra fields (e.g., `v2=`) are ignored for forward compatibility.

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) → `parseSigHeader(hdr string)`.
- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) → `Verify(r *http.Request)`.

### Operational notes

- Use the default name unless you have an existing header name convention.
- Non-default names require coordinating with all clients.

## `verifiers.hmac.header_client`

Syntax:  `header_client: "<header-name>"`  
Default: `"X-Veilgate-Client"`  
Context: `verifiers.hmac`

Names the header that identifies which client secret to load from `clients_dir`.
The value is the client name (no path separators, no `..`).

`validClientName()` rejects names containing `/`, `\`, or `..` to prevent path
traversal attacks when loading secrets from `clients_dir/<name>.secret`.

```go
// internal/verifier/hmac.go
func validClientName(name string) bool {
    return !strings.Contains(name, "..") &&
           !strings.Contains(name, "/") &&
           !strings.Contains(name, `\`)
}
```

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) → `validClientName()`.
- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) → `loadSecret(name)`.

### Operational notes

- Use short, alphanumeric client names (e.g., `payment-service`, `cron-worker`).
- Rotate secrets by replacing the `.secret` file — the verifier hot-reloads
  on mtime change.

## `verifiers.hmac.clock_skew_sec`

Syntax:  `clock_skew_sec: <seconds>`  
Default: `300`  
Context: `verifiers.hmac`

Sets the maximum allowed difference between the timestamp in the signature
and the server's current time. Requests outside this window are rejected by
the verifier and fall through to normal scoring.

This limits replay attacks: a captured signature can only be replayed within
the skew window (default 5 minutes).

```go
// internal/verifier/hmac.go (schematic)
age := time.Since(time.Unix(sigTs, 0))
if age > time.Duration(cfg.ClockSkewSec)*time.Second || age < -skewTolerance {
    return Result{Accepted: false, Reason: "clock_skew"}
}
```

### Operational notes

- Keep service clocks synchronized with NTP (chrony, systemd-timesyncd).
- Reduce `clock_skew_sec` to `60` if all clients have reliable NTP; this
  tightens the replay window.
- Do not increase beyond `600` — a 10-minute replay window is operationally
  unusual.

### Validation

```bash
# Test clock skew rejection: sign with old timestamp
# Should fall through to normal scoring, not be accepted
date -d "10 minutes ago" +%s  # Get old timestamp
# Use that timestamp in your signature test
```

## `verifiers.hmac.max_body_bytes`

Syntax:  `max_body_bytes: <bytes>`  
Default: `1048576` (1 MB)  
Context: `verifiers.hmac`

Caps how many bytes the verifier reads and hashes from the request body. This
prevents memory exhaustion via oversized requests with a valid signature header.

`readCappedBody()` wraps `io.LimitReader` and replaces `r.Body` with a new
`ReadCloser` containing the buffered bytes, so the upstream proxy handler can
still read the body after verification.

```go
// internal/verifier/hmac.go (schematic)
body, err := io.ReadAll(io.LimitReader(r.Body, int64(cfg.MaxBodyBytes)))
r.Body = io.NopCloser(bytes.NewReader(body)) // restore for upstream
```

### Operational notes

- Signed requests larger than `max_body_bytes` will fail verification even with
  a valid secret, because the hash is computed over a truncated body.
- Set this to the maximum expected signed API request size.
- For webhook-only use cases, `65536` (64 KB) is typically sufficient.

## `verifiers.hmac.clients_dir`

Syntax:  `clients_dir: "<directory>"`  
Default: none  
Context: `verifiers.hmac`

Directory containing one file per client: `<client-name>.secret`. The file
contents (trimmed of whitespace) are the HMAC-SHA256 key for that client.

The verifier caches secrets and hot-reloads them when the file mtime changes.
This allows secret rotation without a VeilGate restart.

```
/etc/veilgate/clients/
    payment-service.secret      ← HMAC key for the payment service
    cron-worker.secret          ← HMAC key for the scheduled worker
    monitoring.secret           ← HMAC key for the health check service
```

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) → `NewHMACVerifier()`.
- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go) → `loadSecret(name)`.

### Operational notes

- Required when HMAC is enabled.
- Permissions: `chmod 600 /etc/veilgate/clients/*.secret`.
- Do not use the same secret for multiple clients.
- Rotate by replacing the file; the change is detected automatically via mtime.

### Validation

```bash
ls -la /etc/veilgate/clients/
# All files should be owned by the VeilGate service user, mode 600
```

## Signing Example (Go)

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "fmt"
    "strconv"
    "time"
)

func signRequest(secret, method, path string, body []byte) string {
    ts := strconv.FormatInt(time.Now().Unix(), 10)
    bodyHash := sha256.Sum256(body)
    canonical := fmt.Sprintf("%s.%s.%s.%x", ts, method, path, bodyHash)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(canonical))
    sig := fmt.Sprintf("t=%s,v1=%x", ts, mac.Sum(nil))
    return sig
}
```

## Signing Example (Python)

```python
import hashlib, hmac, time

def sign_request(secret: str, method: str, path: str, body: bytes) -> str:
    ts = str(int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    canonical = f"{ts}.{method}.{path}.{body_hash}"
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"
```

## Troubleshooting

### All HMAC requests fall through to scoring

Check that both `X-Veilgate-Client` and `X-Veilgate-Signature` headers are
present. The client name must match a file in `clients_dir`. Check mtime on
the secret file.

```bash
ls -la /etc/veilgate/clients/
curl -v -H "X-Veilgate-Client: myservice" \
     -H "X-Veilgate-Signature: t=..." \
     http://localhost:8080/api/endpoint
```

### Clock skew rejections

Verify NTP sync on the signing service:

```bash
timedatectl status | grep "NTP synchronized"
```

## Related

- [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md)
- [Module veilgate_challenge](veilgate_challenge.md)
- [Module veilgate_proxy](veilgate_proxy.md)
- [HMAC verifier internals](../functionalities/hmac-verifier.md)

## Example Configuration

```yaml
verifiers:
  hmac:
    enabled: true
    header_signature: "X-Veilgate-Signature"
    header_client: "X-Veilgate-Client"
    clock_skew_sec: 300
    max_body_bytes: 1048576
    clients_dir: "/etc/veilgate/clients"
```

## Directives

- `verifiers.hmac.enabled`
- `verifiers.hmac.header_signature`
- `verifiers.hmac.header_client`
- `verifiers.hmac.clock_skew_sec`
- `verifiers.hmac.max_body_bytes`
- `verifiers.hmac.clients_dir`

## `verifiers.hmac.enabled`

Syntax:  `enabled: true | false`  
Default: `false`  
Context: `verifiers.hmac`

Enables Stripe-style request signature verification. When enabled, the verifier
is added to the proxy verifier chain at startup.

### Code path

- [`cmd/veilgate/main.go#L39`](../../cmd/veilgate/main.go#L39)
- [`internal/verifier/verifier.go`](../../internal/verifier/verifier.go)
- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go)
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go)

### Operational notes

- This is not a universal allowlist.
- Valid HMAC bypasses challenge tier only.
- Tarpit decisions remain controlled by score.

## `header_signature`

Syntax:  `header_signature: "<header-name>"`  
Default: `"X-Veilgate-Signature"`  
Context: `verifiers.hmac`

Names the header containing the timestamp and signature:

```text
t=<unix>,v1=<hex-hmac>
```

The canonical string is:

```text
<timestamp>.<method>.<path>.<sha256(body)>
```

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go)
- `parseSigHeader()`
- `Verify()`

## `header_client`

Syntax:  `header_client: "<header-name>"`  
Default: `"X-Veilgate-Client"`  
Context: `verifiers.hmac`

Names the header that identifies which client secret to load.

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go)
- `validClientName()`
- `loadSecret()`

### Operational notes

- Client names are restricted to filename-safe characters.
- `..` is rejected to prevent path traversal.

## `clock_skew_sec`

Syntax:  `clock_skew_sec: <seconds>`  
Default: `300`  
Context: `verifiers.hmac`

Controls timestamp tolerance and limits replay. Requests outside the skew
window are rejected by the verifier and fall through to normal scoring.

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go)

### Operational notes

- Keep service clocks synchronized.
- Reduce only if all clients have reliable time sync.

## `max_body_bytes`

Syntax:  `max_body_bytes: <bytes>`  
Default: `1048576`  
Context: `verifiers.hmac`

Caps how many request body bytes the verifier reads and hashes. This protects
the proxy from memory exhaustion via huge signed requests.

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go)
- `readCappedBody()`

### Operational notes

- Requests larger than the cap should fail HMAC verification.
- Choose a value large enough for expected signed API bodies.

## `clients_dir`

Syntax:  `clients_dir: "<directory>"`  
Default: none  
Context: `verifiers.hmac`

Directory containing one `<client>.secret` file per client. File contents are
trimmed and used as the HMAC secret. Secrets are cached and reloaded when file
mtime changes.

### Code path

- [`internal/verifier/hmac.go`](../../internal/verifier/hmac.go)
- `NewHMACVerifier()`
- `loadSecret()`

### Operational notes

- Required when HMAC is enabled.
- Restrict directory and file permissions.
- Rotate secrets by replacing the secret file.

## Validation

Unsigned requests should fall through to normal scoring:

```bash
curl -i http://localhost:8080/api/internal
```

Signed request validation requires generating `X-Veilgate-Signature` using the
configured client secret and canonical string.

## Related

- [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md)
- [Module veilgate_challenge](veilgate_challenge.md)
- [Module veilgate_proxy](veilgate_proxy.md)

