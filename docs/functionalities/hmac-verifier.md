# Module veilgate_verifier

The `veilgate_verifier` module documents optional request verifier chains. The
current implemented verifier is HMAC. A verifier can mark a non-tarpit request
as trusted enough to skip the challenge tier.

Verifier acceptance does not override a tarpit decision. This protects against
stolen verifier material being used to hide high-confidence attack behavior.

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
- [Module veilgate_challenge](../modules/veilgate_challenge.md)
- [Module veilgate_proxy](../modules/veilgate_proxy.md)

