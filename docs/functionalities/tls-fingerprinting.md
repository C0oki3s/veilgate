# Module veilgate_tls_fingerprinting

The `veilgate_tls_fingerprinting` module captures TLS ClientHello data and
classifies clients using JA3 and JA4 fingerprints. It contributes detector
signals such as `tls_agent`, `tls_bot`, and `tls_non_browser`.

This module has two operating modes:

- **Self-TLS** (default): VeilGate terminates TLS directly, peeking at the raw
  ClientHello for the highest-fidelity, unforgeable fingerprint.
- **CDN passthrough** (`cdn_mode`): VeilGate sits behind a CDN that terminates
  TLS and injects fingerprint headers. Requires `trusted_proxies` as a security
  gate. See [CDN fingerprinting](../how-to/cdn-fingerprinting.md).

## Example Configuration

**Self-TLS (recommended when Cloudflare is not in front):**

```yaml
tls:
  enabled: true
  cert_file: "/etc/veilgate/cert.pem"
  key_file: "/etc/veilgate/key.pem"

rules_dir: "~/.veilgate/rules"
```

**CDN passthrough (Cloudflare example):**

```yaml
tls:
  enabled: true          # still terminate the Cloudflare→VeilGate TLS leg
  cert_file: "/etc/veilgate/tls/cert.pem"
  key_file:  "/etc/veilgate/tls/key.pem"

detector:
  trusted_proxies:
    - 173.245.48.0/20    # Cloudflare IPv4 — full list at cloudflare.com/ips
  cdn_mode: cloudflare   # read cf-ja4 and CF-Connecting-IP from Cloudflare
```

## Directives

- `tls.enabled`
- `tls.cert_file`
- `tls.key_file`
- `detector.cdn_mode`
- `rules/tls_fingerprints.yaml`

## `tls.enabled`

Syntax:  `enabled: true | false`  
Default: `false`  
Context: `tls`

Enables HTTPS termination at the VeilGate listener. When enabled, the listener
peeks at the first TLS record, parses ClientHello data, stores the fingerprint
by remote address, and then lets Go's TLS handshake continue.

### Code path

- [`cmd/veilgate/main.go#L71`](../../cmd/veilgate/main.go#L71)
- [`internal/tlsfp/listener.go`](../../internal/tlsfp/listener.go)
- [`internal/tlsfp/ja4.go`](../../internal/tlsfp/ja4.go)
- [`internal/detector/tls.go`](../../internal/detector/tls.go)

### Operational notes

- TLS private keys are critical secrets.
- If a CDN terminates TLS before VeilGate, this module cannot see the raw
  ClientHello. Set `detector.cdn_mode` to recover fingerprints from CDN-injected
  headers instead.
- Self-TLS produces unforgeable fingerprints; CDN mode depends on the CDN's
  accuracy and requires `trusted_proxies` to prevent header forgery.
- Use self-TLS when fingerprint quality is the top priority and CDN pass-through
  when Cloudflare/CDN DDoS protection outweighs the fingerprint quality trade-off.

### Validation

```bash
curl -k -i https://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep tls
```

## `tls.cert_file`

Syntax:  `cert_file: "<path>"`  
Default: `"cert.pem"` in sample config; empty if omitted  
Context: `tls`

Specifies the certificate file loaded by `tls.LoadX509KeyPair()`.

### Code path

- [`cmd/veilgate/main.go#L71`](../../cmd/veilgate/main.go#L71)

### Operational notes

- The service user must be able to read the certificate.
- Renew certificates through your normal certificate-management process.

## `tls.key_file`

Syntax:  `key_file: "<path>"`  
Default: `"key.pem"` in sample config; empty if omitted  
Context: `tls`

Specifies the private key file loaded with the certificate.

### Code path

- [`cmd/veilgate/main.go#L71`](../../cmd/veilgate/main.go#L71)

### Operational notes

- Restrict file permissions.
- Never commit private keys to the repository.

## `rules/tls_fingerprints.yaml`

Syntax:  TLS fingerprint database  
Default: embedded TLS fingerprints  
Context: `rules_dir`

Maps JA3 and JA4 exact hashes or prefixes to labels, categories, and
confidence values. The detector uses the classifier result to add TLS-related
signals.

### Code path

- [`internal/rules/loader.go#L173`](../../internal/rules/loader.go#L173)
- [`internal/tlsfp/database.go`](../../internal/tlsfp/database.go)
- [`internal/detector/tls.go`](../../internal/detector/tls.go)

### Operational notes

- Keep browser fingerprints current.
- Treat non-browser classification as a signal, not a final verdict.
- Hot reload is registered only when TLS fingerprinting is enabled.

## Troubleshooting

### No TLS fingerprints (self-TLS mode)

Check:

- `tls.enabled: true`;
- clients are using `https://`;
- TLS is not terminated before VeilGate;
- cert and key files are readable by the service user.

### JA4 metrics are zero (CDN mode)

Check:

- `detector.cdn_mode` matches your CDN.
- The CDN's IP ranges are listed under `detector.trusted_proxies` — fingerprint
  headers are silently ignored from untrusted source IPs.
- Cloudflare JA4 requires the **Enterprise Bot Management** add-on. Without it
  `cf-ja4` is not set; the existing HTTP and IP signals still work.
- For Fastly: no header is sent by default; configure `set bereq.http.X-JA4 =
  tls.client.ja4;` in VCL and use `cdn_mode: fastly`.

## Related

- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_rules](../modules/veilgate_rules.md)
- [CDN fingerprinting how-to](../how-to/cdn-fingerprinting.md)
- [Configuration: `detector.cdn_mode`](../config/detector.md#cdn_mode)

