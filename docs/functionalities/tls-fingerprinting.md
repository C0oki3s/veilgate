# Module veilgate_tls_fingerprinting

The `veilgate_tls_fingerprinting` module captures TLS ClientHello data and
classifies clients using JA3 and JA4 fingerprints. It contributes detector
signals such as `tls_agent`, `tls_bot`, and `tls_non_browser`.

This module requires VeilGate to terminate TLS directly.

## Example Configuration

```yaml
tls:
  enabled: true
  cert_file: "/etc/veilgate/cert.pem"
  key_file: "/etc/veilgate/key.pem"

rules_dir: "~/.veilgate/rules"
```

## Directives

- `tls.enabled`
- `tls.cert_file`
- `tls.key_file`
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
- If NGINX, Envoy, ALB, or a CDN terminates TLS before VeilGate, this module
  cannot see the real client handshake.
- Use this module when fingerprint quality matters more than delegating TLS to
  another edge component.

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

### No TLS fingerprints

Check:

- `tls.enabled: true`;
- clients are using `https://`;
- TLS is not terminated before VeilGate;
- cert and key files are readable by the service user.

## Related

- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_rules](../modules/veilgate_rules.md)

