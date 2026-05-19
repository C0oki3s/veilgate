# Module veilgate_tls_fingerprinting

The `veilgate_tls_fingerprinting` module captures TLS ClientHello data and
classifies clients using JA3 and JA4 fingerprints. It contributes detector
signals such as `tls_agent`, `tls_bot`, and `tls_non_browser`.

This module requires VeilGate to terminate TLS directly. If TLS is terminated
by a load balancer, CDN, or edge proxy before traffic reaches VeilGate, this
module cannot see the real client handshake and will produce no signal.

## How It Works

TLS fingerprinting intercepts the ClientHello message — the first record sent
by the TLS client — before Go's TLS stack processes it. This is achieved by
wrapping the `net.Listener` with `internal/tlsfp.Listener`.

```
Client TCP connect
    │
    ▼
tlsfp.Listener.Accept()
    │
    ├── Peek at first TLS record (ClientHello)
    ├── Parse handshake: cipher suites, extensions, curves, compression, ALPN
    ├── Compute JA3 hash: MD5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePoints)
    ├── Compute JA4 hash: t<version><SNI-present><cipher-count><ext-count><ALPN-first>_<sorted-ciphers>_<sorted-extensions>
    ├── Store fingerprint by remote address
    │
    ▼
Go TLS handshake proceeds normally on the same connection
```

The detector's `scoreTLS()` function looks up the stored fingerprint for the
client's remote address and classifies it against `rules/tls_fingerprints.yaml`.

### JA3 fingerprint format

```
MD5("<SSLVersion>,<Ciphers>,<Extensions>,<EllipticCurves>,<EllipticCurvePoints>")
```

Each field is a sorted hyphen-delimited list of decimal values. GREASE values
are excluded before hashing.

### JA4 fingerprint format

```
t<tls_version><has_sni><cipher_count><ext_count><alpn_first>_<sorted_cipher_hex>_<sorted_ext_hex>
```

Example: `t13d1516h2_002f0035...`

JA4 is more specific than JA3 and is less susceptible to randomization
because it captures ALPN and extension ordering.

### Prefix matching

`tls_fingerprints.yaml` supports both exact hash matches and prefix matches.
Prefix matching allows grouping related tool versions that share a fingerprint
prefix:

```yaml
fingerprints:
  - ja4_prefix: "t13d"
    label: "tls13-client"
    category: "generic"
  - ja3: "a0e9f5d64349fb13191bc781f81f42e1"
    label: "python-requests-2.x"
    category: "bot"
    confidence: 0.9
```

Exact matches take precedence over prefix matches.

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
by remote address, and then lets Go's TLS handshake continue normally.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — TLS listener setup.
- [`internal/tlsfp/listener.go`](../../internal/tlsfp/listener.go) — `Listener.Accept()`, ClientHello parser.
- [`internal/tlsfp/ja4.go`](../../internal/tlsfp/ja4.go) — JA4 hash computation.
- [`internal/detector/tls.go`](../../internal/detector/tls.go) — `scoreTLS()` signal evaluation.
- [`internal/tlsfp/database.go`](../../internal/tlsfp/database.go) — fingerprint classification DB.

### Operational notes

- TLS private keys are critical secrets. Restrict file permissions to the
  VeilGate service user.
- If a CDN, ALB, or NGINX terminates TLS before VeilGate, the real ClientHello
  is invisible. All TLS signals will be absent.
- Use this module when fingerprint quality matters more than delegating TLS to
  an edge component. In practice, TLS termination at VeilGate is most viable
  for on-premise or bare-metal deployments.
- VeilGate sets TLS minimum version to 1.2 and does not currently support
  TLS 1.3 downgrade detection.

### Validation

```bash
curl -k -i https://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep tls
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## `tls.cert_file`

Syntax:  `cert_file: "<path>"`  
Default: `"cert.pem"` in sample config; empty if omitted  
Context: `tls`

Specifies the certificate file loaded by `tls.LoadX509KeyPair()`. The
certificate must match the private key.

### Operational notes

- The service user must be able to read the certificate (but not necessarily
  the private key directory).
- Renew certificates through your normal PKI/ACME process. A restart is
  required to pick up a new certificate file; VeilGate does not currently
  hot-reload TLS certificates.

### Validation

```bash
openssl x509 -in /etc/veilgate/cert.pem -noout -subject -dates
```

## `tls.key_file`

Syntax:  `key_file: "<path>"`  
Default: `"key.pem"` in sample config; empty if omitted  
Context: `tls`

Specifies the private key file. Must be readable by the service user.

### Operational notes

- `chmod 600 key.pem` and `chown veilgate:veilgate key.pem`.
- Never commit private keys to source control.
- Rotate keys by replacing the file and restarting.

### Validation

```bash
ls -la /etc/veilgate/key.pem
# Should show: -rw------- 1 veilgate veilgate ...
```

## `rules/tls_fingerprints.yaml`

Syntax:  TLS fingerprint database  
Default: embedded TLS fingerprints  
Context: `rules_dir`

Maps JA3 and JA4 exact hashes or prefixes to labels, categories, and
confidence values. The detector uses the classification result to fire
`tls_agent`, `tls_bot`, or `tls_non_browser` signals.

```yaml
# rules/tls_fingerprints.yaml (excerpt)
fingerprints:
  # Exact JA3 match — known scanner
  - ja3: "a0e9f5d64349fb13191bc781f81f42e1"
    label: "python-requests"
    category: "bot"
    confidence: 0.95

  # JA4 prefix match — generic TLS 1.3 automation
  - ja4_prefix: "t13d"
    label: "tls13-automation"
    category: "suspicious"
    confidence: 0.5

  # Known browser baseline (Chrome 120)
  - ja3: "cd08e31494f9531f560d64c695473da9"
    label: "chrome-120"
    category: "browser"
    confidence: 1.0
```

### Code path

- [`internal/rules/loader.go`](../../internal/rules/loader.go) — loads and parses the file.
- [`internal/tlsfp/database.go`](../../internal/tlsfp/database.go) — `Database.Apply()`, `Classify()`.
- [`internal/detector/tls.go`](../../internal/detector/tls.go) — `scoreTLS()` uses classification.

### Operational notes

- Hot reload is registered only when `tls.enabled: true`.
- Update browser fingerprints periodically; browser TLS handshakes change
  with browser version updates.
- Treat `non_browser` classification as a signal, not a final verdict.
  Many internal services legitimately send non-browser fingerprints.
- `confidence` scales the points contributed. `1.0` contributes full points
  from the `tls_agent` or `tls_bot` weight in `detector.yaml`.

## Deployment Topology

| Deployment | TLS at VeilGate | Fingerprints available |
| --- | --- | --- |
| VeilGate directly on port 443 | yes | yes |
| VeilGate behind NGINX (HTTPS upstream) | yes, NGINX → VeilGate HTTPS | yes (NGINX handshake, not client's) |
| VeilGate behind AWS ALB | no (ALB terminates) | no |
| VeilGate behind Cloudflare | no | no |
| VeilGate on plain HTTP, NGINX on 443 | no | no |

When TLS fingerprinting is unavailable, configure the remaining detector
signals (honeypot, user-agent, IP reputation, H2FP) for compensation.

## Troubleshooting

### No TLS signals firing

Confirm:

```bash
# VeilGate is listening on HTTPS
curl -k -i https://localhost:8080/
# Check TLS signal presence
curl http://127.0.0.1:9090/metrics | grep 'signal="tls_'
```

Common causes: `tls.enabled: false`; clients are connecting over HTTP; TLS
terminated by upstream load balancer; cert or key file unreadable at startup.

## Related

- [Module veilgate_http2_fingerprinting](veilgate_http2_fingerprinting.md)
- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_rules](veilgate_rules.md)
- [TLS fingerprinting internals](../functionalities/tls-fingerprinting.md)

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

- [Module veilgate_http2_fingerprinting](veilgate_http2_fingerprinting.md)
- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_rules](veilgate_rules.md)
