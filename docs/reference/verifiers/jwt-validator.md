# JWT Validator

The JWT validator verifies a signed JSON Web Token against a JWKS-published
public key set, then asserts standard claims (`iss`, `aud`, `exp`, `nbf`) and
extracts a client identifier from a configured claim. It is used by the
[cookie verifier](cookie.md) and the [header verifier](header.md) when the
credential is a signed token rather than an opaque secret.

Source: `internal/verifier/jwt.go`. Library: `github.com/golang-jwt/jwt/v5`.
Part of the [credential-verifiers project](../../design/credential-verifiers.md)
(ship #4).

## When to use it

Reach for the JWT validator when an upstream identity system already issues
signed tokens you can verify locally. Common cases:

| Source                         | Header / cookie                  |
|--------------------------------|----------------------------------|
| Cloudflare Access              | `CF-Access-Jwt-Assertion` header |
| Google IAP                     | `X-Goog-IAP-JWT-Assertion` header |
| Auth0 / Okta / Keycloak        | session cookie                   |
| Internal OIDC provider         | session cookie or bearer         |

If your token is a random opaque string with no signature, use the
[opaque validator](cookie.md#opaque-validator) instead.

## Configuration

Configured inline on a cookie or header verifier entry — same fields apply to
both:

```yaml
verifiers:
  cookies:
    - name:           SESSION_JWT
      validator:      jwt
      jwks_url:       https://auth.example.com/.well-known/jwks.json
      issuer:         https://auth.example.com
      audience:       veilgate
      client_claim:   sub                    # default
      algorithms:     [RS256, ES256]          # default
      refresh_interval: 1h                    # default

  headers:
    - name:           CF-Access-Jwt-Assertion
      validator:      jwt
      jwks_url:       https://team.cloudflareaccess.com/cdn-cgi/access/certs
      audience:       12345.cloudflareaccess.com
```

### Fields

| Field              | Default            | Notes |
|--------------------|--------------------|-------|
| `jwks_url`         | _required_         | HTTPS endpoint serving an RFC 7517 JWKS. Fetched at startup; refreshed every `refresh_interval`. |
| `issuer`           | _none_             | When set, must equal the token's `iss` claim exactly. **Strongly recommended in production.** |
| `audience`         | _none_             | When set, must appear in the token's `aud` claim (string or array). **Strongly recommended.** |
| `client_claim`     | `sub`              | The claim whose value becomes the audit client id. |
| `algorithms`       | `[RS256, ES256]`   | Allow-list of `alg` header values. Symmetric algorithms (`HS256/384/512`) and `none` are stripped unconditionally — see [Security model](#security-model). |
| `refresh_interval` | `1h`               | Background JWKS refresh cadence. Duration string (`30m`, `1h`, `24h`). |

## How it works

1. **Startup** — fetch the JWKS, parse each key (RSA `n/e` or EC `x/y/crv`)
   into a `kid → crypto.PublicKey` map. Fail loudly if the URL is unreachable
   or returns no usable keys.
2. **Background refresh** — a goroutine re-fetches every `refresh_interval`.
   Transient failures are swallowed; the cached keys remain valid.
3. **Per-request validation**:
   - Parse the JWT header, look up the `kid` in the cache.
   - **Cache miss** → one synchronous refresh, then retry. This makes key
     rotations graceful: a fresh `kid` shows up on the first request after
     the IdP rotates, not after the next scheduled refresh.
   - Verify the signature with `jwt.Parser.Parse` constrained to the
     configured algorithms.
   - Check `iss`, `aud`, `exp`, `nbf`.
   - Extract `client_claim`; return it as the audit client id.

```
Cookie: SESSION_JWT=eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0…
                                       │
                                       ▼
                            kid → public key (cached)
                                       │
                                       ▼
                          signature verify (RS256/ES256)
                                       │
                                       ▼
                          claim checks (iss/aud/exp/nbf)
                                       │
                                       ▼
                          sub → "alice@example.com"  → DecisionReal
```

## Security model

- **No symmetric algorithms.** `HS256/384/512` and `none` are stripped from
  the algorithm list at startup. Reasoning: shipping a shared HMAC secret in
  `veilgate.yaml` that the IdP also holds is a footgun, not a feature. A
  deployment with a JWKS URL is already on asymmetric keys.
- **`kid` is mandatory.** A token without a `kid` header is rejected. Any
  real JWKS-based deployment names its keys; tokens that omit `kid` are
  either misconfigured or hostile.
- **Algorithm confusion is blocked.** `jwt.WithValidMethods` is passed to
  the parser so a token claiming `HS256` against an RSA key (the classic
  "algorithm confusion" attack) cannot succeed.
- **JWKS body cap.** JWKS responses are read with a 1 MiB cap so a malicious
  or misconfigured endpoint cannot exhaust memory.
- **Audit reasons are coarse.** All signature-, expiry-, and `nbf`-failures
  collapse to `reason="signature invalid"`. The claim-specific reasons
  (`iss mismatch`, `aud mismatch`) only fire when the signature is valid.
  This minimises caller-controlled audit-log noise.
- **Tarpit still trumps.** A valid JWT does not bypass a tarpit decision —
  same invariant as every other verifier (`internal/proxy/proxy.go:238-256`).

### What the validator does NOT do

- **Revocation.** A leaked-but-unexpired token remains valid until `exp`.
  If your IdP supports introspection or a `jti` blocklist, prefer the
  [callout validator](callout-validator.md) (ship #5) or pair JWT with a
  short token lifetime.
- **Scope / role assertion.** Only the configured `iss` / `aud` / a present
  `client_claim` are checked. Authorisation (which endpoints this client may
  call) belongs to your upstream, not to VeilGate.

## Examples

### Cloudflare Access pass-through

```yaml
verifiers:
  headers:
    - name:         CF-Access-Jwt-Assertion
      validator:    jwt
      jwks_url:     https://yourteam.cloudflareaccess.com/cdn-cgi/access/certs
      audience:     12345aud.cloudflareaccess.com    # from Access app config
      client_claim: email                            # CF emits email in sub-like claims
```

### Auth0 session cookie

```yaml
verifiers:
  cookies:
    - name:         SESSION_JWT
      validator:    jwt
      jwks_url:     https://tenant.auth0.com/.well-known/jwks.json
      issuer:       https://tenant.auth0.com/
      audience:     https://api.example.com
```

### Mixed chain

JWT cookie for browser users + bearer for API consumers + HMAC for webhooks:

```yaml
verifiers:
  hmac:
    enabled: true
    clients_dir: /etc/veilgate/hmac
  bearer:
    enabled: true
    tokens_dir: /etc/veilgate/api-tokens
  cookies:
    - name: SESSION_JWT
      validator: jwt
      jwks_url: https://auth.example.com/.well-known/jwks.json
      issuer: https://auth.example.com
      audience: veilgate
```

Chain order: HMAC → bearer → cookies → headers. First match wins.

## Operational notes

- Startup audit: `cookie verifier enabled cookie=SESSION_JWT validator=jwt`,
  followed by the JWKS fetch outcome on the validator side.
- A JWKS endpoint that returns zero usable keys at startup is a startup error
  — operators see it immediately rather than discovering it on first
  challenged request.
- Background JWKS refreshes log nothing on success; transient failures are
  silently retried at the next interval.
- The validator runs one goroutine per configured JWT validator entry for
  background refresh. These run for the process lifetime — fine for VeilGate
  which sets them up once at startup and never tears them down.

## See also

- [Credential verifiers — design tracker](../../design/credential-verifiers.md)
- [Cookie verifier](cookie.md)
- [Header verifier](header.md)
- [JWT validator source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/jwt.go)
- [RFC 7517 — JSON Web Key](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7519 — JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
