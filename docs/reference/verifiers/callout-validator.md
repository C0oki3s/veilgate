# HTTP Callout Validator

The callout validator delegates credential validation to an operator-supplied
HTTP endpoint and caches affirmative responses. It is used by the
[cookie verifier](cookie.md) and the [header verifier](header.md) when neither
a static opaque value nor a JWT signature is the right fit — typically when
your existing session service is the source of truth.

Source: `internal/verifier/callout.go`. Part of the
[credential-verifiers project](../../design/credential-verifiers.md) (ship #5).

## When to use it

| Situation | Why callout |
|-----------|-------------|
| You already run a session service with an `/introspect`-style endpoint | Reuse it — no token migration needed. |
| Tokens are short-lived, server-issued, and revocable mid-session | A static cache or JWT-with-long-exp can't model revocation; callout can. |
| Validation depends on per-request context (account state, feature flags) | Your service has it, VeilGate doesn't. |

If your tokens are static shared secrets, the [opaque validator](cookie.md#opaque-validator)
is simpler. If they are signed JWTs, the [JWT validator](jwt-validator.md) is
faster (no network hop).

## Configuration

```yaml
verifiers:
  cookies:
    - name:        SESSION
      validator:   callout
      url:         https://internal-auth.example.com/veilgate/introspect
      cache_ttl:   30s              # default
      timeout:     5s               # default
      auth_header: X-Veilgate-Secret
      auth_value:  ${VEILGATE_CALLOUT_SECRET}

  headers:
    - name:        X-Internal-Service-Token
      validator:   callout
      url:         https://internal-auth.example.com/veilgate/introspect
      cache_ttl:   60s
```

### Fields

| Field         | Default     | Notes |
|---------------|-------------|-------|
| `url`         | _required_  | The endpoint VeilGate POSTs to. HTTPS strongly recommended. |
| `cache_ttl`   | `30s`       | How long affirmative results are cached. A per-result TTL in the response body overrides this when smaller. |
| `timeout`     | `5s`        | Per-callout HTTP timeout. Keep tight — the validator is on the proxy hot path. |
| `auth_header` | _none_      | Optional header VeilGate sends so your upstream can authenticate VeilGate itself. |
| `auth_value`  | _none_      | Value paired with `auth_header`. |

## Protocol

### Request

```
POST <url>
Content-Type: application/json
Accept: application/json
<auth_header>: <auth_value>      (when configured)

{"value": "<the credential as VeilGate received it>"}
```

The credential ships in the JSON body so it does not leak into upstream
access logs or proxy chains the way URL- or header-borne credentials can.

### Response

| Status   | Meaning             |
|----------|---------------------|
| `200-299` with empty body | Valid. No client id; no per-result TTL. |
| `200-299` with JSON body  | Valid. Optional `client` and `cache_ttl`. |
| `4xx` / `5xx`             | Invalid. Reason recorded as `callout rejected`. |

JSON body shape:

```json
{
  "client": "alice@example.com",
  "cache_ttl": 60
}
```

- `client` — recorded as the audit identifier. Optional.
- `cache_ttl` — seconds. When present and smaller than the configured
  `cache_ttl`, **takes precedence**. Lets a short-lived token request a
  short cache window.

## Caching

- **Affirmative results** are cached for `min(cache_ttl, per-result cache_ttl)`.
- **Negative results are never cached.** A transient 401 from the upstream
  must not lock a credential out for the cache window. The cost is a network
  hop per failed attempt — acceptable because attackers presenting random
  tokens already pay for being wrong.
- The cache key is `sha256(credential value)`. The plaintext value is never
  stored.
- Cache entries are evicted lazily on next lookup; there is no global
  reaper. A 30-second window means stale entries vanish within seconds of
  next traffic.

## Security model

- **Credential confidentiality.** Always run the callout endpoint over HTTPS.
  The body contains the user's session token — TLS is the only thing keeping
  it private in transit.
- **Mutual authn.** Use `auth_header` / `auth_value` so your upstream knows
  the request actually came from VeilGate. A shared secret is fine; mTLS is
  better when your internal mesh supports it.
- **Audit reasons stay coarse.** A non-2xx is reported as `callout rejected`
  regardless of the upstream's HTTP status. The upstream's status codes are
  an implementation detail you may evolve without affecting VeilGate's audit
  schema.
- **Response body cap.** Responses are read with a 64 KiB cap. A
  misconfigured validator cannot OOM the proxy.
- **No request retry.** A transport error returns reject without retry. The
  failure mode under sustained validator outage is "challenge tier engages" —
  by design. Operators who want availability over correctness can pair
  callout with a longer `cache_ttl` so a brief outage rides on cached
  acceptances.
- **Tarpit still trumps.** Same invariant as every verifier
  (`internal/proxy/proxy.go:238-256`).

## Implementing the callout endpoint

A minimal Go handler:

```go
http.HandleFunc("/veilgate/introspect", func(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("X-Veilgate-Secret") != os.Getenv("VEILGATE_CALLOUT_SECRET") {
        http.Error(w, "forbidden", 403); return
    }
    var body struct{ Value string `json:"value"` }
    _ = json.NewDecoder(r.Body).Decode(&body)

    sess, ok := store.Lookup(body.Value)
    if !ok || sess.Revoked || time.Now().After(sess.ExpiresAt) {
        http.Error(w, "no", 401); return
    }
    _ = json.NewEncoder(w).Encode(map[string]any{
        "client":    sess.UserID,
        "cache_ttl": int(time.Until(sess.ExpiresAt).Seconds()),
    })
})
```

Five lines past the auth check. Existing session services usually need
nothing more than a thin adapter on top.

## Examples

### Internal session service

```yaml
verifiers:
  cookies:
    - name:        SESSION
      validator:   callout
      url:         https://auth-internal/veilgate/introspect
      cache_ttl:   30s
      auth_header: X-Veilgate-Secret
      auth_value:  ${VEILGATE_CALLOUT_SECRET}
```

### OAuth2 introspection (RFC 7662) adapter

OAuth2 introspection responds in a different shape than VeilGate's, so wrap
it in a tiny adapter service that returns VeilGate's expected JSON. Point
VeilGate at the adapter, not at the introspection endpoint directly.

### Chain with bearer fallback

```yaml
verifiers:
  bearer:
    enabled: true
    tokens_dir: /etc/veilgate/api-tokens
  cookies:
    - name: SESSION
      validator: callout
      url: https://auth-internal/veilgate/introspect
```

Bearer matches first for API consumers; cookie callout matches for browser
users; everyone else falls through to the score / challenge tier.

## Operational notes

- Startup log: `cookie verifier enabled cookie=SESSION validator=callout`.
  No initial probe of the URL — failures are surfaced at first traffic so a
  validator that is slow to come up does not crash VeilGate.
- Add a Prometheus dashboard panel for `callout` rejection rate; a spike
  usually means the upstream changed shape or rotated its auth secret.
- Set `cache_ttl` deliberately: longer cache = better proxy latency but more
  revocation lag.

## See also

- [Credential verifiers — design tracker](../../design/credential-verifiers.md)
- [Cookie verifier](cookie.md)
- [Header verifier](header.md)
- [JWT validator](jwt-validator.md) — alternative when tokens are signed
- [Callout validator source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/callout.go)
- [RFC 7662 — OAuth2 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
