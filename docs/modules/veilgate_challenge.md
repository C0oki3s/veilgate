# Module veilgate_challenge

The `veilgate_challenge` module serves proof-of-work (PoW) challenges for
requests that are suspicious but not high-confidence tarpit traffic. When a
client's score meets `score_challenge_threshold`, VeilGate returns an HTML page
containing a JavaScript PoW puzzle. On correct solution, the server issues a
signed pass token. The token is accepted on subsequent requests through either
a cookie or a configured header, routing those requests to the real upstream
for the token TTL.

This is analogous to NGINX's `limit_req_zone` combined with a CAPTCHAmechanism,
but operates server-side with HMAC-signed tokens and no third-party dependency.
Challenge behavior is controlled by both `veilgate.yaml` and
`rules/challenge.yaml`. The YAML config provides the secret and simple
overrides; the rule file controls the HTML template, cookie name, verify path,
SPA-aware response behavior, and related details.

## Challenge Protocol

1. Client request arrives; score ≥ `score_challenge_threshold`.
2. `Server.serve()` dispatches to `challengeHandler.ServeHTTP()`.
3. Handler serves the challenge HTML page containing difficulty, a fresh
   timestamp, and HMAC of that timestamp.
4. Client JavaScript iterates nonces until `SHA-256("<ts>.<nonce>")` starts
   with `difficulty` zero hex digits.
5. Browser POSTs `{ts, nonce}` to `verify_path`.
6. Server re-verifies HMAC of timestamp, validates the PoW against the nonce,
   checks token age ≤ TTL.
7. On success: server sets a cookie and/or returns the token in a JSON body
   for SPA-aware clients.
8. Client retries; `Handler.Passed()` accepts token → decision upgrades to
   `DecisionReal`.

## Token Format

```
<RFC3339-timestamp>.<HMAC-SHA256(secret, RFC3339-timestamp) hex>
```

Example:

```
2024-01-15T10:30:00Z.a3f2b8e1c9d5...
```

`Passed()` parses the token from the configured cookie name first, then from
the configured token header name. The token is split on the first `.`. The
timestamp part is parsed as RFC3339, compared against the current time within
`ttl_minutes`, and the HMAC is recomputed and compared in constant time.

```go
// internal/challenge/challenge.go (schematic)
func (h *Handler) Passed(r *http.Request) bool {
    token := tokenFromCookieOrHeader(r, h.cfg.CookieName, h.cfg.TokenHeaderName)
    if token == "" {
        return false
    }
    parts := strings.SplitN(token, ".", 2)
    ts, sig := parts[0], parts[1]
    if !hmac.Equal(computeHMAC(h.secret, ts), hexDecode(sig)) {
        return false
    }
    issued, _ := time.Parse(time.RFC3339, ts)
    return time.Since(issued) <= h.cfg.TTL
}
```

## Example Configuration

```yaml
mode: "challenge"

challenge:
  secret: "${VEILGATE_SECRET}"
  difficulty: 3
  ttl_minutes: 30
```

Example `rules/challenge.yaml` fields:

```yaml
difficulty: 3
token_ttl_minutes: 10
cookie_name: "veilgate_challenge"
verify_path: "/_g/verify"
token_header_name: "X-App-Token"
spa_aware_response: true
```

## Directives

- `challenge.secret`
- `challenge.difficulty`
- `challenge.ttl_minutes`
- `rules/challenge.yaml: verify_path`
- `rules/challenge.yaml: cookie_name`
- `rules/challenge.yaml: token_header_name`
- `rules/challenge.yaml: spa_aware_response`

## `challenge.secret`

Syntax:  `secret: "<string>"`  
Default: `"change-me-in-production-or-set-VEILGATE_SECRET"`  
Context: `challenge`

The HMAC key used to sign the fresh challenge timestamp and the issued pass
token. `VEILGATE_SECRET` in the environment overrides the config value at
startup. The override happens in `cmd/veilgate/main.go` before the server
starts.

VeilGate refuses to start outside `observe` mode when the secret is still the
placeholder value. This prevents silent deployment with unsigned tokens.

```go
// cmd/veilgate/main.go (schematic)
if secret := os.Getenv("VEILGATE_SECRET"); secret != "" {
    cfg.Challenge.Secret = secret
}
```

The same secret also seeds the HMAC verifier for the `challenge` path. Rotating
the secret immediately invalidates all outstanding tokens, requiring existing
challenged clients to complete the challenge flow again.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — `VEILGATE_SECRET` override.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) — signs the challenge and token.
- [`internal/config/config.go`](../../internal/config/config.go) — placeholder default and config struct.

### Operational notes

- Set `VEILGATE_SECRET` via a secret management system; do not store it in
  plain-text YAML in version control.
- Rotate by restarting with a new secret value.
- Treat it like an application signing key (256-bit entropy minimum).

### Validation

```bash
export VEILGATE_SECRET="$(openssl rand -hex 32)"
go run ./cmd/veilgate -config configs/veilgate.yaml
```

## `challenge.difficulty`

Syntax:  `difficulty: <integer>`  
Default: `4`  
Context: `challenge`, `rules/challenge.yaml`

Controls the PoW target. Difficulty `D` requires a SHA-256 digest whose hex
form begins with `D` zero characters. Each additional difficulty level
approximately 16× the expected work for the solving client.

| Difficulty | Expected hashes | ~Browser solve time |
| --- | --- | --- |
| 3 | ~4 096 | < 100 ms |
| 4 | ~65 536 | 100–500 ms |
| 5 | ~1 048 576 | 1–5 s |
| 6 | ~16 777 216 | 10–60 s |

Server-side verification is constant time regardless of difficulty.

### Code path

- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `verifyPOW(nonce, ts, difficulty)`
- Challenge HTML page receives `difficulty` as a JSON value in the template.

### Operational notes

- Use `4` as a starting point.
- Increasing to `5` is noticeable for legitimate users on slow devices.
- Do not rely on difficulty as the sole control; it is a cost increase, not a
  complete block.
- If automated tooling bypasses the challenge at difficulty 4 (rare), increase
  to 5 and add IP reputation or verifier controls.

### Validation

```bash
# Set mode to challenge, score above threshold
curl -i -A "python-requests/2.31.0" http://localhost:8080/.git/config
# Expect: 200 with challenge HTML body
```

## `challenge.ttl_minutes`

Syntax:  `ttl_minutes: <minutes>`  
Default: `30`  
Context: `challenge`

Sets how long a solved challenge token remains valid. `Passed()` parses the
RFC3339 timestamp from the token and rejects tokens older than `ttl_minutes`.
Clock skew tolerance is not applied; the server clock is authoritative.

### Code path

- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `Passed()` token validation.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `verify()` issues the token with a fresh timestamp.

### Operational notes

- Shorter TTLs reduce the value of a stolen token (30 min: stolen token usable
  for at most 30 min).
- Longer TTLs reduce user friction for slow scanners that re-use sessions.
- A valid token bypasses `challenge` decisions only. It does not bypass
  `tarpit` decisions.

### Validation

```bash
# Obtain a token (manual or scripted solve)
curl -s -X POST http://localhost:8080/_g/verify \
  -d '{"ts":"2024-01-15T10:30:00Z","nonce":"abc123"}'
```

## `verify_path`

Syntax:  `verify_path: "<path>"`  
Default: `"/_g/verify"`  
Context: `rules/challenge.yaml`

Defines the endpoint that receives PoW solutions. `serve()` in the proxy checks
this path before normal scoring and passes matched requests directly to the
challenge handler. This path is never forwarded to the upstream application.

```go
// internal/proxy/proxy.go
if s.challengeHandler != nil && r.URL.Path == s.challengeHandler.VerifyPath() {
    s.challengeHandler.ServeHTTP(w, r)
    return
}
```

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `serve()` bypass check.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `ServeHTTP()` verify branch.

### Operational notes

- Do not route this path to the upstream application.
- Keep it stable if clients or SPAs are built around the default path.
- The path is loaded from `rules/challenge.yaml` and hot-reloadable, but
  changing it during active sessions invalidates in-flight challenge pages.

### Validation

```bash
curl -i -X POST http://localhost:8080/_g/verify
# Expect: 400 or 403 (missing/invalid body), not 502 (upstream)
```

## `token_header_name`

Syntax:  `token_header_name: "<header-name>"`  
Default: `"X-App-Token"` (default rules)  
Context: `rules/challenge.yaml`

Allows SPA or API clients to submit the pass token through a custom HTTP header
instead of relying on cookies. This is useful in cross-origin contexts where
SameSite cookie restrictions would block the cookie-only flow.

On a valid solution, when `spa_aware_response: true`, the handler returns a
JSON response body containing the token:

```json
{
  "status": "ok",
  "token": "2024-01-15T10:30:00Z.a3f2b8e1c9d5..."
}
```

The SPA stores this value and injects it as `X-App-Token` (or the
configured name) on subsequent requests. `Passed()` checks the header name
after failing to find a cookie.

### Code path

- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `Passed()` header fallback.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `verify()` JSON response branch.

### Operational notes

- Header transport is useful for XHR/fetch clients that cannot set
  `credentials: "include"`.
- Treat the token like a short-lived bearer credential.
- Do not expose the token in URLs (query strings) to avoid logging.

### Validation

```bash
# Simulate SPA client with header token
TOKEN="2024-01-15T10:30:00Z.valid-hmac"
curl -H "X-App-Token: $TOKEN" http://localhost:8080/api/endpoint
```

## `spa_aware_response`

Syntax:  `spa_aware_response: true | false`  
Default: `false`  
Context: `rules/challenge.yaml`

When `true`, the verify endpoint returns `application/json` instead of an HTML
redirect after a successful challenge solution. The JSON body contains the token
field. The JavaScript challenge page reads the response type and either follows
the redirect (classic mode) or stores the token for header injection (SPA mode).

### Operational notes

- Enable when your application uses a JavaScript framework that intercepts
  navigation or when the challenge is served inside an iframe.
- Disable in traditional multi-page applications where HTTP redirects work.

## Troubleshooting

### Normal browser traffic is challenged

Check the fired signals before changing thresholds:

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
curl http://127.0.0.1:9090/metrics | grep veilgate_score
```

Common causes: missing `trusted_proxies` means private health check IP scores
above zero; sparse `Accept-Encoding` or missing `Sec-Fetch-*` headers on old
browsers; honeypot path in shared URL from a third-party service.

### Challenge page not shown (502 or connection reset)

The verify path must not match a route in the upstream application. Confirm:

```bash
curl -i -X GET http://localhost:8080/_g/verify
# Expect: 405 (challenge handler) or challenge HTML, not 502
```

### Tokens not accepted after restart

Rotating the secret (new `VEILGATE_SECRET`) invalidates all existing tokens.
Clients must re-solve the challenge. This is expected behavior for a secret
rotation.

## Related

- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_verifier](veilgate_verifier.md)
- [Challenge handler internals](../functionalities/challenge-handler.md)
- [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md)
- [PoW challenge walkthrough](../blog/pow-challenge-walkthrough.md)

## Example Configuration

```yaml
mode: "challenge"

challenge:
  secret: "${VEILGATE_SECRET}"
  difficulty: 3
  ttl_minutes: 30
```

Example `rules/challenge.yaml` fields:

```yaml
difficulty: 3
token_ttl_minutes: 10
cookie_name: "veilgate_challenge"
verify_path: "/_g/verify"
token_header_name: "X-App-Token"
spa_aware_response: true
```

## Directives

- `challenge.secret`
- `challenge.difficulty`
- `challenge.ttl_minutes`
- `rules/challenge.yaml: verify_path`
- `rules/challenge.yaml: cookie_name`
- `rules/challenge.yaml: token_header_name`
- `rules/challenge.yaml: spa_aware_response`

## `challenge.secret`

Syntax:  `secret: "<string>"`  
Default: `"change-me-in-production-or-set-VEILGATE_SECRET"`  
Context: `challenge`

Defines the HMAC key used to sign challenge payloads and issued pass tokens.
The environment variable `VEILGATE_SECRET` overrides the config value at
startup.

VeilGate refuses to start outside `observe` mode when the secret is still the
placeholder value.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) applies `VEILGATE_SECRET`.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) signs challenge and token payloads.
- [`internal/config/config.go`](../../internal/config/config.go) sets the placeholder default.

### Operational notes

- Set `VEILGATE_SECRET` before using `challenge`, `tarpit`, or `auto`.
- Rotate the secret to invalidate all outstanding challenge tokens.
- Treat the secret like an application signing key.

### Validation

```bash
export VEILGATE_SECRET="dev-secret"
go run ./cmd/veilgate -config configs/veilgate.yaml
```

## `challenge.difficulty`

Syntax:  `difficulty: <integer>`  
Default: `4`  
Context: `challenge`, `rules/challenge.yaml`

Controls the proof-of-work target. A difficulty of `4` requires a SHA-256
digest whose hex form begins with four zeroes. Higher values increase attacker
cost but also increase legitimate browser solve time.

### Code path

- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go)
- `normalizedDifficulty()`
- `verifyPOW()`

### Operational notes

- Use `4` as a starting point.
- Increasing to `5` can be noticeably slower for real users.
- Do not rely on challenge difficulty as the only control. It is a cost
  increase, not a complete block.

### Validation

```bash
curl -i -A "python-requests/2.31.0" http://localhost:8080/.git/config
```

Expected result in `challenge` mode: a challenge response for a score above the
challenge threshold.

## `challenge.ttl_minutes`

Syntax:  `ttl_minutes: <minutes>`  
Default: `30`  
Context: `challenge`

Sets how long a solved challenge token remains valid. The token format is an
RFC3339 timestamp and HMAC signature. `Passed()` accepts the token from either
the configured cookie or configured header.

### Code path

- [`internal/challenge/challenge.go#L74`](../../internal/challenge/challenge.go#L74) validates tokens.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) issues tokens in `verify()`.

### Operational notes

- Shorter TTLs reduce the value of stolen tokens.
- Longer TTLs reduce user friction.
- A valid token bypasses only challenge-tier decisions. It does not bypass a
  tarpit-tier decision.

### Validation

```bash
curl -i -X POST http://localhost:8080/_g/verify
```

An unsigned or malformed verify request should fail.

## `verify_path`

Syntax:  `verify_path: "<path>"`  
Default: `"/_g/verify"`  
Context: `rules/challenge.yaml`

Defines the endpoint that receives proof-of-work solutions. The proxy passes
this path directly to the challenge handler before normal scoring.

### Code path

- [`internal/proxy/proxy.go#L163`](../../internal/proxy/proxy.go#L163)
- [`internal/challenge/challenge.go#L124`](../../internal/challenge/challenge.go#L124)

### Operational notes

- Do not route this path to the upstream application.
- Keep it stable if clients or SPAs are built around the default path.

## `token_header_name`

Syntax:  `token_header_name: "<header-name>"`  
Default: `"X-App-Token"` in the default rules  
Context: `rules/challenge.yaml`

Allows cross-origin or SPA clients to submit the same pass token through a
header instead of relying only on cookies.

### Code path

- [`internal/challenge/challenge.go#L74`](../../internal/challenge/challenge.go#L74)
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) returns token metadata in JSON.

### Operational notes

- Header transport is useful when SameSite or cross-origin cookie behavior
  would block a cookie-only flow.
- Treat the token like a bearer credential until it expires.

## Troubleshooting

### Normal browser traffic is challenged

Check the fired signals before changing thresholds:

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
curl http://127.0.0.1:9090/metrics | grep veilgate_score
```

Review sparse header, Accept-Encoding, Sec-Fetch, honeypot path, and trusted
proxy configuration.

## Related

- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_verifier](veilgate_verifier.md)
- [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md)

