# Module veilgate_challenge

The `veilgate_challenge` module serves proof-of-work challenges for
requests that are suspicious but not high-confidence tarpit traffic. It issues
a signed pass token after a valid solution. The token can be carried as an HTTP
cookie or as a configured header for SPA/API clients.

Challenge behavior is controlled by both `veilgate.yaml` and
`rules/challenge.yaml`. The YAML config provides the secret and simple
overrides; the rule file controls the HTML template, cookie names, verify path,
SPA-aware response behavior, and related details.

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
verify_path: "/__veilgate/verify"
token_header_name: "X-Veilgate-Token"
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
curl -i -X POST http://localhost:8080/__veilgate/verify
```

An unsigned or malformed verify request should fail.

## `verify_path`

Syntax:  `verify_path: "<path>"`  
Default: `"/__veilgate/verify"`  
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
Default: `"X-Veilgate-Token"` in the default rules  
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

- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_verifier](../modules/veilgate_verifier.md)
- [How-to: server-to-server HMAC](../how-to/server-to-server-hmac.md)
- [Request classification: SPA, browser page, server-to-server](./request-classification.md)

