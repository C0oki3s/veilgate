# Cookie Verifier

The cookie verifier accepts a request when a named cookie carries a value
that the configured **validator** approves. It is the bridge between
operator-owned session systems (SSO, internal auth, CDN-set JWTs) and
VeilGate's challenge-bypass surface.

Source: `internal/verifier/cookie.go`. Part of the
[credential-verifiers project](../../design/credential-verifiers.md) (ship #2).

## When to use it

Use a cookie verifier when **logged-in users on your site should never see a
PoW challenge**. The browser is already carrying a session cookie; tell
VeilGate to trust it.

You can pair it with the bearer verifier (for API consumers) or with HMAC
(for high-value endpoints) — the verifier chain short-circuits on the first
acceptance.

## Configuration

```yaml
verifiers:
  cookies:
    - name:       MY_AUTH_SESSION
      validator:  opaque
      tokens_dir: /etc/veilgate/sessions

    - name:       ACCESS_JWT          # JWT lands in ship #4
      validator:  jwt
      jwks_url:   https://auth.example.com/.well-known/jwks.json
```

Each entry under `cookies:` produces one verifier in the chain in declaration
order. The audit name is `cookie:<name>` to disambiguate when multiple cookie
verifiers are installed.

### Fields

| Field        | Default     | Notes |
|--------------|-------------|-------|
| `name`       | _required_  | The cookie name to read from the request. Case-sensitive, exact match. |
| `validator`  | `opaque`    | Validator type. See [Validators](#validators). |
| `tokens_dir` | _required when `validator: opaque`_ | Directory of pre-shared session values. Same layout as the bearer verifier's `tokens_dir`. |

## Validators

A **validator** answers "is this credential value good?" Separating the
cookie's *location* (verifier) from its *validation* (validator) means an
operator can swap in a new validator type without touching the cookie wiring.

| Validator   | Ship | Use case |
|-------------|------|----------|
| `opaque`    | #2 (this page) | Pre-shared session values; sha256 lookup against a directory of files. |
| `jwt`       | #4 (pending)   | Verify a signed token via JWKS, assert claims. |
| `callout`   | #5 (pending)   | Delegate to an HTTP endpoint with a TTL cache. |

The yaml shape is forward-compatible — declaring `validator: jwt` today
returns a clear startup error pointing at the future ship until #4 lands.

### `opaque` validator

Same layout and behavior as the [bearer verifier's `tokens_dir`](bearer.md):

```
tokens_dir/
├── alice.token              # client id "alice", contents = the session value
├── partner-acme.token
└── partner-acme-2.token     # second active value for "partner-acme" (rotation)
```

- Filename without extension → client id used in audit logs.
- File contents → the raw cookie value VeilGate compares against.
- Lookup is constant-time via sha256.
- Directory is hot-reloaded on mtime change — no restart.
- Hidden files and subdirectories are skipped.

## How requests are validated

1. Look up the named cookie on the request.
2. **Cookie absent or empty** → zero `Result`; chain continues silently.
3. **Cookie present** → hand the value to the validator.
4. Validator returns `(client, ok, reason)`. Map to a `Result`.

```
Cookie: MY_AUTH_SESSION=session-abc-123
         │
         ▼
  OpaqueValidator
         │
         ▼
   tokens[sha256] → "alice"  → DecisionReal
```

## Security model

- **Tarpit always trumps**: a valid cookie does not bypass tarpit. A stolen
  session cannot rehabilitate a bot whose behavioral score has crossed the
  threshold (`internal/proxy/proxy.go:238-256`).
- **Empty cookie values are treated as absent**, not as "presented invalid".
  Otherwise an attacker could probe whether the empty string is a valid
  session.
- **Audit lines never include the cookie value or its hash** — only the
  client id (filename) and the rejection reason.
- **Cross-origin caveat**: the cookie is only sent by the browser when its
  `Domain` / `SameSite` / `Path` attributes allow it. The cookie verifier
  does not set the cookie — your auth system does, and you must ensure it is
  scoped to reach the VeilGate-fronted origin. For the SPA-on-different-origin
  case, see [`/_g/start`](../endpoints/start.md) (ship #7).

## Examples

### Single internal session cookie

```yaml
verifiers:
  cookies:
    - name:       INTERNAL_SESSION
      validator:  opaque
      tokens_dir: /etc/veilgate/sessions
```

Drop a file `/etc/veilgate/sessions/alice.token` containing the session
value your auth system issues to alice. Subsequent requests carrying
`Cookie: INTERNAL_SESSION=<value>` bypass the challenge.

### Multiple cookies, layered

```yaml
verifiers:
  hmac:
    enabled: true
    clients_dir: /etc/veilgate/hmac-clients

  bearer:
    enabled: true
    tokens_dir: /etc/veilgate/api-tokens

  cookies:
    - name: INTERNAL_SESSION
      validator: opaque
      tokens_dir: /etc/veilgate/sessions
    - name: CF_AUTHORIZATION             # JWT lands in ship #4
      validator: jwt
      jwks_url: https://team.cloudflareaccess.com/cdn-cgi/access/certs
```

Chain order: HMAC → bearer → cookies (in declaration order). First match
wins.

## Operational notes

- Startup logs include `cookie verifier enabled cookie=<name> validator=<type>`.
- The verifier name appears in audit as `cookie:<name>` so an operator who
  runs two cookie verifiers can tell them apart.
- A cookie-rejected request falls through to the score system; it does not
  short-circuit to 401.

## See also

- [Credential verifiers — design tracker](../../design/credential-verifiers.md)
- [Bearer verifier](bearer.md)
- [Module reference: veilgate_verifier](../../modules/veilgate_verifier.md)
- [Cookie verifier source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/cookie.go)
- [Opaque validator source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/validator.go)
