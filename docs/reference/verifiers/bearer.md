# Bearer Verifier

The bearer verifier accepts opaque static tokens carried in a request header.
A valid token short-circuits the score/challenge tier — the request is treated
as `real` without solving a PoW.

This is the **GitHub personal-access-token / Stripe API key** model. Unlike
the [HMAC verifier](../../modules/veilgate_verifier.md), bearer tokens are not
bound to the request body, method, or path — they are static secrets. Replay
protection is the operator's responsibility: rely on TLS for confidentiality,
rotate on suspected compromise.

Source: `internal/verifier/bearer.go`. Part of the
[credential-verifiers project](../../design/credential-verifiers.md) (ship #1).

## When to use it

Use the bearer verifier when you want to **bypass the challenge tier for known
API consumers** — third-party developers, mobile apps, server-to-server
callers. The PoW challenge cannot run in any of those environments; an opaque
token is the standard substitute.

Do **not** use it as a substitute for HMAC when the credential rides on an
untrusted transport (replayable), and do not use it when the credential is
short-lived and issued by a separate auth system — for that, prefer the
forthcoming JWT validator on either the cookie or header verifier.

## Configuration

```yaml
verifiers:
  bearer:
    enabled:    true
    header:     "Authorization"          # default
    scheme:     "Bearer"                  # default when header=Authorization
    tokens_dir: "/etc/veilgate/tokens"   # required
```

| Field        | Default            | Notes |
|--------------|--------------------|-------|
| `enabled`    | `false`            | Set true to install the verifier. |
| `header`     | `Authorization`    | Request header carrying the credential. |
| `scheme`     | `Bearer` (auto)    | Prefix stripped before lookup. Set to `""` to treat the entire header value as the raw token (use for `X-…-Token` style headers without a scheme prefix). |
| `tokens_dir` | _required_         | Directory of token files. Loaded at startup; hot-reloaded on directory mtime change. |

### Token file layout

```
tokens_dir/
├── payments.token         # client id "payments", contents = the token value
├── mobile-ios.token       # client id "mobile-ios"
├── partner-acme.token     # client id "partner-acme"
└── partner-acme-2.token   # second active token for "partner-acme" (rotation)
```

- **Filename** (without extension) becomes the client identifier in audit logs.
- **File contents** is the raw token value. Whitespace is trimmed.
- Hidden files (`.foo.swp`, dotfiles) and subdirectories are skipped — editor
  swap files cannot accidentally grant access.
- **Rotation**: drop in a second `.token` file for the same client, let
  consumers migrate, then remove the old file. Both tokens are active during
  the overlap.
- Invalid client names (path traversal, non-filename-safe characters) are
  rejected at load time.

### Hot reload

The verifier watches the **directory mtime**. Add, remove, or modify a token
file and the change is picked up on the next request — no `SIGHUP`, no
restart. On filesystems with coarse mtime resolution, the change may take up
to one second to take effect.

## How requests are validated

1. Read the configured header.
2. If empty → return a zero `Result` (chain continues silently).
3. If a `scheme` is configured, strip the case-insensitive prefix; reject on
   mismatch.
4. Hash the remaining token with SHA-256.
5. Constant-time lookup in the in-memory map.
6. If found → `Accepted=true` with the client id; otherwise → reject with
   `reason="token unknown"`.

```
Authorization: Bearer vg_pat_a1b2c3d4e5f6...
                       │
                       ▼
                   SHA-256
                       │
                       ▼
            tokens[sha256] → "payments"  → DecisionReal
```

## Security model

| Property                      | Bearer | HMAC |
|-------------------------------|--------|------|
| Bound to method + path        | ❌      | ✓ |
| Bound to body                 | ❌      | ✓ |
| Replay protection (timestamp) | ❌      | ✓ |
| Tokens at rest, hashed        | ❌ (raw on disk) | ❌ (raw on disk) |
| Constant-time comparison      | ✓ (SHA-256 lookup) | ✓ |
| Tarpit still trumps           | ✓      | ✓ |

A bearer token is a **shared secret**. If it leaks, anyone with it can present
as that client until you rotate. This matches the security model that GitHub,
Stripe, and most public-API providers ship with — accept it consciously, not
by accident.

**Tarpit invariant**: A valid bearer token does **not** override a tarpit
decision. A bot that steals a token and then ramps up suspicious behavior
still gets tarpitted by score. This is the same invariant that protects the
PoW cookie (`internal/proxy/proxy.go:238-256`).

### Storage hardening

- `tokens_dir` and every token file should be mode `0600`, owned by the
  veilgate user. The verifier does not enforce this — it is an operator
  responsibility.
- Treat the tokens directory like an SSH key directory: never commit to git,
  exclude from container images, mount as a secret at runtime.
- Audit-log lines record the **client id** (filename) and never the token
  value or hash.

## Examples

### Curl

```bash
curl -H "Authorization: Bearer $(cat /etc/veilgate/tokens/payments.token)" \
     https://api.example.com/data
```

### Custom header without scheme

For a Cloudflare-Access-style header that carries the raw token directly:

```yaml
verifiers:
  bearer:
    enabled:    true
    header:     "X-Internal-Service-Token"
    scheme:     ""                              # raw-token mode
    tokens_dir: "/etc/veilgate/internal-tokens"
```

```bash
curl -H "X-Internal-Service-Token: raw-secret-xyz" https://api.example.com/data
```

### Two verifiers, layered

You can enable both HMAC and bearer simultaneously — the chain accepts the
first match. Use HMAC for high-value endpoints where you want body-binding,
bearer for everything else.

```yaml
verifiers:
  hmac:
    enabled:    true
    clients_dir: "/etc/veilgate/hmac-clients"
  bearer:
    enabled:    true
    tokens_dir:  "/etc/veilgate/api-tokens"
```

## Operational notes

- Startup logs include `bearer verifier enabled tokens_dir=… loaded=N`.
- A bearer-rejected request falls through to the score system. It does not
  short-circuit to a 401 — that decision belongs to the upstream service, not
  to the proxy.
- An empty `tokens_dir` is **not** an error. It loads zero tokens; every
  bearer-presented request is rejected with `reason="token unknown"`. This
  lets operators ship config before tokens.

## See also

- [Credential verifiers — design tracker](../../design/credential-verifiers.md)
- [Module reference: veilgate_verifier](../../modules/veilgate_verifier.md)
- [HMAC verifier source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/hmac.go)
- [Bearer verifier source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/bearer.go)
