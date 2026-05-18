# Header Verifier

The header verifier accepts a request when a named **request header** carries
a value the configured validator approves. It is the header-shaped sibling of
the [cookie verifier](cookie.md) and shares the same validator surface —
switching between header and cookie is a yaml change, not a code change.

Source: `internal/verifier/header.go`. Part of the
[credential-verifiers project](../../design/credential-verifiers.md) (ship #3).

## When to use it

| Header                      | Typical source            |
|-----------------------------|---------------------------|
| `CF-Access-Jwt-Assertion`   | Cloudflare Access in front of VeilGate |
| `X-Goog-IAP-JWT-Assertion`  | Google IAP                |
| `X-Internal-Service-Token`  | Internal service mesh     |
| `X-Forwarded-Identity`      | API-gateway-injected identity |

For the `Authorization: Bearer <token>` shape with **opaque** tokens, prefer
the dedicated [bearer verifier](bearer.md) — it knows how to strip the
`Bearer ` scheme. The header verifier treats the **entire header value** as
the credential.

## Configuration

```yaml
verifiers:
  headers:
    - name:       X-Internal-Service-Token
      validator:  opaque
      tokens_dir: /etc/veilgate/internal

    - name:       CF-Access-Jwt-Assertion        # JWT lands in ship #4
      validator:  jwt
      jwks_url:   https://team.cloudflareaccess.com/cdn-cgi/access/certs
```

### Fields

| Field        | Default     | Notes |
|--------------|-------------|-------|
| `name`       | _required_  | Header name. Canonicalised internally — `X-Foo`, `x-foo`, `X-FOO` all match. |
| `validator`  | `opaque`    | Validator type. See the [validators table](cookie.md#validators) on the cookie page — the list is shared. |
| `tokens_dir` | _required when `validator: opaque`_ | Directory of pre-shared values; same layout as the bearer verifier's `tokens_dir`. |

## How requests are validated

1. Read the configured header (case-insensitive).
2. Trim surrounding whitespace.
3. **Empty after trim** → zero `Result`; chain continues silently.
4. Hand the value to the validator.
5. Validator's verdict produces an `Accepted` or `rejected` Result.

The audit name is `header:<original-casing>` so multiple header verifiers
produce distinct audit lines.

## Security model

Same invariants as the [cookie verifier](cookie.md#security-model):

- Tarpit always trumps a valid credential.
- Empty values are treated as **absent**, not as "presented invalid".
- Audit lines never include the header value or its hash — only the client
  id (from the validator) and the rejection reason.
- The header verifier does not authenticate the **upstream** that injected
  the header. If you are accepting `CF-Access-Jwt-Assertion`, you must
  trust Cloudflare to be the only path to VeilGate — otherwise a direct
  caller can forge the header. Pair with TLS client-cert pinning or a
  network ACL when this matters.

## Examples

### Cloudflare Access pass-through (today: opaque shared secret)

If your Cloudflare Access tunnel injects a shared service-token header:

```yaml
verifiers:
  headers:
    - name:       CF-Access-Client-Secret
      validator:  opaque
      tokens_dir: /etc/veilgate/cf-secrets
```

```bash
curl -H "CF-Access-Client-Secret: $(cat /etc/veilgate/cf-secrets/main.token)" \
     https://api.example.com/data
```

When the JWT validator lands (ship #4) you can swap to the assertion header
without rewriting any consumer code:

```yaml
- name:       CF-Access-Jwt-Assertion
  validator:  jwt
  jwks_url:   https://team.cloudflareaccess.com/cdn-cgi/access/certs
```

### Internal service mesh

```yaml
verifiers:
  headers:
    - name:       X-Internal-Service-Token
      validator:  opaque
      tokens_dir: /etc/veilgate/services
```

Drop one file per consuming service:

```
/etc/veilgate/services/
├── checkout.token
├── billing.token
└── search.token
```

Audit logs show the consuming service by filename.

## See also

- [Credential verifiers — design tracker](../../design/credential-verifiers.md)
- [Cookie verifier](cookie.md) — the cookie-shaped sibling
- [Bearer verifier](bearer.md) — for `Authorization: Bearer …`
- [Header verifier source](https://github.com/C0oki3s/veilgate/blob/main/internal/verifier/header.go)
