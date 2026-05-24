# Credential Verifiers — Design & Ship Tracker

Status: in-progress. Raised by: Jai, 2026-05-17 discussion (continuation of `Challege.md`).
Companion docs: `../../Challege.md`, `../modules/veilgate_challenge.md`.

The PoW challenge tier is built for browser document navigations. It does not
cover API consumers (third-party devs, mobile, server-to-server) and it does
not survive cross-origin SPA fetches without help. This work generalizes the
existing HMAC verifier into a pluggable **credential bypass layer** so an
operator can name *what credential to accept* (cookie, bearer header, custom
header) and *how to validate it* (opaque equals, HMAC, JWT, HTTP callout)
entirely through `veilgate.yaml` — no Go code. A companion client package
auto-discovers the configured credentials and attaches them on the SPA side.

## The shape

```yaml
verifiers:
  hmac:           # existing — Stripe-style request signatures
    enabled: true
    clients_dir: ./secrets/clients

  bearer:         # NEW (#1): opaque tokens, Stripe / GitHub-PAT style
    enabled: true
    header: Authorization
    scheme: Bearer
    tokens_dir: ./secrets/tokens

  cookies:        # NEW (#2): arbitrary cookie names, any validator
    - name: MY_AUTH_SESSION
      validator: jwt
      jwks_url: https://auth.example.com/.well-known/jwks.json
      required_claims: { aud: veilgate }

  headers:        # NEW (#3): arbitrary header names, any validator
    - name: CF-Access-Jwt-Assertion
      validator: jwt
      jwks_url: https://team.cloudflareaccess.com/cdn-cgi/access/certs
```

Validators (`opaque` / `hmac` / `jwt` / `callout`) are shared across cookie and
header verifiers. Each request walks the chain in order; first acceptance
wins; tarpit still trumps every verifier (load-bearing security invariant —
see `internal/proxy/proxy.go:238-256`).

## Ship order

| # | Item                             | Effort | Status |
|---|----------------------------------|--------|--------|
| 1 | Bearer verifier (opaque)         | 1 d    | **shipped** ✓ |
| 2 | Cookie verifier (opaque)         | 1 d    | **shipped** ✓ |
| 3 | Header verifier (opaque)         | 0.5 d  | **shipped** ✓ |
| 4 | JWT validator (shared 2 + 3)     | 2 d    | **shipped** ✓ |
| 5 | HTTP callout validator           | 1 d    | **shipped** ✓ |
| 6 | `/_g/config`        | 0.5 d  | **shipped** ✓ |
| 7 | `/_g/start` interstitial | 3 d    | **shipped** ✓ |
| 8 | `@veilgate/client` browser pkg   | 1 w    | **shipped** ✓ |
| 9 | `@veilgate/node` server pkg      | 2 d    | **shipped** ✓ |

Server-only milestone is items 1–6 (~5 days). That alone makes VeilGate
deployable in front of API surfaces and SPA+API multi-origin topologies.
Items 7–9 close the cross-origin SPA UX gap.

## Security trade-offs to document on every ship

- **Opaque tokens** have no per-request replay protection. Document this
  clearly on the bearer / opaque-validator pages: rotate on leak, rely on TLS
  for confidentiality. Fine for the GitHub-PAT / Stripe-key model.
- **JWT validator** trusts the JWKS issuer — operator must control or vet it.
- **Callout validator** adds a network hop to the hot path; cache TTL is
  load-bearing, not just an optimization.
- **Tarpit override** stands across all verifiers: a valid credential cannot
  bypass tarpit (score ≥ tarpit_threshold). This is what keeps a stolen
  credential from rehabilitating a bot's score.

## Per-ship checklist

Each item lands as: implementation + tests + a docs page under
`docs/reference/verifiers/` linked from `docs/index.md` and from this tracker.

## Links

- Ship #1 docs: [`../reference/verifiers/bearer.md`](../reference/verifiers/bearer.md) ✓
- Ship #2 docs: [`../reference/verifiers/cookie.md`](../reference/verifiers/cookie.md) ✓
- Ship #3 docs: [`../reference/verifiers/header.md`](../reference/verifiers/header.md) ✓
- Ship #4 docs: [`../reference/verifiers/jwt-validator.md`](../reference/verifiers/jwt-validator.md) ✓
- Ship #5 docs: [`../reference/verifiers/callout-validator.md`](../reference/verifiers/callout-validator.md) ✓
- Ship #6 docs: [`../reference/endpoints/well-known.md`](../reference/endpoints/well-known.md) ✓
- Ship #7 docs: [`../reference/endpoints/start.md`](../reference/endpoints/start.md) ✓
- Ship #8 docs: [`../reference/clients/browser.md`](../reference/clients/browser.md) ✓
- Ship #9 docs: [`../reference/clients/node.md`](../reference/clients/node.md) ✓
