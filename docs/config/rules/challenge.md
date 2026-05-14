# `rules/challenge.yaml`

> **File:** `/etc/veilgate/rules/challenge.yaml` &nbsp;·&nbsp;
> **Reload:** hot-reload (~500 ms).
>
> Presentation layer for the proof-of-work challenge. The runtime
> secret + difficulty + TTL are in the proxy config under
> [`challenge:`](../challenge.md); this file controls how the challenge
> is rendered to the client.

**On this page:**

- [Parameters](#parameters)
- [HTML template variables](#html-template-variables)
- [Customising the appearance](#customising-the-appearance)
- [Example](#example)
- [Related](#related)

## Parameters

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `difficulty` | int | inherits from `challenge.difficulty` (4) | leading-zero hex digits required on the solution |
| `token_ttl_minutes` | int | inherits from `challenge.ttl_minutes` (30) | cookie / token TTL once solved |
| `cookie_name` | string | `__veilgate_pow` | cookie set when the client successfully solves |
| `status_code` | int | `429` | HTTP status returned with the challenge HTML |
| `content_type` | string | `text/html; charset=utf-8` | Content-Type of the challenge page |
| `verify_path` | string | `/__veilgate/verify` | path the JS POSTs to after solving |
| `cookie_path` | string | `/` | cookie scope |
| `html_template` | string | shipped HTML | Go `text/template` body |

> The `difficulty` and `token_ttl_minutes` keys here are *informational*
> for the operator. The values that actually run the challenge are the
> ones in the top-level [`challenge:`](../challenge.md) block — the
> only reason they're duplicated here is that the runtime can hot-reload
> the rules file while the top-level config can't.

## HTML template variables

The default `html_template` is rendered with this context:

| Variable | Source |
| --- | --- |
| `.Difficulty` | `difficulty` from this file (or top-level fallback) |
| `.Challenge` | the per-request challenge string (random nonce) |
| `.VerifyPath` | `verify_path` |

A minimal usable template:

```html
<!doctype html>
<html>
  <head>
    <title>Verifying…</title>
    <meta charset="utf-8"/>
  </head>
  <body>
    <p>Verifying your browser…</p>
    <script>
      const challenge = {{.Challenge | js}};
      const difficulty = {{.Difficulty}};
      const verify = {{.VerifyPath | js}};
      // (PoW solver loop — finds a nonce N such that
      //  sha256(challenge||N) starts with `difficulty` hex zeros, then
      //  POSTs N to verify.)
    </script>
  </body>
</html>
```

The shipped default is a complete page with a small loading spinner.
Read it from
[`internal/rules/defaults/challenge.yaml`](../../../internal/rules/defaults/challenge.yaml).

## Customising the appearance

Common operator changes:

- **Branding.** Replace the page with one that mentions your company
  by name. The transparency helps real-user trust.
- **Failure-mode message.** Add a fallback message rendered when JS
  is disabled — links to a contact form, alternative auth, etc.
- **Status code.** Some operators prefer `403 Forbidden` over `429 Too
  Many Requests` when the challenge is part of a security-tooling
  context. Either is fine; `429` is the more standards-friendly choice
  because it implies "retry later" rather than "denied".

## Example

```yaml
difficulty: 4
token_ttl_minutes: 30
cookie_name: __veilgate_pow
status_code: 429
content_type: "text/html; charset=utf-8"
verify_path: /__veilgate/verify
cookie_path: /
html_template: |
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <title>Verifying — example.com</title>
      <style>
        body { font: 14px sans-serif; max-width: 480px; margin: 6em auto; }
        .spinner { /* ... */ }
      </style>
    </head>
    <body>
      <h1>Verifying your browser</h1>
      <p>This takes a second. If it doesn't, please contact
         <a href="mailto:security@example.com">security@example.com</a>.</p>
      <div class="spinner"></div>
      <script>
        const challenge = {{.Challenge | js}};
        const difficulty = {{.Difficulty}};
        const verify = {{.VerifyPath | js}};
        // … solver …
      </script>
    </body>
  </html>
```

## Related

- [`challenge:`](../challenge.md) — runtime secret + difficulty + TTL
- [`detector.score_challenge_threshold`](../detector.md#score_challenge_threshold)
- [Use case: Bug-bounty triage](../../usecases/bug-bounty-triage.md)

---

*Previous: [`rules/ip_reputation.yaml`](ip-reputation.md) · Next: [Configuration reference](../README.md)*
