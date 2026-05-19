# `rules/challenge.yaml`

> **File:** `~/.veilgate/rules/challenge.yaml`
> **Reload:** hot-reload (~500 ms).
>
> Presentation layer for the proof-of-work challenge. The runtime
> secret + difficulty + TTL are in the proxy config under
> [`challenge:`](../challenge.md); this file controls how the challenge
> is rendered to the client.

**On this page:**

- [Parameters](#parameters)
- [HTML template variables](#html-template-variables)
- [Customizing the appearance](#customizing-the-appearance)
- [Example](#example)
- [Related](#related)

## Parameters

| Key | Type | Default | Purpose |
| --- | --- | --- | --- |
| `difficulty` | int | inherits from `challenge.difficulty` (4) | leading-zero hex digits required on the solution |
| `token_ttl_minutes` | int | inherits from `challenge.ttl_minutes` (30) | cookie / token TTL once solved |
| `cookie_name` | string | `veilgate_pow` | cookie set when the client successfully solves |
| `cookie_path` | string | `/` | cookie `Path=` attribute |
| `cookie_domain` | string | `""` (host-only) | cookie `Domain=` attribute; set to `.example.com` for cross-subdomain |
| `cookie_same_site` | string | `strict` | `strict`, `lax`, or `none` |
| `token_header_name` | string | `X-Veilgate-Token` | header to also accept the token from (for cross-origin SPAs) |
| `spa_aware_response` | bool | `true` | return 401 JSON for XHR/fetch contexts instead of 503 HTML |
| `status_code` | int | `503` | HTTP status returned with the challenge HTML for document navigations |
| `content_type` | string | `text/html; charset=utf-8` | Content-Type of the challenge page |
| `verify_path` | string | `/__veilgate/verify` | path the JS POSTs to after solving |
| `html_template` | string | shipped HTML | Go `text/template` body |

> The `difficulty` and `token_ttl_minutes` keys here are *informational*
> for the operator. The values that actually run the challenge are the
> ones in the top-level [`challenge:`](../challenge.md) block - the
> only reason they're duplicated here is that the runtime can hot-reload
> the rules file while the top-level config can't.

## Cross-origin / SPA deployments

If your frontend (`app.example.com`) and your VeilGate-protected API
(`api.example.com`) live on different subdomains, the historical
defaults break: the cookie VeilGate sets on `api.example.com` is
host-only, and `SameSite=strict` blocks cross-site sends entirely.
Four fields together fix this.

### `cookie_domain`

Leave empty for single-origin deployments - the cookie is host-only,
which is the safest default.

Set to a parent domain (with a leading `.`) when your SPA and API
live on sibling subdomains:

```yaml
cookie_domain: ".example.com"
```

The browser will send the cookie on every request to any subdomain of
`example.com`. **Be deliberate**: a `.example.com` cookie is visible
to every subdomain, including ones you don't control if you have a
permissive CNAME policy. Don't set this on shared registrable domains
(`*.github.io`, `*.herokuapp.com`).

### `cookie_same_site`

`strict` is the historical default and the safest. The cookie won't
be sent on cross-site initiations of any kind - clicking a link from
an external site to your origin won't carry the cookie either.

Set to `lax` for cross-subdomain SPAs:

```yaml
cookie_same_site: "lax"
```

`lax` still blocks cross-origin POSTs but allows the cookie on
top-level navigations between subdomains under the same registrable
domain. This is what you want when `app.example.com` opens a popup
to `verify.example.com` to solve the challenge.

`none` requires `Secure` (HTTPS only) and is broadly the same as
"send always, including cross-site." Use only if you have a specific
third-party context where you've considered the CSRF surface.

### `token_header_name`

For SPAs that can't rely on cookies at all - fully cross-origin
fetches with `credentials: "omit"`, or apps that prefer header-based
auth for clarity - VeilGate also accepts the token value from a
request header:

```yaml
token_header_name: "X-Veilgate-Token"
```

The same value VeilGate puts in the `Set-Cookie` is also returned in
the JSON body of `/__veilgate/verify`:

```http
HTTP/1.1 200 OK
Set-Cookie: veilgate_pow=2026-05-16T18:35:18Z.67a2e29...; Path=/; ...
Content-Type: application/json

{"token": "2026-05-16T18:35:18Z.67a2e29...", "expires_in": 1800,
 "header": "X-Veilgate-Token"}
```

SPAs read `token` from the body and attach it as a header on every
subsequent API call. Set this to `""` to disable the header transport
entirely.

### `spa_aware_response`

When the request is an XHR or `fetch()` (rather than a top-level
document navigation), serving the 503 HTML challenge page is useless
- the SPA's JS won't execute the embedded `<script>`. With
`spa_aware_response: true` (the default), the challenge handler
returns a structured 401 + JSON instead:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Veilgate-Challenge realm="api.example.com"
Content-Type: application/json
Access-Control-Allow-Origin: https://app.example.com

{"error": "challenge_required",
 "token_header": "X-Veilgate-Token",
 "retry_after": 1}
```

The SPA detects this shape and routes the user through whatever
challenge-solve flow you provide (a click-through page, a redirect to
a sign-in, etc.). Document navigations still receive the 503 HTML so
a regular browser visit gets the embedded PoW script as before.

Detection is on `Sec-Fetch-Dest` (modern browsers), then
`X-Requested-With: XMLHttpRequest` (legacy jQuery), then `Accept`
listing JSON without `text/html`. Plain `*/*` is treated as ambiguous
and gets the HTML - most non-browser tooling sets `*/*`.

Set to `false` to always return the 503 HTML. Useful when you don't
have an SPA and want to keep the legacy behavior unconditionally.

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
    <title>Verifying...</title>
    <meta charset="utf-8"/>
  </head>
  <body>
    <p>Verifying your browser...</p>
    <script>
      const challenge = {{.Challenge | js}};
      const difficulty = {{.Difficulty}};
      const verify = {{.VerifyPath | js}};
      // (PoW solver loop - finds a nonce N such that
      //  sha256(challenge||N) starts with `difficulty` hex zeros, then
      //  POSTs N to verify.)
    </script>
  </body>
</html>
```

The shipped default is a complete page with a small loading spinner.
Read it from
[`internal/rules/defaults/challenge.yaml`](../../../internal/rules/defaults/challenge.yaml).

## Customizing the appearance

Common operator changes:

- **Branding.** Replace the page with one that mentions your company
  by name. The transparency helps real-user trust.
- **Failure-mode message.** Add a fallback message rendered when JS
  is disabled - links to a contact form, alternative auth, etc.
- **Status code.** Some operators prefer `403 Forbidden` over `429 Too
  Many Requests` when the challenge is part of a security-tooling
  context. Either is fine; `429` is the more standards-friendly choice
  because it implies "retry later" rather than "denied".

## Example

```yaml
difficulty: 4
token_ttl_minutes: 30
cookie_name: veilgate_pow
status_code: 503
content_type: "text/html; charset=utf-8"
verify_path: /__veilgate/verify
cookie_path: /
cookie_domain: ".example.com"      # parent-domain cookie for app + api subdomains
cookie_same_site: "lax"            # safe default for cross-subdomain
token_header_name: "X-Veilgate-Token"
spa_aware_response: true
html_template: |
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8"/>
      <title>Verifying - example.com</title>
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
        // ... solver ...
      </script>
    </body>
  </html>
```

## Related

- [`challenge:`](../challenge.md) - runtime secret + difficulty + TTL
- [`detector.score_challenge_threshold`](../detector.md#score_challenge_threshold)
- [Use case: Bug-bounty triage](../../usecases/bug-bounty-triage.md)

---

*Previous: [`rules/ip_reputation.yaml`](ip-reputation.md) | Next: [Configuration reference](../README.md)*
