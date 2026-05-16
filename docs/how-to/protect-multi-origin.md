# Protect an SPA + API on different subdomains

> **Audience:** Operators putting veilgate in front of an HTTP API
> consumed by a single-page application hosted on a different
> subdomain. e.g.:
> `app.example.com` (SPA on CDN) → `api.example.com` (behind veilgate).

The PoW challenge tier was originally designed for monolithic
deployments where the SPA and the API share one origin. The
multi-origin case has historically broken in two predictable ways —
this guide walks through the fix, end to end.

**On this page:**

- [Why the defaults don't work cross-origin](#why-the-defaults-dont-work-cross-origin)
- [The deployment topology](#the-deployment-topology)
- [Configuration](#configuration)
- [Client-side: handling the 401 response](#client-side-handling-the-401-response)
- [Verifying it works](#verifying-it-works)
- [Common pitfalls](#common-pitfalls)
- [Related](#related)

## Why the defaults don't work cross-origin

Two browser-level constraints compound:

1. **`fetch()` does not execute embedded scripts.** When veilgate
   returns its 503 HTML challenge page in response to an SPA fetch,
   the browser delivers the HTML *as the response body* — the
   embedded PoW `<script>` never runs. The SPA's JS sees a 503 with
   HTML content-type and treats it as a server error.

2. **Cookies are host-scoped by default and `SameSite=Strict` blocks
   cross-origin sends.** Even if you somehow executed the embedded
   script, the cookie veilgate sets on `api.example.com` wouldn't
   travel with requests initiated by `app.example.com`.

The fix has three parts: configure the cookie scope so it survives
cross-subdomain navigation, add a header transport for SPAs that
can't use cookies at all, and have veilgate return a structured 401
JSON for fetch-shaped requests instead of useless HTML.

## The deployment topology

```
   ┌──────────────────┐         ┌────────────────┐
   │  app.example.com │ ──────▶ │ api.example.com│
   │  (SPA on CDN)    │  fetch  │  (veilgate)    │
   └──────────────────┘         └───────┬────────┘
                                        │
                                  upstream API
```

The SPA lives on a CDN; veilgate sits in front of the API. The user
visits `app.example.com`, the SPA bundle loads, and the SPA makes
`fetch()` calls to `api.example.com/...`. The cookie must travel
across the subdomain boundary; the SPA must understand the challenge
shape.

## Configuration

### Step 1 — set the cookie scope

In `/etc/veilgate/rules/challenge.yaml`:

```yaml
cookie_domain: ".example.com"
cookie_same_site: "lax"
```

`cookie_domain: ".example.com"` makes the cookie visible to every
subdomain under `example.com` — `app.example.com` *and*
`api.example.com` *and any other subdomain you own*. Be deliberate:
don't use this on shared registrable domains (e.g. `*.herokuapp.com`,
`*.github.io`) where you'd be leaking the cookie to unrelated apps.

`cookie_same_site: "lax"` allows the cookie on top-level
navigations between same-site subdomains. Cross-origin POSTs are
still blocked, which is the CSRF-protective behavior you want.

Both fields hot-reload — no restart needed. Edit, save, the next
challenge-mint uses the new attributes.

### Step 2 — enable the header transport

```yaml
token_header_name: "X-Veilgate-Token"
```

The token (same value as the cookie) is also returned in the JSON
body of `/__veilgate/verify`:

```http
HTTP/1.1 200 OK
Set-Cookie: veilgate_pow=…; Domain=example.com; Path=/; SameSite=Lax; …
Content-Type: application/json

{"token":"…","expires_in":1800,"header":"X-Veilgate-Token"}
```

SPAs that can't rely on cookies (cross-origin with `credentials:
"omit"`, mobile webviews with strict cookie policies, etc.) read the
token from the body and attach it on every API call as
`X-Veilgate-Token: <value>`.

### Step 3 — enable the SPA-aware response

```yaml
spa_aware_response: true
```

This is the default, but worth being explicit about. With it on, an
XHR/fetch from the SPA receives:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Veilgate-Challenge realm="api.example.com"
Content-Type: application/json
Access-Control-Allow-Origin: https://app.example.com

{"error":"challenge_required","token_header":"X-Veilgate-Token","retry_after":1}
```

instead of the 503 HTML page. Document navigations
(`Sec-Fetch-Dest: document`) still get the HTML so a regular browser
visit still works transparently.

### Final challenge.yaml

```yaml
# /etc/veilgate/rules/challenge.yaml
difficulty: 4
token_ttl_minutes: 30
cookie_name: veilgate_pow
cookie_path: /
cookie_domain: ".example.com"      # ← parent-domain cookie
cookie_same_site: "lax"            # ← allow cross-subdomain
token_header_name: "X-Veilgate-Token"
spa_aware_response: true

# ... existing html_template ...
```

## Client-side: handling the 401 response

The SPA must detect the challenge shape and route the user through
some interstitial — a separate page that runs the PoW and obtains a
token, or a sign-in flow, or whatever your auth surface looks like.

A minimal fetch wrapper:

```js
async function apiFetch(url, init = {}) {
  // Attach the stashed token on every call.
  const headers = new Headers(init.headers);
  const token = localStorage.getItem("veilgate_token");
  if (token) headers.set("X-Veilgate-Token", token);

  let res = await fetch(url, { ...init, headers });
  if (res.status !== 401) return res;

  const body = await res.clone().json().catch(() => ({}));
  if (body.error !== "challenge_required") return res;

  // Operator-specific: route the user to your interstitial /
  // sign-in / device-attestation flow. After it completes, the
  // user (or your code) stashes the issued token into
  // localStorage under "veilgate_token" and we retry.
  await routeUserThroughChallenge();

  // Retry once with the new token.
  const retryHeaders = new Headers(init.headers);
  retryHeaders.set("X-Veilgate-Token", localStorage.getItem("veilgate_token"));
  return fetch(url, { ...init, headers: retryHeaders });
}
```

If you have a single-tenant deployment and you want the simplest
possible interstitial: redirect the user to
`https://verify.example.com` (a page you control, same registrable
domain as your API), load veilgate's challenge HTML there as a
top-level navigation, let the user solve the PoW, then `Domain=.example.com`
makes the cookie travel back to `api.example.com`. The SPA's retry on
the next API call will then carry the cookie automatically.

## Verifying it works

After restarting veilgate to pick up the config changes:

```bash
# 1. From a clean browser session, hit the API. Should get 401 JSON.
curl -i \
  -H "Origin: https://app.example.com" \
  -H "Sec-Fetch-Dest: empty" \
  -H "User-Agent: python-requests/2.32.3" \
  https://api.example.com/data
# Expect:
#   HTTP/1.1 401 Unauthorized
#   Content-Type: application/json
#   Access-Control-Allow-Origin: https://app.example.com
#   {"error":"challenge_required",...}

# 2. From a real browser visit (no Sec-Fetch-Dest hint), expect HTML 503.
curl -i \
  -H "Sec-Fetch-Dest: document" \
  -H "Accept: text/html,application/xhtml+xml" \
  https://api.example.com/data
# Expect:
#   HTTP/1.1 503 Service Unavailable
#   Content-Type: text/html; charset=utf-8
#   <!DOCTYPE html>...

# 3. After solving + obtaining a token, the API call goes through.
curl -i \
  -H "X-Veilgate-Token: <token-from-verify-response>" \
  https://api.example.com/data
# Expect: response from your real upstream
```

## Common pitfalls

### "My cookie isn't traveling"

The two most common causes:

- `cookie_domain` is set to `"example.com"` (no leading dot) on a
  browser that requires the dot. Go's `net/http` strips the leading
  dot, so both forms are functionally equivalent — but if you're
  reverse-engineering this on the network, you'll see `Domain=example.com`
  in the `Set-Cookie` and might think it's a bug. It isn't.

- `cookie_same_site: "strict"` is still in place. `strict` blocks
  cross-site sends entirely. Use `lax` (or, for fully cross-origin
  contexts where the API is called from third parties, `none`).

### "The SPA can't read the 401 JSON"

Almost always a CORS issue. Check:

- The proxy is echoing the `Origin` header into
  `Access-Control-Allow-Origin`. The veilgate SPA-aware response does
  this automatically — but if you have an intermediate proxy
  (nginx, ELB, etc.) that strips headers, the SPA will fail to read
  the response. Make the intermediate proxy pass `Access-Control-*`
  headers through unmodified.

- The browser sent `credentials: "include"` but `Access-Control-Allow-Origin`
  is `*`. Browsers refuse credentialed requests with wildcard origins;
  veilgate echoes the specific `Origin` value to avoid this.

### "The token expires too quickly"

`token_ttl_minutes` defaults to 30 — fine for human session length,
aggressive for an SPA that wants long-lived background polling. Raise
it carefully; longer TTLs extend the value of any stolen token. If
you raise it above ~60, consider also binding the token to a coarse
client fingerprint (see
[docs/security/defending-headless-browsers.md §1.1](../security/defending-headless-browsers.md#11-bind-the-cookie-to-a-coarse-client-fingerprint)).

### "Mobile webviews don't carry the cookie"

iOS Safari's Intelligent Tracking Prevention (ITP) and Android
WebView's storage isolation can clear cookies aggressively. For these
contexts, the header transport (`X-Veilgate-Token`) is the safer
path — the SPA reads the token from `localStorage` and attaches it
on every request. Cookies are best-effort; header is reliable.

## Related

- [`rules/challenge.yaml`](../config/rules/challenge.md)
  — the config surface
- [docs/security/challenge-deployment-limits.md](../security/challenge-deployment-limits.md)
  — the problem this guide solves
- [How-to: Server-to-server HMAC](server-to-server-hmac.md)
  — when the caller is a service, not a browser

---

*Previous: [How-to: Observe-mode rollout](observe-and-tune.md) ·
Next: [How-to: Server-to-server HMAC](server-to-server-hmac.md)*
