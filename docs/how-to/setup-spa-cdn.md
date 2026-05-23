# Setup: SPA on CDN + API behind VeilGate

**When to use this:** Your frontend (React, Vue, Svelte, etc.) is hosted on a
CDN — Vercel, Netlify, AWS CloudFront, Oracle CDN, or any static host — and
your API runs on a separate host behind VeilGate.

**Traffic flow:**

```
Browser
  ├─► CDN (serves HTML, JS, CSS)
  └─► Cloudflare / edge ──► VeilGate ──► your API
```

---

## Step 1 — Install VeilGate on your API server

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

Replace `http://localhost:3000` with the address your API process listens on.

The install script:
- places the binary at `/usr/local/bin/veilgate`
- writes a starter config at `/etc/veilgate/veilgate.yaml` in `observe` mode
- installs a systemd service
- clones [veilgate-rules](https://github.com/C0oki3s/veilgate-rules) into `~veilgate/.veilgate/rules`

Check it started:

```bash
systemctl status veilgate
journalctl -u veilgate -f
```

---

## Step 2 — Set a challenge secret

VeilGate refuses to enter `challenge` or `tarpit` mode without a secret.

```bash
sudo systemctl edit veilgate
```

Add under `[Service]`:

```ini
[Service]
Environment=VEILGATE_SECRET=<output-of-openssl-rand-hex-32>
```

Generate one:

```bash
openssl rand -hex 32
```

Restart:

```bash
sudo systemctl restart veilgate
```

---

## Step 3 — Configure cross-origin cookie and challenge shape

Your SPA origin (`app.example.com`) and API origin (`api.example.com`) are
different hosts. The default cookie scope is single-host, so without this step
the solved challenge token never reaches the API.

Edit `~/.veilgate/rules/challenge.yaml`:

```yaml
difficulty: 3
token_ttl_minutes: 10

# Share the token cookie across all your subdomains.
cookie_domain: ".example.com"
cookie_same_site: "lax"

# Also return the token in a JSON field so SPAs that cannot use cookies
# (strict WebViews, CORS-omit contexts) can attach it as a header instead.
token_header_name: "X-Veilgate-Token"

# Return 401 JSON to XHR/fetch calls instead of an HTML 503 page.
# The @veilgate/client SDK expects this shape.
spa_aware_response: true
```

This file hot-reloads — no restart needed.

> **Shared registrable domains:** do not set `cookie_domain: ".vercel.app"`,
> `".github.io"`, or any other shared domain. That would expose your token to
> unrelated apps on the same domain. Use your own domain only.

---

## Step 4 — Configure CORS

In `/etc/veilgate/veilgate.yaml`, declare which frontend origins are allowed
to read API responses:

```yaml
listen: ":443"
upstream: "http://127.0.0.1:3000"
rules_dir: "~veilgate/.veilgate/rules"
mode: "challenge"

cors:
  allowed_origins:
    - "https://app.example.com"
    - "https://app.vercel.app"       # if using Vercel production URL
    - "https://app-*.vercel.app"     # Vercel branch preview URLs
  allow_credentials: true
```

Restart after editing `veilgate.yaml`:

```bash
sudo systemctl restart veilgate
```

---

## Step 5 — Configure your CDN to not proxy the API

The SPA must call the API origin directly from the browser. Running API traffic
through the CDN hides browser context from VeilGate, causes request storms from
CDN edge IPs, and makes API calls slower.

**Correct path:**

```
Browser → Cloudflare → VeilGate → API
```

**Wrong path (don't do this):**

```
Browser → CDN → Cloudflare → VeilGate → API
```

**Vercel** — add `vercel.json` to your repo root:

```json
{
  "redirects": [
    {
      "source": "/api/:path*",
      "destination": "https://api.example.com/api/:path*",
      "permanent": false
    }
  ],
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ]
}
```

The `redirects` rule for `/api/:path*` is a safety net for stale bookmarks or
cached bundles. It sends those requests to the API host with a 30x, not a
proxy rewrite. Do not put `/api/*` in `rewrites` pointing at the API.

**AWS CloudFront + S3** — configure a single origin behavior:
- Origin: your S3 bucket (SPA assets only)
- Do not add a second behavior for `/api/*` that forwards to your API
- Error responses: map 403 and 404 to `/index.html` with HTTP 200 (SPA routing)

**Netlify** — add to `netlify.toml`:

```toml
[[redirects]]
  from = "/api/*"
  to = "https://api.example.com/api/:splat"
  status = 302
  force = true

[[redirects]]
  from = "/*"
  to = "/index.html"
  status = 200
```

**Any other Nginx-based static server:**

```nginx
location /api/ {
    return 302 https://api.example.com$request_uri;
}

location / {
    try_files $uri /index.html;
}
```

---

## Step 6 — Point your SPA at the API origin

The API client in your SPA must use the API host, not the CDN host.

```js
// src/config.js
export const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "https://api.example.com";
```

For Vercel production, either leave `VITE_API_BASE_URL` unset (the fallback
applies) or set it to:

```
VITE_API_BASE_URL=https://api.example.com
```

Do not set it to an empty string. That makes requests go to
`app.example.com/api/*` — the CDN — instead of the API host.

---

## Step 7 — Integrate `@veilgate/client`

```bash
npm install @veilgate/client
```

In your entry point (`src/main.jsx` / `src/main.ts`):

```js
import { init, handleAll, getToken } from "@veilgate/client";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "https://api.example.com";

const showOverlay = () => {
  document.getElementById("vg-overlay").style.display = "flex";
};
const hideOverlay = () => {
  document.getElementById("vg-overlay").style.display = "none";
};

// Fetch the challenge config from the API origin and cache it.
await init({
  baseURL: API_BASE,
  onChallenge: showOverlay,
  onToken: hideOverlay,
});

// Patch global fetch + XHR so every API call carries the token automatically.
handleAll({
  baseURL: API_BASE,
  onChallenge: showOverlay,
  onToken: hideOverlay,
});

// Mount the app immediately — do not block first render on PoW computation.
mountApp();

// Warm the token in the background.
getToken().catch(() => {}).finally(hideOverlay);
```

Add an overlay element to your HTML so users see feedback while the challenge
is being solved:

```html
<div id="vg-overlay"
  style="display:none; position:fixed; inset:0;
         background:rgba(0,0,0,.5); align-items:center;
         justify-content:center; z-index:9999;">
  <p style="color:#fff; font-size:1.2rem;">Verifying your browser…</p>
</div>
```

---

## Step 8 — Verify everything works

**CDN serves HTML, not the API:**

```bash
curl -sD - -o /dev/null https://app.example.com/
# Expect: content-type: text/html
```

**Stale `/api` paths on the CDN redirect to the API host:**

```bash
curl -sD - -o /dev/null https://app.example.com/api/health
# Expect: 302 location: https://api.example.com/api/health
```

**API returns JSON challenge to fetch-shaped requests:**

```bash
curl -i \
  -H "Origin: https://app.example.com" \
  -H "Sec-Fetch-Dest: empty" \
  -H "User-Agent: python-requests/2.31.0" \
  https://api.example.com/api/health
# Expect:
#   HTTP/1.1 401 Unauthorized
#   Content-Type: application/json
#   Access-Control-Allow-Origin: https://app.example.com
#   {"error":"challenge_required",...}
```

**Direct browser navigation to the API returns the HTML challenge page:**

```bash
curl -i \
  -H "Sec-Fetch-Dest: document" \
  -H "Accept: text/html" \
  -H "User-Agent: python-requests/2.31.0" \
  https://api.example.com/api/health
# Expect: HTTP/1.1 503 ... <!DOCTYPE html>...
```

---

## Keeping rules up to date

```bash
veilgate update-rules
```

Rules hot-reload — no VeilGate restart needed.

---

## Related

- [Protect a multi-origin SPA](protect-multi-origin.md) — deep-dive on cross-origin cookie and token config
- [Setup: same-origin](setup-same-origin.md) — frontend and API on the same host
- [Setup: server-to-server](setup-server-to-server.md) — no browser, HMAC signing
- [Configuration reference: challenge](../config/rules/challenge.md)
- [Browser SDK reference](../reference/clients/browser.md)
