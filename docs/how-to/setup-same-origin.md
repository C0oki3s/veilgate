# Setup: Same-origin (frontend + API on one server)

**When to use this:** Your backend serves both the SPA bundle and the API from
the same host. VeilGate sits in front of everything on one origin.

**Traffic flow:**

```
Browser ──► Cloudflare / edge ──► VeilGate ──► your app
                                               ├─ GET /       → index.html
                                               └─ GET /api/*  → API handlers
```

This is the simplest VeilGate deployment. There is no cross-origin cookie
problem, no CORS config, and no CDN-specific routing to manage.

---

## Step 1 — Install VeilGate

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

Replace `http://localhost:3000` with the port your app listens on.

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

## Step 3 — Switch to challenge mode

Edit `/etc/veilgate/veilgate.yaml`:

```yaml
listen: ":443"
upstream: "http://127.0.0.1:3000"
rules_dir: "~veilgate/.veilgate/rules"
mode: "challenge"

persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"

metrics:
  listen: "127.0.0.1:9090"
```

Restart:

```bash
sudo systemctl restart veilgate
```

---

## Step 4 — Integrate `@veilgate/client` in your SPA

Because the SPA and the API share the same origin, the SDK defaults work
without any `baseURL` configuration.

```bash
npm install @veilgate/client
```

In your entry point (`src/main.jsx` / `src/main.ts`):

```js
import { init, handleAll, getToken } from "@veilgate/client";

const showOverlay = () => {
  document.getElementById("vg-overlay").style.display = "flex";
};
const hideOverlay = () => {
  document.getElementById("vg-overlay").style.display = "none";
};

// Fetch /_g/config from the same origin and cache the config.
await init({
  onChallenge: showOverlay,
  onToken: hideOverlay,
});

// Patch global fetch + XHR so every API call carries the token automatically.
handleAll();

// Mount the app immediately — do not block first render on PoW computation.
mountApp();

// Warm the token in the background.
getToken().catch(() => {}).finally(hideOverlay);
```

Add an overlay element to your HTML:

```html
<div id="vg-overlay"
  style="display:none; position:fixed; inset:0;
         background:rgba(0,0,0,.5); align-items:center;
         justify-content:center; z-index:9999;">
  <p style="color:#fff; font-size:1.2rem;">Verifying your browser…</p>
</div>
```

---

## Step 5 — Verify

**A normal browser-shaped request passes through to your app:**

```bash
curl http://localhost:8080/
# Expect: your app's response
```

**A suspicious request receives the HTML challenge page:**

```bash
curl -i -A "python-requests/2.31.0" http://localhost:8080/api/users
# Expect:
#   HTTP/1.1 503 Service Unavailable
#   Content-Type: text/html; charset=utf-8
#   <!DOCTYPE html>...
```

**A browser fetch call receives the JSON challenge shape** (because `Sec-Fetch-Dest: empty`):

```bash
curl -i \
  -H "Sec-Fetch-Dest: empty" \
  -H "User-Agent: python-requests/2.31.0" \
  http://localhost:8080/api/users
# Expect:
#   HTTP/1.1 401 Unauthorized
#   Content-Type: application/json
#   {"error":"challenge_required",...}
```

**Check metrics are running:**

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

---

## Observe before you enforce

The install script starts VeilGate in `observe` mode. In this mode every
request is scored and logged, but nothing is blocked. Before switching to
`challenge` or `tarpit`:

1. Run in `observe` for at least a few hours of real traffic.
2. Open the dashboard at `http://127.0.0.1:9090` and review signal hits.
3. Check for false positives: are any legitimate user agents scoring high?
4. Tune thresholds in your rules if needed.
5. Switch `mode: "challenge"` in `veilgate.yaml` and restart.

See [observe-mode rollout & threshold tuning](observe-and-tune.md) for detail.

---

## Keeping rules up to date

```bash
veilgate update-rules
```

Rules hot-reload — no VeilGate restart needed.

---

## Related

- [Setup: SPA on CDN](setup-spa-cdn.md) — frontend and API on different hosts
- [Setup: server-to-server](setup-server-to-server.md) — no browser, HMAC signing
- [Observe-mode rollout & tuning](observe-and-tune.md)
- [Browser SDK reference](../reference/clients/browser.md)
- [Deployment guide](../deployment/README.md)
