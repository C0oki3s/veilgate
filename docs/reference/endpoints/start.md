# `/_g/start`

The PoW interstitial endpoint. Serves a self-contained HTML page that solves the proof-of-work challenge in the browser and `postMessage`s the resulting token back to the parent window. Designed to be loaded in a hidden `<iframe>` by a cross-origin SPA.

---

## Why this endpoint exists

The PoW challenge page (served when a request scores above the challenge threshold) only works for same-origin browser navigations: the HTML page embeds a `<script>` that runs in the user's browser, solves the nonce search, and POSTs the proof. It does not work for:

- **Cross-origin SPA `fetch()` calls** — the SPA can't execute HTML returned in a response body
- **Mobile apps / non-browser clients** — see the [bearer verifier](../verifiers/bearer.md) for that case

The SPA path uses the `/_g/config` discovery response + a `401 JSON` challenge returned by the `serveSPAChallenge` code path. A sophisticated SPA can solve the nonce search inline (on the main thread). But for operators who want a branded "checking…" overlay and don't want to block the SPA's own main thread, `/_g/start` provides an iframe that does all the work and signals completion via `postMessage`.

---

## Request

```
GET /_g/start[?origin=<target-origin>]
```

| Parameter | Required | Description |
|---|---|---|
| `origin` | No | The `targetOrigin` passed to `window.parent.postMessage`. When set to your SPA's origin (e.g. `https://app.example.com`), the browser rejects the message if the parent is on a different origin — a defence-in-depth measure. Defaults to `"*"` when absent. |

No authentication required.

---

## Response

`Content-Type: text/html; charset=utf-8`  
`Cache-Control: no-store`  
`Content-Security-Policy: frame-ancestors *`

The page:
1. Starts the nonce search immediately using `crypto.subtle` (no user interaction required)
2. POSTs the proof to `verify_path` (injected at serve time from the live challenge rules)
3. On success: calls `window.parent.postMessage({type: "veilgate-token", token: "...", header: "X-App-Token", expires_in: N}, targetOrigin)`
4. On error: calls `window.parent.postMessage({type: "veilgate-error", reason: "...", status?: N}, targetOrigin)`

---

## Integration pattern (SPA)

```js
// 1. Listen for the token before opening the iframe.
function solveChallenge(origin = location.origin) {
  return new Promise((resolve, reject) => {
    function onMessage(evt) {
      if (evt.origin !== location.origin) return; // ignore if same-origin guard fails
      if (evt.data?.type === "veilgate-token") {
        window.removeEventListener("message", onMessage);
        resolve(evt.data);
      }
      if (evt.data?.type === "veilgate-error") {
        window.removeEventListener("message", onMessage);
        reject(new Error(evt.data.reason));
      }
    }
    window.addEventListener("message", onMessage);

    // 2. Open the iframe. The start page does the work and postMessages back.
    const iframe = document.createElement("iframe");
    iframe.src = `/_g/start?origin=${encodeURIComponent(origin)}`;
    iframe.style.cssText = "position:fixed;width:0;height:0;border:0;opacity:0";
    document.body.appendChild(iframe);
    setTimeout(() => {
      document.body.removeChild(iframe);
      reject(new Error("timeout"));
    }, 30_000);
  });
}

// 3. Use the token on every API request.
const {token, header} = await solveChallenge();
sessionStorage.setItem("vg_token", token);

await fetch("/api/data", {
  headers: {[header]: token},
});
```

> The `@veilgate/client` npm package (ship #8) wraps this pattern into `init()` + `handleAll()` so you don't write it by hand.

---

## Security notes

- The page contains no cookies, sessions, or PII. The injected config is challenge metadata generated fresh per request.
- The `frame-ancestors *` CSP header is intentional — this page must be embeddable from any origin.
- Using `?origin=` is recommended: it binds the `postMessage` to your SPA's origin, so a rogue third-party page that happens to `postMessage`-sniff cannot steal the token.
- Without `?origin=`, the page sends to `"*"`. The token is short-lived (default 30 min) and only useful to an origin that knows your API server's URLs, so the practical risk is low — but specifying the origin is better practice.
- The PoW token is a PoW proof, not a user-identity credential. A stolen token lets a bot's requests bypass the challenge tier for at most one TTL window. The tarpit override (score ≥ tarpit threshold) still applies even with a valid token.

---

## Configuration

The start path defaults to `/_g/start`. To use a different path, set `start_path` in `challenge.yaml`:

```yaml
start_path: /__vg/begin
```

The configured value is advertised in the `start_path` field of the [`/_g/config`](well-known.md) discovery response.
