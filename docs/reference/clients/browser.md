# `@veilgate/client` — browser SDK

The browser-side companion package for VeilGate. Add two lines to your SPA and all `fetch` requests automatically:

- Attach a valid challenge token when one is cached
- Solve a fresh PoW challenge via a hidden iframe when the server issues a 401
- Retry the original request with the new token transparently

---

## Installation

```bash
npm install @veilgate/client
```

**CDN (no build step):**

```html
<script src="https://unpkg.com/@veilgate/client/dist/client.umd.js"></script>
```

---

## Two-liner setup

```js
import { init, handleAll } from "@veilgate/client";

await init();      // fetch /_g/config, cache config
handleAll();       // patch global fetch + XHR
```

After this, every `fetch()` call in your app is transparently protected:

- If a valid token is in `sessionStorage`, it is attached as the configured header
- If the server returns `401 { "error": "challenge_required" }`, the SDK opens a hidden iframe pointing to `/_g/start`, waits for the token via `postMessage`, then retries the request

---

## Cross-origin SPA

When your SPA lives on a different origin than your API:

```js
await init({ baseURL: "https://api.example.com" });
handleAll({ baseURL: "https://api.example.com" });
```

The SDK appends `?origin=https://your-spa.example.com` to the iframe URL so the `postMessage` is scoped to your origin.

---

## API reference

### `init(opts?)`

Fetches `/_g/config` and caches the discovery document. Idempotent: calling it multiple times after the first success is a no-op.

```ts
await init({
  baseURL?: string,          // default: "" (same origin)
  storageKey?: string,       // default: "vg_token"
  onChallenge?: () => void,  // called when the challenge iframe opens
  onToken?: (token: string, header: string) => void,
});
```

### `handleAll(opts?)`

Patches `window.fetch` and `XMLHttpRequest.prototype.send` globally. Safe to call once. Call after `init()`.

```ts
handleAll(opts?: VeilGateOptions);
```

### `getToken()`

Returns a valid `StoredToken`, solving a fresh challenge if the cached token is missing or expiring within 60 s. Use this as an escape hatch to attach the token manually to non-standard requests (WebSockets, `EventSource`, etc.).

```ts
const { value, header, expiresAt } = await getToken();
```

### `getDiscovery()`

Returns the cached `DiscoveryDoc` from `/_g/config`, or `null` if `init()` hasn't been called.

---

## Callbacks and custom UI

Show a "verifying…" spinner while the challenge is being solved:

```js
await init({
  onChallenge: () => { document.getElementById("auth-overlay").style.display = "flex"; },
  onToken:     () => { document.getElementById("auth-overlay").style.display = "none"; },
});
handleAll();
```

---

## Token storage

The SDK stores the token in `sessionStorage` under the configured `storageKey`. On iOS Safari private mode and some embedded WebViews where `sessionStorage` is unavailable, it falls back to an in-memory map that lives for the lifetime of the page.

Tokens are per-tab (not shared). Each tab solves its own challenge. This is the correct behaviour: `sessionStorage` does not propagate between tabs.

---

## Bearer credentials (operator-issued tokens)

If the server is configured with a [bearer verifier](../verifiers/bearer.md), the operator hands the client a static API token (like a GitHub PAT). Pass it via `fetch` options directly:

```js
await fetch("/api/data", {
  headers: { "Authorization": "Bearer my-api-token" },
});
```

The bearer token bypasses the PoW flow entirely. `handleAll()` does not interfere with requests that already carry a recognized credential.

---

## Security notes

- The SDK never reads or transmits passwords, cookies, or user identity. It only manages the short-lived PoW challenge token.
- The challenge token expires quickly (operator-configured, default 30 min) and is tied to no user identity — losing it is equivalent to a cache miss.
- The `postMessage` from `/_g/start` is scoped to your origin when `?origin=` is set. Omitting it defaults to `"*"` which is acceptable for the PoW token (not a long-lived secret) but specifying the origin is better practice.

---

## Package layout

```
packages/browser/
  src/index.ts       — source (TypeScript, no external runtime deps)
  dist/client.esm.js — ES module
  dist/client.cjs.js — CommonJS
  dist/client.umd.js — UMD (CDN)
  dist/index.d.ts    — TypeScript declarations
  test/index.test.ts — Vitest test suite (18 tests, jsdom)
```

Build: `npm run build` (Rollup + TypeScript)  
Tests: `npm test` (Vitest + jsdom)
