# `@veilgate/node` — server-side SDK

Node.js helper for server-to-server calls to a VeilGate-protected API. Provides two authentication modes:

- **Bearer** — attach a static API token (Stripe/GitHub PAT model)
- **HMAC** — sign each request with a per-request HMAC-SHA256 signature

---

## Installation

```bash
npm install @veilgate/node
```

Requires Node.js ≥ 18 (uses `node:crypto` and the Web Fetch API built into Node).

---

## Bearer mode

The server operator creates a token file in the configured `tokens_dir`:

```
# /etc/veilgate/tokens/payment-service.token
vg_live_a1b2c3d4e5f6…
```

Your service reads the token from an environment variable and passes it to `bearerFetch`:

```ts
import { bearerFetch } from "@veilgate/node";

const apiFetch = bearerFetch(process.env.VG_API_TOKEN!);

// Every request automatically carries "Authorization: Bearer vg_live_…"
const resp = await apiFetch("https://api.example.com/widgets");
const data = await resp.json();
```

**Custom header or raw-token mode:**

```ts
// X-Api-Key: <token> (no "Bearer " prefix)
const apiFetch = bearerFetch({ token: process.env.VG_API_TOKEN!, header: "X-Api-Key", scheme: "" });
```

---

## HMAC mode

HMAC mode signs each request with a shared secret. The signature covers the timestamp, method, path, and body hash — preventing replay attacks and body tampering.

```ts
import { hmacFetch } from "@veilgate/node";

const apiFetch = hmacFetch({
  clientId: "payment-service",     // sent as X-Veilgate-Client
  secret: process.env.VG_SECRET!,  // shared HMAC-SHA256 secret
});

// Every request gets X-Veilgate-Signature + X-Veilgate-Client
const resp = await apiFetch("https://api.example.com/charge", {
  method: "POST",
  body: JSON.stringify({ amount: 100 }),
  headers: { "Content-Type": "application/json" },
});
```

> **Body buffering**: `hmacFetch` buffers the request body to compute the body hash. Do not pass a streaming body — convert it to `Buffer` or `string` first.

---

## API reference

### `bearerFetch(tokenOrOpts, fetchImpl?)`

Returns a `fetch`-compatible function. All arguments after the token/options are passed through to the underlying `fetch`.

```ts
bearerFetch(token: string, fetchImpl?: typeof fetch): typeof fetch
bearerFetch(opts: BearerOptions, fetchImpl?: typeof fetch): typeof fetch

interface BearerOptions {
  token: string;
  header?: string;  // default: "Authorization"
  scheme?: string;  // default: "Bearer". Pass "" for raw-token mode.
}
```

### `hmacFetch(opts, fetchImpl?)`

Returns a `fetch`-compatible function that signs each request.

```ts
hmacFetch(opts: HMACOptions, fetchImpl?: typeof fetch): typeof fetch

interface HMACOptions {
  clientId: string;
  secret: string;
  signatureHeader?: string;  // default: "X-Veilgate-Signature"
  clientHeader?: string;     // default: "X-Veilgate-Client"
  replayWindow?: number;     // default: 300 (seconds). Match server config.
}
```

### `signRequest(secret, method, path, body?, timestamp?)`

Low-level function. Computes the HMAC signature string for one request. Use this if you need to sign requests outside of the `hmacFetch` wrapper (e.g. for WebSockets or EventSource authentication via a query parameter).

```ts
signRequest(
  secret: string,
  method: string,
  path: string,          // including query string
  body?: Buffer | Uint8Array | string,
  timestamp?: number,    // Unix seconds. Defaults to Date.now()/1000.
): string  // "t=<ts>,v1=<hex>"
```

### `signHeaders(opts, method, path, body?, timestamp?)`

Returns a plain object of headers to attach:

```ts
signHeaders(opts: HMACOptions, method: string, path: string, body?, timestamp?): Record<string, string>
// { "X-Veilgate-Signature": "t=…,v1=…", "X-Veilgate-Client": "…" }
```

### `verifySignature(sig, secret, method, path, body?, opts?)`

Verifies a `X-Veilgate-Signature` value. Useful for integration tests or custom middleware.

```ts
verifySignature(
  signature: string,
  secret: string,
  method: string,
  path: string,
  body?: Buffer | Uint8Array | string,
  opts?: { replayWindow?: number },
): boolean
```

Comparison is constant-time (`timingSafeEqual`). Returns `false` when the timestamp is outside the replay window.

---

## Signature canonical string

The HMAC covers:

```
<unix-timestamp>.<METHOD>.<path-including-query>.<hex(SHA-256(body))>
```

For a `GET /api/data` request with no body, the body hash is `SHA-256("")` = `e3b0c44298fc1c149afbf4c8996fb924…`.

This matches the canonical string computed by VeilGate's `HMACVerifier` on the server side.

---

## Security notes

- Keep the shared secret in an environment variable (`VG_SECRET`). Do not commit it to source.
- The default replay window is 300 s (5 min). Requests outside this window are rejected by the server. Clock skew > 5 min will cause authentication failures — use NTP.
- A leaked secret allows an attacker to forge valid signatures for up to `replayWindow` seconds after discovery. Rotate secrets via a new token file + rolling restart.
- HMAC provides per-request integrity. Bearer tokens provide per-session identity. Use HMAC when body integrity matters; use bearer when you want a simpler shared-secret model.
