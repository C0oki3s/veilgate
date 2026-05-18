# `/__veilgate/.well-known`

The discovery endpoint. Returns a JSON document that describes the current VeilGate configuration — which challenge flow is active and which credential shapes are accepted. A browser SDK or server client calls this once on startup to learn how to authenticate without any hard-coded configuration.

---

## Request

```
GET /__veilgate/.well-known
```

No authentication required. The endpoint is intentionally open — it contains only configuration metadata, never secrets, tokens, or PII.

---

## Response

`Content-Type: application/json`  
`Cache-Control: public, max-age=60`  
`Access-Control-Allow-Origin: *`

```json
{
  "challenge": {
    "verify_path": "/__veilgate/verify",
    "start_path": "/__veilgate/start",
    "token_header": "X-Veilgate-Token",
    "cookie_name": "veilgate_pow"
  },
  "credentials": [
    {
      "type": "bearer",
      "header": "Authorization",
      "scheme": "Bearer"
    },
    {
      "type": "cookie",
      "name": "MY_SESSION",
      "validator": "jwt"
    },
    {
      "type": "header",
      "name": "CF-Access-Jwt-Assertion",
      "validator": "jwt"
    }
  ]
}
```

### `challenge` object

Present when a challenge handler is configured. Absent when VeilGate runs in a configuration with no challenge tier.

| Field | Type | Description |
|---|---|---|
| `verify_path` | string | POST target for a PoW solution. |
| `start_path` | string | (Ship #7) Iframe-loadable page that runs the PoW challenge and `postMessage`s the token to the parent window. Present only after ship #7 lands. |
| `token_header` | string | Header the client attaches on every API request to prove a solved challenge. |
| `cookie_name` | string | Same-origin cookie name carrying the solved-challenge token. |

### `credentials` array

One entry per configured verifier. Empty array or absent when no verifier chain is configured.

| Field | Present for | Description |
|---|---|---|
| `type` | all | `"bearer"`, `"cookie"`, or `"header"` |
| `header` | `bearer` | Header name the token rides on (`Authorization` by default). |
| `scheme` | `bearer` | Prefix to prepend (`Bearer` by default). Empty when the header carries the raw token. |
| `name` | `cookie`, `header` | Cookie or header name. |
| `validator` | `cookie`, `header` | Underlying validation type: `"opaque"`, `"jwt"`, or `"callout"`. |

---

## Behaviour

- **60-second cache**: Hot-reloaded rule changes propagate within 60 seconds. Clients that cache the response for a full minute will converge within one TTL.
- **CORS open**: The `*` wildcard is intentional. A browser SDK loaded from any origin must be able to fetch this document without a preflight. The document contains no secrets.
- **Stable contract**: The shape of this response is considered a stable API. New optional fields may be added; existing fields will not be removed or renamed without a major version bump.

---

## Example: curl

```bash
curl -s https://app.example.com/__veilgate/.well-known | jq .
```

---

## Example: `@veilgate/client`

The `@veilgate/client` browser package calls this endpoint during `init()` and caches the result. All subsequent `handleAll()` interception uses the cached descriptor to decide which header to attach (bearer vs. token) and where to drive the PoW iframe if a challenge is returned. See [client package docs](../../client/browser.md) (ship #8).
