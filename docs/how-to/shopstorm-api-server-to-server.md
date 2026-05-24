# Server-to-Server: Calling the ShopStorm API

> **Demo API base URL:** `https://demo-api.veilgate.dev`
> **OpenAPI spec:** `shopstorm/openapi.yaml` in the demo repo

This guide shows how a backend service calls the ShopStorm demo API through
VeilGate using HMAC authentication. Browser users use the proof-of-work
challenge SDK instead; this guide is for machine-to-machine calls only.

**On this page:**

- [How VeilGate HMAC works](#how-veilgate-hmac-works)
- [Signature algorithm](#signature-algorithm)
- [Register your client](#register-your-client)
- [Node.js — using the signing helper](#nodejs--using-the-signing-helper)
- [Node.js — manual signing](#nodejs--manual-signing)
- [Python](#python)
- [Go](#go)
- [curl](#curl)
- [ShopStorm JWT flow](#shopstorm-jwt-flow)
- [Full walkthrough: browse, cart, order](#full-walkthrough-browse-cart-order)
- [Error reference](#error-reference)

---

## How VeilGate HMAC works

Browser traffic uses proof-of-work challenges. Server traffic skips the
challenge entirely by presenting a signed request that VeilGate can verify
cryptographically.

```
Your service  ──HMAC signed──▶  VeilGate  ──forwarded──▶  ShopStorm API
```

VeilGate checks three headers on every request:

| Header | Example |
| --- | --- |
| `X-Veilgate-Client` | `my-backend` |
| `X-Veilgate-Timestamp` | `1716000000` |
| `X-Veilgate-Signature` | `a3f4b2...` (hex HMAC) |

If all three pass, the request is forwarded with a score of 0 (fully trusted).
If any header is missing or the signature is wrong, the request is treated as
anonymous browser traffic and may receive a challenge.

---

## Signature algorithm

```
signature_string = "<unix_ts>.<METHOD>.<path>.<sha256hex(body)>"
signature        = HMAC-SHA256(secret, signature_string)  → hex
```

**Fields:**

| Field | Notes |
| --- | --- |
| `unix_ts` | Seconds since epoch (UTC). VeilGate rejects requests outside a ±30 s window. |
| `METHOD` | Uppercase: `GET`, `POST`, `PUT`, `DELETE` |
| `path` | URL path only, including query string. Example: `/api/products?q=shoes` |
| `sha256hex(body)` | SHA-256 of the raw request body bytes. For requests with no body, hash the empty string. |

**Example (GET with no body):**

```
ts   = 1716000000
msg  = "1716000000.GET./api/products.e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
sig  = HMAC-SHA256(secret, msg)
```

---

## Register your client

1. Create a client file in the VeilGate clients directory (default `/etc/veilgate/clients/`):

   ```bash
   # Filename = client ID
   sudo nano /etc/veilgate/clients/my-backend
   ```

2. Paste the secret (one line, no trailing newline):

   ```
   super-secret-random-32-char-value
   ```

3. Restart or reload VeilGate:

   ```bash
   sudo systemctl restart veilgate
   ```

No YAML changes needed. VeilGate loads client files from the directory
automatically on startup.

---

## Node.js — using the signing helper

The demo repo ships a ready-made helper at
`shopstorm/src/lib/veilgateHmac.js`:

```js
const { createVeilgateClient } = require('./src/lib/veilgateHmac');

const api = createVeilgateClient(
  process.env.VEILGATE_HMAC_SECRET,   // secret from /etc/veilgate/clients/my-backend
  'my-backend',                        // must match the filename
  'https://demo-api.veilgate.dev',
);

// Public endpoint — no JWT needed
const { items } = await api.get('/api/products?limit=5');
console.log(items.map(p => p.name));

// Authenticated endpoint — obtain a JWT first, then pass it
const { token } = await api.post('/api/auth/login', {
  email: 'alice@example.com',
  password: 's3cr3tPa$$',
});

const { orders } = await api.get('/api/orders', { jwt: token });
```

The helper automatically adds `X-Veilgate-Client`, `X-Veilgate-Timestamp`,
and `X-Veilgate-Signature` to every request.

---

## Node.js — manual signing

If you prefer not to use the helper:

```js
const crypto = require('crypto');

const SECRET    = process.env.VEILGATE_HMAC_SECRET;
const CLIENT_ID = 'my-backend';
const BASE_URL  = 'https://demo-api.veilgate.dev';

function veilgateHeaders(method, path, body = '') {
  const ts       = Math.floor(Date.now() / 1000).toString();
  const bodyHash = crypto.createHash('sha256').update(body).digest('hex');
  const msg      = `${ts}.${method.toUpperCase()}.${path}.${bodyHash}`;
  const sig      = crypto.createHmac('sha256', SECRET).update(msg).digest('hex');
  return {
    'X-Veilgate-Client':    CLIENT_ID,
    'X-Veilgate-Timestamp': ts,
    'X-Veilgate-Signature': sig,
  };
}

// GET example
const path = '/api/products/featured';
const res  = await fetch(`${BASE_URL}${path}`, {
  headers: veilgateHeaders('GET', path),
});
const { items } = await res.json();

// POST example
const body = JSON.stringify({ email: 'alice@example.com', password: 's3cr3tPa$$' });
const res2 = await fetch(`${BASE_URL}/api/auth/login`, {
  method:  'POST',
  headers: {
    'Content-Type': 'application/json',
    ...veilgateHeaders('POST', '/api/auth/login', body),
  },
  body,
});
const { token } = await res2.json();
```

---

## Python

```python
import hashlib, hmac, time, json
import os
import urllib.request

SECRET    = os.environ["VEILGATE_HMAC_SECRET"].encode()
CLIENT_ID = "my-backend"
BASE_URL  = "https://demo-api.veilgate.dev"

def veilgate_headers(method: str, path: str, body: bytes = b"") -> dict:
    ts        = str(int(time.time()))
    body_hash = hashlib.sha256(body).hexdigest()
    msg       = f"{ts}.{method.upper()}.{path}.{body_hash}".encode()
    sig       = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    return {
        "X-Veilgate-Client":    CLIENT_ID,
        "X-Veilgate-Timestamp": ts,
        "X-Veilgate-Signature": sig,
    }

# GET request
path    = "/api/products/featured"
headers = veilgate_headers("GET", path)
req     = urllib.request.Request(BASE_URL + path, headers=headers)
with urllib.request.urlopen(req) as r:
    data = json.load(r)
print([p["name"] for p in data["items"]])

# POST request
payload = json.dumps({"email": "alice@example.com", "password": "s3cr3tPa$$"}).encode()
headers = {
    "Content-Type": "application/json",
    **veilgate_headers("POST", "/api/auth/login", payload),
}
req = urllib.request.Request(BASE_URL + "/api/auth/login", data=payload, headers=headers)
with urllib.request.urlopen(req) as r:
    token = json.load(r)["token"]
print("JWT:", token[:20], "...")
```

---

## Go

```go
package main

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "strconv"
    "time"
)

var (
    secret   = []byte(os.Getenv("VEILGATE_HMAC_SECRET"))
    clientID = "my-backend"
    baseURL  = "https://demo-api.veilgate.dev"
)

func sign(method, path string, body []byte) (ts, sig string) {
    ts = strconv.FormatInt(time.Now().Unix(), 10)
    h := sha256.Sum256(body)
    msg := fmt.Sprintf("%s.%s.%s.%s", ts, method, path, hex.EncodeToString(h[:]))
    mac := hmac.New(sha256.New, secret)
    mac.Write([]byte(msg))
    sig = hex.EncodeToString(mac.Sum(nil))
    return
}

func veilgateRequest(method, path string, body []byte, jwt string) (*http.Response, error) {
    req, _ := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
    ts, sig := sign(method, path, body)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-Veilgate-Client", clientID)
    req.Header.Set("X-Veilgate-Timestamp", ts)
    req.Header.Set("X-Veilgate-Signature", sig)
    if jwt != "" {
        req.Header.Set("Authorization", "Bearer "+jwt)
    }
    return http.DefaultClient.Do(req)
}

func main() {
    // GET featured products
    res, _ := veilgateRequest("GET", "/api/products/featured", nil, "")
    defer res.Body.Close()
    var out map[string]any
    json.NewDecoder(res.Body).Decode(&out)
    fmt.Println(out)
}
```

---

## curl

```bash
#!/bin/bash
SECRET="super-secret-random-32-char-value"
CLIENT="my-backend"
BASE="https://demo-api.veilgate.dev"

sign() {
  local method="$1" path="$2" body="${3:-}"
  local ts=$(date +%s)
  local body_hash=$(printf '%s' "$body" | openssl dgst -sha256 -hex | awk '{print $2}')
  local msg="${ts}.${method}.${path}.${body_hash}"
  local sig=$(printf '%s' "$msg" | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
  echo "${ts} ${sig}"
}

# GET /api/products/featured
PATH_=/api/products/featured
read -r TS SIG <<< "$(sign GET $PATH_)"
curl -s "$BASE$PATH_" \
  -H "X-Veilgate-Client: $CLIENT" \
  -H "X-Veilgate-Timestamp: $TS" \
  -H "X-Veilgate-Signature: $SIG" | jq '.items[].name'

# POST /api/auth/login
BODY='{"email":"alice@example.com","password":"s3cr3tPa$$"}'
read -r TS SIG <<< "$(sign POST /api/auth/login "$BODY")"
TOKEN=$(curl -s -X POST "$BASE/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "X-Veilgate-Client: $CLIENT" \
  -H "X-Veilgate-Timestamp: $TS" \
  -H "X-Veilgate-Signature: $SIG" \
  -d "$BODY" | jq -r '.token')

echo "JWT: $TOKEN"
```

---

## ShopStorm JWT flow

VeilGate HMAC and ShopStorm JWT are independent layers:

- **VeilGate HMAC** — proves your service is a trusted backend. VeilGate strips
  these headers before forwarding.
- **ShopStorm JWT** — proves *which user* you are acting as. Obtained from
  `POST /api/auth/login` and passed as `Authorization: Bearer <jwt>`.

```
1. Sign the login request with HMAC → VeilGate trusts the call
2. ShopStorm issues a JWT for the user
3. Sign subsequent requests with HMAC + include Authorization: Bearer <jwt>
4. ShopStorm reads the JWT from the forwarded request
```

Public endpoints (product catalog) need HMAC only. All cart, order, returns,
support, and user endpoints also need the JWT.

---

## Full walkthrough: browse, cart, order

```js
const { createVeilgateClient } = require('./src/lib/veilgateHmac');

const api = createVeilgateClient(
  process.env.VEILGATE_HMAC_SECRET,
  'my-backend',
);

async function placeOrder() {
  // 1. Get a JWT
  const { token } = await api.post('/api/auth/login', {
    email: 'alice@example.com',
    password: 's3cr3tPa$$',
  });

  // 2. Browse products
  const { items } = await api.get('/api/products?category=Electronics&limit=5');
  const productId = items[0].id;

  // 3. Add to cart
  await api.post('/api/cart/items', { productId, quantity: 1 }, { jwt: token });

  // 4. Place order
  const { order } = await api.post('/api/orders', {
    shippingAddress: {
      line1: '123 Main St',
      city: 'Austin',
      state: 'TX',
      zip: '78701',
      country: 'US',
    },
    paymentMethod: { type: 'card', last4: '4242' },
  }, { jwt: token });

  console.log('Order placed:', order.id, 'Total:', order.totalCents / 100, 'USD');
  return order;
}

placeOrder().catch(console.error);
```

---

## Error reference

| Status | Meaning |
| --- | --- |
| `401` from VeilGate | HMAC signature invalid or timestamp out of window |
| `401` from ShopStorm | Missing or expired JWT |
| `403` | JWT present but insufficient role (e.g. non-admin accessing `/api/admin`) |
| `404` | Resource not found |
| `409` | Conflict — duplicate email, username, or return |
| `400` | Validation error — see `error` field in response body |

VeilGate and ShopStorm both return `{ "error": "<message>" }` on failure.

---

## Related

- [`openapi.yaml`](../../veilgate-demo/shopstorm/openapi.yaml) — Full API spec
  (load in Swagger UI, Insomnia, or Postman)
- [`docs/how-to/setup-server-to-server.md`](setup-server-to-server.md) — Generic
  VeilGate HMAC setup for any upstream
- [`docs/config/challenge.md`](../config/challenge.md) — Challenge config
  reference
