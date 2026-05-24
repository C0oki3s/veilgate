# WebSocket and gRPC Proxying

VeilGate proxies WebSocket upgrades and gRPC streams in addition to plain HTTP.
Both protocols run through the full scoring and decision pipeline before being
routed; the difference is in how the response is shaped when a request is
challenged or tarpitted.

Source: `internal/proxy/proxy.go` — `serveWebSocket`, `serveUpgradeBlocked`,
`serveGRPCBlocked`, `grpcProxy`.

## WebSocket

### How it works

VeilGate's WebSocket tunnelling supports the HTTP/1.1 upgrade form. It detects
a WebSocket upgrade when the incoming request carries both:

```
Upgrade: websocket
Connection: Upgrade
```

Detection is case-insensitive on both headers. The check happens after the full
scoring pipeline and verifier chain have run, so the decision is already final.

HTTP/2 WebSocket extended CONNECT (RFC 8441) is detected separately and returns
`501` JSON:

```
{"error":"http2_websocket_unsupported"}
```

This is deliberate. Go's normal HTTP/2 server path does not expose
`http.Hijacker`, and RFC 8441 is a stream-level CONNECT tunnel rather than the
HTTP/1.1 `101 Switching Protocols` flow used by `serveWebSocket`. VeilGate does
not try to fake this as an HTTP/1.1 upgrade; a future implementation should use
a dedicated HTTP/2 stream tunnel.

When the decision is `real` or `observe`:

1. VeilGate dials the upstream directly over TCP (TLS when the upstream URL is
   `https://` or `wss://`).
2. The incoming client connection is hijacked from the HTTP server.
3. The upgrade request is forwarded to upstream with the `Host` header rewritten
   to the upstream address.
4. The upstream's `101 Switching Protocols` response is read and forwarded
   verbatim to the client.
5. Both sides are now in WebSocket frame territory. VeilGate copies bytes
   bidirectionally until either side closes the connection.

### Per-mode behaviour

| Mode | Score band | Result |
|------|-----------|--------|
| `observe` | any | Tunnelled to upstream. Scoring runs but never diverts. |
| `challenge` | below threshold | Tunnelled to upstream. |
| `challenge` | at/above threshold | `503` JSON (see below). |
| `challenge` | at/above, but has valid PoW cookie or verifier token | Tunnelled — credential bypass applies to WebSocket. |
| `tarpit` / `auto` | challenge band | `503` JSON. |
| `tarpit` / `auto` | tarpit band | `403` JSON (see below). |
| `tarpit` / `auto` | tarpit band, has valid credential | `403` JSON — credentials **cannot** bypass tarpit. |

### Blocked response

WebSocket clients cannot execute an HTML PoW challenge page. When an upgrade is
blocked, VeilGate returns a plain HTTP error response before the connection is
hijacked:

```
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{"error":"challenge_required"}
```

For tarpit-band requests:

```
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"error":"forbidden"}
```

### Tarpit asymmetry

For plain HTTP, tarpitted requests are handed to the tarpit handler which
adds deliberate latency and serves a fake application response. **This
does not apply to WebSocket.** A tarpitted WebSocket upgrade gets an
immediate `403` — there is no meaningful way to slow-drain a bidirectional
tunnel, and holding a half-open connection wastes proxy resources.

The practical consequence: an attacker who probes WebSocket endpoints
discovers they are blocked faster than when probing HTTP endpoints. This is an
accepted trade-off. The tarpit's primary value (consuming automated scanner
time on plausible fake content) does not translate to the WebSocket model.

### SPA + socket.io integration

The recommended integration order when using socket.io or a similar library
behind VeilGate:

1. The `@veilgate/client` SDK's `init()` call fetches `/_g/config`
   (served without challenge) and patches `fetch` / `XMLHttpRequest`.
2. Call `getToken()` explicitly before connecting socket.io. This forces the
   PoW challenge to be solved on the main page's origin and sets the challenge
   cookie for the API domain.
3. Configure socket.io with `transports: ['polling']` initially. Once the
   challenge cookie is in place, the polling requests carry it and VeilGate
   passes them through.
4. If WebSocket upgrade is then attempted, the same cookie is sent in the
   upgrade request headers, and VeilGate tunnels the connection.

Cross-domain note: `demo.veilgate.dev` and `demo-api.veilgate.dev` are
different cookie scopes. The challenge must be solved separately for the API
origin (e.g. via an iframe to `https://demo-api.veilgate.dev/_g/start`)
before socket.io connects there.

---

## gRPC and gRPC-Web

gRPC over HTTP/2 works on both TLS listeners and plain h2c listeners. When TLS
is enabled, HTTP/2 is negotiated by ALPN. When TLS is disabled, VeilGate wraps
the plain listener with h2c support so HTTP/2 prior-knowledge and h2c upgrade
clients can reach the normal request pipeline.

### How it works

VeilGate detects gRPC when the request carries a `Content-Type` header
starting with `application/grpc`. This covers:

| Content-Type | Protocol |
|---|---|
| `application/grpc` | gRPC over HTTP/2 |
| `application/grpc+proto` | gRPC Protobuf over HTTP/2 |
| `application/grpc+json` | gRPC JSON over HTTP/2 |
| `application/grpc-web` | gRPC-Web over HTTP/1.1 |
| `application/grpc-web+proto` | gRPC-Web Protobuf over HTTP/1.1 |

When the decision is `real` or `observe`, the request is routed to a dedicated
gRPC-aware reverse proxy (`grpcProxy`) rather than the standard `realProxy`.
The two differ in exactly one way:

| Setting | `realProxy` (HTTP) | `grpcProxy` (gRPC) |
|---|---|---|
| `ResponseHeaderTimeout` | 15 s | none |
| `FlushInterval` | default | `-1` (flush every write) |

`ResponseHeaderTimeout` must be absent for gRPC because a long-running
streaming RPC may not produce response headers until the first message
arrives, which can be arbitrarily late. `FlushInterval: -1` ensures that
each frame reaches the client immediately rather than being buffered.

### Per-mode behaviour

Identical to WebSocket mode, with gRPC-specific error codes:

| Mode | Score band | Result |
|------|-----------|--------|
| `observe` | any | Proxied via gRPC transport. |
| `challenge` | below threshold | Proxied. |
| `challenge` | at/above threshold | HTTP 200 + `grpc-status: 16` (UNAUTHENTICATED). |
| `challenge` | at/above, valid credential | Proxied — credential bypass applies. |
| `tarpit` / `auto` | challenge band | HTTP 200 + `grpc-status: 16`. |
| `tarpit` / `auto` | tarpit band | HTTP 200 + `grpc-status: 7` (PERMISSION_DENIED). |
| `tarpit` / `auto` | tarpit band, valid credential | `grpc-status: 7` — credentials cannot bypass tarpit. |

### Blocked response

Per the gRPC spec, the HTTP status is always `200`; the error code lives in
the `grpc-status` response header:

**Challenge (UNAUTHENTICATED):**
```
HTTP/1.1 200 OK
Content-Type: application/grpc
grpc-status: 16
grpc-message: challenge_required
```

**Tarpit (PERMISSION_DENIED):**
```
HTTP/1.1 200 OK
Content-Type: application/grpc
grpc-status: 7
grpc-message: forbidden
```

Both gRPC and gRPC-Web clients read `grpc-status` from headers, so this works
for both transports.

### Tarpit asymmetry

Same as WebSocket: tarpitted gRPC calls get an immediate `grpc-status: 7`
rather than a slow tarpit response. Slow-draining a gRPC stream is not
practical.

---

## Configuration

No additional configuration is needed. WebSocket tunnelling and gRPC routing
activate automatically when the respective request signatures are detected.
The upstream URL scheme (`http://` vs `https://`) controls whether the
WebSocket dial uses plain TCP or TLS.

---

## See also

- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [`/_g/start` interstitial](../reference/endpoints/start.md) — for SPA cross-origin challenge solving
- [`@veilgate/client` browser SDK](../reference/clients/browser.md)
- [Bearer verifier](../reference/verifiers/bearer.md) — for non-browser clients that cannot solve PoW
- [Tarpit handler](tarpit-handler.md)
