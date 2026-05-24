# Upload Policies

VeilGate's upload policy layer protects known file-upload endpoints without
turning the proxy into a file scanner. Operators explicitly name upload paths
such as `/api/upload/*`, then VeilGate applies method, declared body size,
declared content type, and authentication checks before proxying.

This follows the same operational model as NGINX locations: large request
bodies should be allowed only on routes that are designed for them.

## Why Uploads Need A Separate Policy

Normal API requests are cheap to reject. Upload requests are different:

- They consume bandwidth before the upstream can make an application decision.
- They may trigger temporary-file writes, image processing, Excel parsing,
  antivirus scanning, or thumbnail generation upstream.
- Direct-to-bucket flows can create write access to S3/R2/Cloudinary style
  storage if the presign endpoint is weak.
- Body-sensitive verifiers such as HMAC can force the proxy to read request
  bodies before proxying.

Upload policies give VeilGate an early, explicit gate for these routes.

## Runtime Flow

```text
HTTP request arrives
│
├── ambiguous HTTP/1.x framing?
│   └── 400 bad_request
│
├── /_g/* internal path?
│   └── handled before upload policy
│
├── CORS preflight?
│   └── handled before upload policy
│
├── path matches upload_policies?
│   │
│   ├── method allowed?
│   │   └── no -> 405 method_not_allowed
│   │
│   ├── Content-Length <= max_body_bytes?
│   │   └── no -> 413 payload_too_large
│   │
│   ├── Content-Type allowed?
│   │   └── no -> 415 unsupported_media_type
│   │
│   ├── require_auth true?
│   │   └── no valid credential -> 401 auth_required
│   │
│   └── continue into normal scoring pipeline
│
├── detector score / decision
│
└── allowed traffic uses upload route's reverse proxy
    with upload-specific upstream_response_timeout
    and streaming max_body_bytes enforcement
```

Upload policy checks happen before detector scoring so obviously invalid upload
requests are rejected before they consume more proxy or upstream work. Passing
the upload policy does not bypass the detector. A request can still be
challenged or tarpitted if its behavior reaches those score bands.

For bodies without a reliable `Content-Length` (HTTP/1.1 chunked requests and
HTTP/2 request streams), VeilGate counts bytes while proxying. If the stream
exceeds `max_body_bytes`, the upload proxy maps the body-limit error to
`413 payload_too_large` and closes the upstream attempt.

## Transfer-Encoding and Smuggling Defense

`Transfer-Encoding` is hop-by-hop framing. VeilGate treats it as transport
state, not as application metadata. Upload policy never trusts trailers or
transfer codings for authentication, content type, or size decisions.

Before Go's `net/http` parser normalizes a request, VeilGate's listener-level
framing guard rejects HTTP/1.x requests with ambiguous body length:

- `Content-Length` together with `Transfer-Encoding`
- duplicate `Content-Length`
- HTTP/1.0 with `Transfer-Encoding`
- transfer codings other than a single `chunked`
- obsolete folded request headers

The rule is stricter than a general-purpose proxy on purpose. Request smuggling
happens when the frontend and backend disagree about where the request body
ends, so VeilGate rejects ambiguous framing instead of forwarding a normalized
version.

## Matching Model

Each policy has a list of paths:

```yaml
paths:
  - "/api/upload"
  - "/api/upload/*"
```

Exact paths match literally. Wildcards are prefix matches for patterns ending
in `/*`. When several policies match, exact paths win and then the longest
prefix wins. This lets operators set a broad upload policy and override one
sensitive endpoint with a stricter exact rule.

## Content Type Handling

VeilGate validates only the declared `Content-Type` header:

```yaml
allowed_content_types:
  - "multipart/form-data"
  - "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
  - "application/pdf"
  - "image/"
```

`image/` accepts any media type with that prefix. Multipart parameters such as
`boundary=...` are ignored for comparison.

VeilGate does not parse multipart bodies and does not inspect Excel/PDF/image
bytes. The upstream application or a dedicated scanning pipeline remains
responsible for real file validation, antivirus scanning, decompression limits,
and content safety.

## Authentication

When `require_auth: true`, VeilGate accepts either:

- a credential accepted by the configured verifier chain, or
- a valid VeilGate challenge token/cookie.

Application session cookies are not automatically meaningful to VeilGate. If
the upstream owns session state, configure a cookie verifier with JWT or
callout validation so the application remains the source of truth.

For large uploads, use:

```yaml
verifier_policy: "skip_body_hmac"
```

This skips the HMAC verifier on that upload route. HMAC request signing hashes
request bodies and is a good fit for JSON/webhook calls, but it is not a good
default for large file streams. Use bearer, JWT, header, cookie, or callout
verification for upload routes instead.

## Timeout Behavior

Normal HTTP proxying uses the standard reverse proxy transport. Upload policies
get their own reverse proxy transport so `upstream_response_timeout` can be
longer or disabled:

```yaml
upstream_response_timeout: "5m"
```

Empty or `"0"` disables the response-header timeout for that upload policy.
This is useful when the upstream receives the file and only sends headers after
processing it.

This does not change process-wide listener timeouts (`ReadTimeout` and
`WriteTimeout`) in `cmd/veilgate/main.go`. Those still protect the server as a
whole and should be made configurable separately if a deployment needs very
slow client uploads.

## Direct-To-S3 And Third-Party Uploads

For large user files, the preferred architecture is usually:

```text
Browser -> VeilGate -> backend /api/uploads/presign
Browser -> S3/R2/Cloudinary direct upload
Backend -> verify or complete upload
```

In that model VeilGate protects the presign or multipart-init endpoint, not the
file bytes themselves. Configure the presign endpoint as a small JSON API:

```yaml
upload_policies:
  - name: "s3-presign"
    paths:
      - "/api/uploads/presign"
      - "/api/uploads/multipart/*"
    methods: ["POST"]
    max_body_bytes: 65536
    allowed_content_types:
      - "application/json"
    require_auth: true
```

The upstream should validate requested size, object key prefix, file type,
owner/user ID, expiration, and multipart completion rules before creating
bucket write access.

## Code Path

| Concern | File | Function |
| --- | --- | --- |
| Config shape | `internal/config/config.go` | `UploadPolicyConfig` |
| Path/method/type/size checks | `internal/proxy/upload.go` | `enforceUploadPolicy()` |
| Upload route matching | `internal/proxy/upload.go` | `matchUploadPolicy()` |
| Upload auth reuse | `internal/proxy/upload.go` | `credentialAccepted()` |
| Streaming body limit | `internal/proxy/upload.go` | `withUploadBodyLimit()` |
| HTTP/1.x framing guard | `internal/proxy/framing_guard.go` | `NewFramingGuardListener()` |
| Skip body HMAC | `internal/verifier/verifier.go` | `VerifyExcept()` |
| Upload-specific proxy transport | `internal/proxy/upload.go` | `uploadTransport()` |

## Related

- [Upload policy config](../config/upload-policies.md)
- [Request classification](./request-classification.md)
- [Challenge handler](./challenge-handler.md)
- [Server-to-server HMAC](../how-to/server-to-server-hmac.md)
- [Bearer verifier](../reference/verifiers/bearer.md)
