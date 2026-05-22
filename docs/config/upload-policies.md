# `upload_policies:`

> **File:** `/etc/veilgate/veilgate.yaml`
>
> **Reload:** restart required (`sudo systemctl restart veilgate`).

`upload_policies` defines explicit routes that are allowed to carry file upload
bodies. Each policy matches one or more paths and can enforce method,
content-type, declared body size, authentication, and upload-specific upstream
timeouts before the request is proxied.

This is intentionally similar to NGINX's per-location upload controls:
operators name the upload paths up front instead of letting every API route
accept large request bodies.

## Example

```yaml
upload_policies:
  - name: "user-files"
    paths:
      - "/api/upload"
      - "/api/upload/*"
      - "/api/files/*"
    methods: ["POST", "PUT"]
    max_body_bytes: 104857600 # 100 MiB
    allowed_content_types:
      - "multipart/form-data"
      - "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      - "application/vnd.ms-excel"
      - "application/pdf"
      - "image/"
    require_auth: true
    verifier_policy: "skip_body_hmac"
    upstream_response_timeout: "5m"
```

## Parameters

### `name`

| Type | Required | Default |
| --- | --- | --- |
| string | no | empty |

Human-readable policy name used in configuration review. It does not affect
matching.

### `paths`

| Type | Required | Default |
| --- | --- | --- |
| list of strings | yes | none |

Paths this policy applies to. Exact paths match literally. Paths ending in
`/*` match that prefix:

```yaml
paths:
  - "/api/upload"   # exact only
  - "/api/upload/*" # /api/upload/avatar, /api/upload/reports/q1.xlsx, ...
```

When multiple policies match, exact paths win over wildcards and the longest
matching prefix wins among wildcards.

### `methods`

| Type | Required | Default |
| --- | --- | --- |
| list of strings | no | all methods |

Allowed HTTP methods for the upload route. A non-matching method returns
`405 method_not_allowed` before proxying.

Typical values are `POST`, `PUT`, and sometimes `PATCH`.

### `max_body_bytes`

| Type | Required | Default |
| --- | --- | --- |
| integer | no | `0` (disabled) |

Maximum allowed declared body size. If the request carries `Content-Length` and
the value is larger than this limit, VeilGate returns `413 payload_too_large`
before proxying.

VeilGate also wraps the upload body with a streaming counter. This catches
HTTP/1.1 chunked uploads and HTTP/2 bodies where the total length was not known
up front. If the stream crosses the limit while proxying, VeilGate closes the
upstream attempt and returns `413 payload_too_large` instead of surfacing the
proxy error as `502`.

The body is still not buffered or parsed. VeilGate counts bytes as they stream.

### `allowed_content_types`

| Type | Required | Default |
| --- | --- | --- |
| list of strings | no | all content types |

Allowed declared `Content-Type` values. Parameters such as multipart boundaries
are ignored during comparison.

Exact values match one media type:

```yaml
allowed_content_types:
  - "multipart/form-data"
  - "application/pdf"
```

Values ending in `/` match a type prefix:

```yaml
allowed_content_types:
  - "image/"
```

That accepts `image/png`, `image/jpeg`, and other image media types.

VeilGate does not inspect file bytes. Treat this as a routing policy, not as
malware scanning or real file-type validation.

### `require_auth`

| Type | Required | Default |
| --- | --- | --- |
| boolean | no | `false` |

When true, VeilGate requires a valid credential before accepting the upload
route. Valid credentials are the existing verifier chain or a valid VeilGate
challenge token.

This does not validate your application session automatically. If your upstream
owns session cookies, configure a cookie verifier with `validator: callout` or
JWT validation so VeilGate can ask the application/auth service whether the
cookie is valid.

### `verifier_policy`

| Type | Required | Default |
| --- | --- | --- |
| string | no | `"normal"` |

Controls how the verifier chain is used on this upload route.

| Value | Behavior |
| --- | --- |
| `normal` or empty | Use the full verifier chain. |
| `skip_body_hmac` | Skip the HMAC verifier and allow other verifiers such as bearer, header, cookie, JWT, or callout. |

Use `skip_body_hmac` for large uploads. The HMAC verifier hashes request bodies
up to its configured cap, which is appropriate for API JSON and webhooks but
not for large multipart uploads.

### `upstream_response_timeout`

| Type | Required | Default |
| --- | --- | --- |
| duration string | no | disabled for upload policy proxies |

Response-header timeout for the upload route's upstream proxy. Empty or `"0"`
means no response-header timeout. Use a value such as `"5m"` when the upstream
may process the uploaded file before sending response headers.

This does not change Go's listener-level `ReadTimeout` or `WriteTimeout`; those
remain process-wide settings in `cmd/veilgate/main.go`.

## Responses

Upload policy rejections are JSON and include CORS headers when the request has
an `Origin` header:

| Condition | Status | Body |
| --- | --- | --- |
| Method not allowed | `405` | `{"error":"method_not_allowed"}` |
| Declared body too large | `413` | `{"error":"payload_too_large"}` |
| Content type not allowed | `415` | `{"error":"unsupported_media_type"}` |
| Auth required but absent/invalid | `401` | `{"error":"auth_required"}` |

## Transfer-Encoding and Request Smuggling

VeilGate rejects ambiguous HTTP/1.x request framing before it reaches the
normal Go HTTP parser. These requests return `400` and are not proxied:

- both `Content-Length` and `Transfer-Encoding`
- duplicate `Content-Length`
- HTTP/1.0 with `Transfer-Encoding`
- transfer codings other than a single `chunked`
- obsolete folded headers in the request header block

This follows the conservative security-proxy stance: reject ambiguous framing
rather than normalize it differently from the upstream application.

## Code Path

- [`internal/config/config.go`](../../internal/config/config.go) defines `UploadPolicyConfig`.
- [`internal/proxy/upload.go`](../../internal/proxy/upload.go) matches and enforces policies.
- [`internal/proxy/framing_guard.go`](../../internal/proxy/framing_guard.go) rejects ambiguous HTTP/1.x framing before `net/http` normalizes it.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) calls upload policy enforcement before scoring normal requests.
- [`internal/verifier/verifier.go`](../../internal/verifier/verifier.go) supports skipping body-sensitive verifiers.

## Related

- [Upload policies functionality](../functionalities/upload-policies.md)
- [Request classification](../functionalities/request-classification.md)
- [Verifier design](../design/credential-verifiers.md)
- [Server-to-server HMAC](../how-to/server-to-server-hmac.md)
