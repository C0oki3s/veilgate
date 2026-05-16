# Module veilgate_http2_fingerprinting

The `veilgate_http2_fingerprinting` module models HTTP/2 SETTINGS fingerprints
and exposes them to the detector as protocol-level signals. It is separate from
TLS fingerprinting: JA3/JA4 describes the TLS ClientHello, while this module
describes the HTTP/2 SETTINGS frame shape, pseudo-header order, and early
window-update behavior.

The current codebase wires an HTTP/2 fingerprint store and classifier into the
detector, but it does not ship a `rules/h2_fingerprints.yaml` loader or watcher.
Known exact HTTP/2 fingerprint entries must therefore be applied by code before
`h2_agent` and `h2_bot` matches can fire. The built-in minimal-settings
heuristic can still emit `h2_non_browser` when settings are captured and look
library-shaped.

## Example Configuration

```yaml
tls:
  enabled: true
  cert_file: "/etc/veilgate/cert.pem"
  key_file: "/etc/veilgate/key.pem"
```

There is no top-level YAML directive for HTTP/2 fingerprinting in the current
tree. `cmd/veilgate/main.go` creates the HTTP/2 store and classifier when the
proxy starts.

## Directives

- HTTP/2 fingerprint store
- HTTP/2 classifier database
- HTTP/2 detector signals

## HTTP/2 Fingerprint Store

Syntax:  code-wired `h2fp.NewStore(<ttl>)`  
Default: `10 minutes` in `cmd/veilgate/main.go`  
Context: runtime

The store keeps captured HTTP/2 SETTINGS observations by remote address. Each
entry expires after the configured TTL. The detector reads the store on every
request using the request remote address.

The store is intentionally only a data layer. The package does not parse raw
HTTP/2 frames because Go's HTTP/2 stack hides the SETTINGS frame from normal
request handlers. A connection-establishment hook or custom HTTP/2 wrapper must
call `Store.Put(remote, settings)` for the signal to have input.

### Code path

- [`internal/h2fp/h2fp.go`](../../internal/h2fp/h2fp.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

### Operational notes

- HTTP/2 fingerprint quality depends on seeing the real client connection.
- If another edge proxy terminates HTTP/2 before VeilGate, the original client
  SETTINGS frame is not available to VeilGate.
- Lack of `h2_*` signals can mean no capture hook populated the store.

## HTTP/2 Classifier Database

Syntax:  code-wired `h2fp.Database.Apply([]h2fp.Entry{...})`  
Default: empty database  
Context: runtime

The database can match either an exact settings fingerprint hash or a
pseudo-header order. Exact hash matches have higher confidence. Pseudo-header
matches are treated as weaker and have their confidence capped.

The current repository includes the database type and classifier, but it does
not include a YAML rule file or loader for HTTP/2 fingerprints. This is
different from TLS fingerprints, which are loaded from
`rules/tls_fingerprints.yaml`.

### Code path

- [`internal/h2fp/h2fp.go`](../../internal/h2fp/h2fp.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

### Operational notes

- Treat exact HTTP/2 matches as supporting evidence, not a standalone block
  decision.
- Keep HTTP/2 labels aligned with TLS and User-Agent evidence when adding code
  entries.
- Do not document or deploy a `rules/h2_fingerprints.yaml` file unless the
  loader and watcher are added to the codebase.

## HTTP/2 Detector Signals

Syntax:  detector-internal protocol signals  
Default: enabled when the classifier is wired and has captured input  
Context: detector runtime

The detector calls the HTTP/2 classifier with the request remote address. The
classifier returns a label, category, confidence, and match flag. The detector
maps that result into one of three signals.

| Category | Signal | Points |
| --- | --- | --- |
| `agent` or `scanner` with high confidence | `h2_agent` | `35` |
| `agent` or `scanner` with lower confidence | `h2_agent` | `22` |
| `bot` | `h2_bot` | `18` |
| `unknown` / minimal library shape | `h2_non_browser` | `15` |

### Code path

- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)
- [`internal/detector/scorer_methods_test.go`](../../internal/detector/scorer_methods_test.go)

### Validation

```bash
curl -k --http2 https://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep h2
```

If no `h2_*` signal appears, confirm that VeilGate is receiving HTTP/2 traffic
and that the SETTINGS capture hook is actually writing to `internal/h2fp.Store`.

## Limitations

- The package does not parse HTTP/2 wire frames by itself.
- The current repository does not load `rules/h2_fingerprints.yaml`.
- Exact `h2_agent` and `h2_bot` matches require classifier entries to be
  applied by code.
- HTTP/2 fingerprinting does not replace TLS, header, behavior, or ML signals.

## Related

- [Module veilgate_tls_fingerprinting](veilgate_tls_fingerprinting.md)
- [Module veilgate_detector](veilgate_detector.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
