# HTTP/2 Fingerprinting

This functionality page mirrors
[Module veilgate_http2_fingerprinting](../modules/veilgate_http2_fingerprinting.md)
for feature-oriented navigation.

HTTP/2 fingerprinting models the SETTINGS frame, pseudo-header order, and early
window-update behavior for clients that speak HTTP/2. The detector can use this
as a protocol signal alongside TLS JA3/JA4, headers, request history, IP
reputation, canary replay, and ML.

## Example Configuration

```yaml
tls:
  enabled: true
  cert_file: "/etc/veilgate/cert.pem"
  key_file: "/etc/veilgate/key.pem"
```

There is no `veilgate.yaml` field or `rules/h2_fingerprints.yaml` loader in the
current codebase. `cmd/veilgate/main.go` wires the store and classifier directly.

## Runtime Fields

- HTTP/2 SETTINGS fingerprint
- Pseudo-header order
- Window update value
- Classifier label
- Classifier category
- Classifier confidence

## Detector Signals

| Signal | Meaning | Points |
| --- | --- | --- |
| `h2_agent` | HTTP/2 SETTINGS match an agent or scanner entry. | `22` or `35` |
| `h2_bot` | HTTP/2 SETTINGS match a known bot entry. | `18` |
| `h2_non_browser` | SETTINGS look library-shaped and do not match a browser. | `15` |

## Code path

- [`internal/h2fp/h2fp.go`](../../internal/h2fp/h2fp.go)
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)

## How To Customize

The current repository does not expose HTTP/2 fingerprint entries as YAML.
Operators can still customize behavior indirectly:

1. Tune `detector.score_challenge_threshold` and
   `detector.score_tarpit_threshold`.
2. Tune neighboring deterministic rules in `rules/detector.yaml`.
3. Add or adjust TLS classifications in `rules/tls_fingerprints.yaml`.
4. Add code that calls `h2fp.Database.Apply()` with approved entries if exact
   HTTP/2 matching is required.

Do not create a production `rules/h2_fingerprints.yaml` file until a loader and
watcher are added to `internal/rules` and `cmd/veilgate/main.go`.

## Validation

```bash
curl -k --http2 https://localhost:8080/
curl http://127.0.0.1:9090/metrics | grep h2
```

If no `h2_*` signal appears, confirm that HTTP/2 traffic reaches VeilGate and
that the SETTINGS capture hook is populated.

## Related

- [Module veilgate_http2_fingerprinting](../modules/veilgate_http2_fingerprinting.md)
- [TLS fingerprinting](tls-fingerprinting.md)
- [Detection signals](detection-signals.md)
