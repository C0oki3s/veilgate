# Architecture

VeilGate is a reverse proxy with a scoring layer and a deception backend.

```text
client
  |
  v
proxy.Server
  |
  +-- detector.Scorer -> score + signals
  |
  +-- decision
        |
        +-- real upstream
        +-- challenge.Handler
        +-- tarpit.Handler
```

## Request Flow

1. Resolve the effective client IP.
2. Record the request in the rolling tracker.
3. Evaluate detector signals.
4. Record metrics, dashboard events, capture events, and persistence events.
5. Choose `real`, `challenge`, or `tarpit`.
6. Feed the response status back into the tracker for future signals.

## Detector

The detector returns a score from `0` to `100`. Signals are additive and the
final score is capped at `100`.

Current signal groups:

- Request shape: suspicious user agent, sparse browser headers, Sec-Fetch
  coherence, Accept-Encoding coherence, H3 mismatch.
- Path and payload: honeypot paths, scanner wordlist paths, injection markers,
  out-of-band callback markers.
- Stateful behavior: timing regularity, path fanout, request graph shape,
  cookie ecology, failure recovery pivots, recon/probe/exploit sequencing.
- Network identity: IP reputation, public/private IP classification, IP fleet
  rotation, UA rotation.
- Protocol fingerprints: JA3/JA4 TLS classification and HTTP/2 settings
  classification.
- Deception feedback: tarpit canary replay.
- ML: online feature scoring and rule-miner candidates.

Most detector rules are configured under `rules/`.

## Challenge

The challenge handler serves a JavaScript proof-of-work page. The verify request
must include:

- challenge nonce
- issued timestamp
- HMAC signature
- solved nonce

The server verifies the signature, age, and proof before setting the challenge
cookie. This prevents a bare POST from minting a bypass cookie.

## Tarpit

The tarpit builds a stable fake application per client IP:

- `ProfileStore` creates deterministic fake identity data.
- `Renderer` executes response templates from `templates.yaml`.
- `Handler` routes requests using `injection_strategy.yaml`.
- `payloads.Injector` inserts decoy and prompt-injection payloads.

The same client sees a consistent fake company, stack, user names, credentials,
and vulnerable-looking endpoints across requests.

## TLS Fingerprinting

When `tls.enabled` is true, VeilGate wraps the listener and peeks the first TLS
record before Go's TLS stack consumes it. It parses the ClientHello, computes
JA3 and JA4 fingerprints, stores them by remote address, and replays the bytes
so the normal TLS handshake continues.

Known fingerprints and browser-like prefixes live in `rules/tls_fingerprints.yaml`.

## Persistence

The SQLite store is asynchronous. Request handling enqueues events and rollup
updates; a background flusher commits batches. When the queue is full, events
are dropped rather than blocking the proxy path.

Stored data includes:

- request events
- feature rollups
- learned rule candidates
- audit log chain
- tarpit canaries

## Rules and Hot Reload

The rules watcher reloads supported YAML files after filesystem changes. Rule
holders use atomic pointers so request-path reads do not take a mutex.

Rule files should be treated as security policy: review them, test them, and
roll them out like code.

## Test Layout

- Package-private unit tests live beside implementation files under `internal/`.
- Black-box integration tests live in [tests](../tests).

This split preserves direct coverage of unexported scoring and rendering
helpers while also exercising public APIs from an external package.
