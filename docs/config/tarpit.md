# `tarpit:`

> **File:** `/etc/veilgate/veilgate.yaml` &nbsp;·&nbsp;
> **Section:** `tarpit:` &nbsp;·&nbsp;
> **Reload:** restart required.

Latency and body caps applied to every tarpit response. The actual
tarpit *content* (templates, fake data, prompt-injection payloads)
lives under [`rules/`](rules/templates.md).

**On this page:**

- [`min_latency_ms`](#min_latency_ms)
- [`max_latency_ms`](#max_latency_ms)
- [`max_body_bytes`](#max_body_bytes)
- [Example](#example)
- [Related](#related)

## Parameters

### `min_latency_ms`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `500` |

Minimum delay before a tarpit response begins. Combined with
`max_latency_ms`, defines a uniform-random sleep applied to every
diverted request.

---

### `max_latency_ms`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `3000` |

Maximum delay. Pick this with attacker economics in mind:

- Higher values waste more attacker wall-clock time but also tie up
  one VeilGate goroutine per concurrent attacker. With Go's scheduler
  this is cheap, but a billion-stream DDoS would still saturate file
  descriptors before it saturates VeilGate.
- Lower values give a less convincing fake-app feel.

> **Tuning.** Most operators settle around `min: 800, max: 4000`.
> Long-tail higher values (10–30 s) work well against LLM agents that
> wait for full bodies before deciding what to do next.

---

### `max_body_bytes`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `102400` (100 KiB) |

Hard cap on the response body served from a tarpit decision. Anything
the template renders beyond this is truncated.

The cap exists to defend the *defender's* bandwidth from tarpit
goroutines that would otherwise stream forever. The
`veilgate_tarpit_bytes_served_total` metric gives you the total served
across all tarpit responses.

## Example

```yaml
tarpit:
  min_latency_ms: 800
  max_latency_ms: 4000
  max_body_bytes: 102400
```

For an "API recon-blocking" deployment (smaller responses, faster):

```yaml
tarpit:
  min_latency_ms: 300
  max_latency_ms: 1500
  max_body_bytes: 32768
```

For an "LLM-agent-defence" deployment (slow + heavy, designed to burn
tokens):

```yaml
tarpit:
  min_latency_ms: 1500
  max_latency_ms: 8000
  max_body_bytes: 262144         # 256 KiB
```

## Related

- [`rules/templates.yaml`](rules/templates.md) — response bodies
- [`rules/payloads.yaml`](rules/payloads.md) — prompt-injection content
- [`rules/injection_strategy.yaml`](rules/injection-strategy.md) — route → template
- [Use case: LLM-agent defence](../usecases/llm-agent-defense.md)

---

*Previous: [`detector:`](detector.md) · Next: [`challenge:`](challenge.md)*
