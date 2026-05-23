# `challenge:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `challenge:`
> **Reload:** restart required.

Configures the JavaScript proof-of-work challenge served when a
request scores in the middle band. The HTML and difficulty defaults
live in [`rules/challenge.yaml`](rules/challenge.md); this section
holds the runtime secrets and TTLs.

**On this page:**

- [`secret`](#secret)
- [`difficulty`](#difficulty)
- [`ttl_minutes`](#ttl_minutes)
- [Example](#example)
- [Related](#related)

## Parameters

### `secret`

| Type | Required | Default |
| --- | --- | --- |
| string | yes (on production) | `change-me-in-production-or-set-VEILGATE_SECRET` |

HMAC secret used to sign issued challenge tokens. **Set this to a real
random value before going to `challenge` or `tarpit` mode** - the
default value is a placeholder that anyone can forge.

Recommended generation:

```bash
openssl rand -hex 32
```

Best practice: keep the secret out of `veilgate.yaml` itself. Set it
via a systemd drop-in:

```bash
sudo systemctl edit veilgate
```

```ini
[Service]
Environment=VEILGATE_SECRET=<long-random-hex>
```

Then in the YAML:

```yaml
challenge:
  secret: ${VEILGATE_SECRET}
```

(Environment variable expansion happens before YAML parsing.)

---

### `difficulty`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `4` |

Number of leading hex zeros required on the SHA-256 proof-of-work solution.
Valid range: **1–4**. Values above 4 are clamped to 4 by the runtime.

| Difficulty | Avg. hash attempts | Typical browser solve time | When to use |
| --- | --- | --- | --- |
| 1 | ~16 | <1 ms | Dev/testing only — no real protection |
| 2 | ~256 | <1 ms | Dev/testing only |
| 3 | ~4,096 | 5–50 ms | Recommended default — imperceptible to users |
| 4 | ~65,536 | 50–500 ms | Higher-security APIs where a brief pause is acceptable |

`3` is the recommended default. Use `4` only when your API is a high-value
target and a short visible delay is acceptable to your users.

---

### `ttl_minutes`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `30` |

How long an issued challenge token stays valid. Capped by
`max_ttl_minutes` (see below).

When a token expires the browser SDK re-solves the challenge
**automatically** on the next API call — the user does not see a manual
prompt. The `@veilgate/client` SDK intercepts the 401, opens a hidden
zero-size iframe, solves the proof-of-work in the background, and
retries the original request. Your `onChallenge` overlay fires for the
duration of the solve (~5–50 ms at difficulty 3), then disappears.

The SDK also renews 60 seconds before expiry on any call to
`getToken()`, so sessions stay warm as long as the page is active.

---

### `max_ttl_minutes`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `60` |

The maximum token lifetime the runtime will issue, regardless of what
`ttl_minutes` or `rules/challenge.yaml` request. If `ttl_minutes`
exceeds this value it is silently clamped to `max_ttl_minutes`.

Set this to whatever ceiling makes sense for your threat model:

| `max_ttl_minutes` | `ttl_minutes` | Effective TTL | Re-solve frequency |
| --- | --- | --- | --- |
| 60 (default) | 30 | 30 min | Every ~29 min |
| 60 | 60 | 60 min | Every ~59 min |
| 60 | 120 | 60 min (capped) | Every ~59 min |
| 10 | 30 | 10 min (capped) | Every ~9 min |
| 10 | 5 | 5 min | Every ~4 min |

Shorter `max_ttl_minutes` limits how long a stolen token is usable.
Longer values reduce background re-solve frequency for real users.

## Example

```yaml
challenge:
  secret: ${VEILGATE_SECRET}
  difficulty: 3
  ttl_minutes: 30
  max_ttl_minutes: 60
```

## Related

- [`rules/challenge.yaml`](rules/challenge.md) - HTML template, cookie
  name, status code
- [`detector.score_challenge_threshold`](detector.md#score_challenge_threshold)
- [How-to: Observe-mode rollout](../how-to/observe-and-tune.md)

---

*Previous: [`tarpit:`](tarpit.md) | Next: [`metrics:`](metrics.md)*
