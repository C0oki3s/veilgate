# `challenge:`

> **File:** `/etc/veilgate/veilgate.yaml` &nbsp;·&nbsp;
> **Section:** `challenge:` &nbsp;·&nbsp;
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
random value before going to `challenge` or `tarpit` mode** — the
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

Number of leading hex zeros required on the challenge solution.

| Difficulty | Approx solve time on a real browser |
| --- | --- |
| 3 | <100 ms |
| 4 | ~500 ms |
| 5 | ~5 s |
| 6 | ~80 s — too slow for real users |

`4` is the sweet spot. Raise to `5` only if your traffic is
overwhelmingly desktop browsers and you don't mind the visible delay
on solve.

---

### `ttl_minutes`

| Type | Required | Default |
| --- | --- | --- |
| int | no | `30` |

How long an issued challenge token stays valid before the client must
solve a fresh one. Longer TTLs are friendlier to real users; shorter
TTLs reduce the value of stealing a solved cookie.

## Example

```yaml
challenge:
  secret: ${VEILGATE_SECRET}
  difficulty: 4
  ttl_minutes: 30
```

## Related

- [`rules/challenge.yaml`](rules/challenge.md) — HTML template, cookie
  name, status code
- [`detector.score_challenge_threshold`](detector.md#score_challenge_threshold)
- [How-to: Observe-mode rollout](../how-to/observe-and-tune.md)

---

*Previous: [`tarpit:`](tarpit.md) · Next: [`metrics:`](metrics.md)*
