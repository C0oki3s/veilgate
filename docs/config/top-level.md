# Top-level keys

> **File:** `/etc/veilgate/veilgate.yaml`
>
> **Reload:** restart required (`sudo systemctl restart veilgate`).

The top-level keys control what VeilGate listens on, where it forwards
real requests, and where it loads detection rules from.

**On this page:**

- [`mode`](#mode)
- [`listen`](#listen)
- [`upstream`](#upstream)
- [`rules_dir`](#rules_dir)
- [Example](#example)
- [Related](#related)

## Parameters

### `mode`

| Type | Required | Default |
| --- | --- | --- |
| string | no | `"observe"` |

One of `"observe"`, `"challenge"`, `"tarpit"`, `"auto"`. Governs what the proxy
does when a score crosses a threshold.

| Value | Behavior |
| --- | --- |
| `observe` | Score every request, never divert. Safe rollout mode. |
| `challenge` | Below `score_challenge_threshold` -> forward; at or above -> JS proof-of-work. Tarpit threshold ignored. |
| `tarpit` | Below `score_challenge_threshold` -> forward; between thresholds -> challenge; at or above `score_tarpit_threshold` -> tarpit. |
| `auto` | Threshold-driven enforcement: below challenge -> forward; between thresholds -> challenge; at or above tarpit -> tarpit. |

> **Operator guidance.** Always start in `observe` mode for at least one
> traffic cycle (typically a week). See the
> [observe-and-tune how-to](../how-to/observe-and-tune.md).

---

### `listen`

| Type | Required | Default |
| --- | --- | --- |
| string | no | `:8080` |

Address the proxy listens on. Standard `host:port` form. Use `:8080`
to bind to all interfaces; use `127.0.0.1:8080` to bind only to
loopback (typical when an edge proxy in front owns TLS).

To bind to a privileged port (`:80` / `:443`) without running as root,
either:

- Front VeilGate with another proxy that owns the privileged port, or
- Grant the binary `cap_net_bind_service` and uncomment
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` in the systemd unit. See
  [deployment guide -> privileged ports](../deployment/README.md).

---

### `upstream`

| Type | Required | Default |
| --- | --- | --- |
| string (URL) | yes (effectively) | - |

URL of the real application VeilGate forwards untainted requests to.
Must include the scheme (`http://` or `https://`).

```yaml
upstream: "http://127.0.0.1:3000"
upstream: "https://app.internal.example.com:8443"
```

VeilGate sends `Host: <upstream-host>` to the upstream, not the
original host. Configure the upstream's virtual hosting accordingly.

---

### `rules_dir`

| Type | Required | Default |
| --- | --- | --- |
| string (path) | no | `""` (use embedded defaults) |

Directory containing the detection rule files (`detector.yaml`,
`ml.yaml`, `payloads.yaml`, ...). When empty, VeilGate uses the rule
files compiled into the binary - convenient for first boot. For community
rules installed with `veilgate update-rules`, use `~/.veilgate/rules`.

The watcher uses `fsnotify` to debounce-reload any file under this
directory whose name matches a registered handler. Files added later
via `cp` / `mv` are picked up automatically.

## Example

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
mode: "observe"
rules_dir: "~/.veilgate/rules"

detector:
  score_tarpit_threshold: 70
  score_challenge_threshold: 40
  trusted_proxies:
    - "10.0.0.0/8"
    - "192.168.0.0/16"

persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"

metrics:
  listen: "127.0.0.1:9090"
```

## Related

- [`detector:`](detector.md) - score thresholds + trusted proxies
- [`tls:`](tls.md) - HTTPS termination
- [Deployment guide](../deployment/README.md)

---

*Previous: [Configuration reference](README.md) | Next: [`tls:`](tls.md)*
