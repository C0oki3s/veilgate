# How-to guides

Task-oriented walk-throughs. Each page solves one specific problem an
operator hits during install or day-2 ops.

| Guide | When to read it |
| --- | --- |
| [Install on Linux](install-on-linux.md) | First-time install on a fresh host |
| [Observe-mode rollout & threshold tuning](observe-and-tune.md) | Before flipping to `challenge` or `tarpit` |
| [Protect an SPA + API on different subdomains](protect-multi-origin.md) | Frontend on `app.example.com`, API on `api.example.com` behind veilgate |
| [Authenticate server-to-server callers with HMAC](server-to-server-hmac.md) | Internal services, mobile apps, webhooks — anything without a JS runtime |
| [Promote learned rules](promote-learned-rules.md) | Once the miner has been running for a week |
| [Handle a Right-to-Erasure (RTBF) request](handle-rtbf.md) | When a data-subject deletion arrives |
| [Monitor with Prometheus + Grafana](monitor-with-prometheus.md) | When you want history, not just live metrics |
| [Install community rules](install-community-rules.md) | Pull the latest community-maintained detection rules from veilgate-rules |

If you don't see your task here, the [configuration reference](../config/README.md)
documents every individual setting.

## Conventions used in these guides

- All paths assume the install layout from
  [deployment guide](../deployment/README.md): binary at `/usr/local/bin/veilgate`,
  config at `/etc/veilgate/`, data at `/var/lib/veilgate/`.
- Commands prefixed `sudo` need root.
- Commands prefixed `veilgate$` run as the dedicated `veilgate`
  user — typically `sudo -u veilgate <cmd>`.
- A YAML block under a heading like `~/.veilgate/rules/ml.yaml`
  shows a *partial* file — merge with what's already there, don't
  replace.

## Related

- [Use cases](../usecases/README.md) — objective-driven pages
- [Configuration reference](../config/README.md)
- [Deployment guide](../deployment/README.md)

---

*Previous: [Use cases](../usecases/README.md) · Next: [Install on Linux](install-on-linux.md)*
