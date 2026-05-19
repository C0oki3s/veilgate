# Getting Started

This guide gets VeilGate running locally, then shows how to verify scoring,
metrics, challenge behavior, and tarpit behavior.

## Quick Start — Install Script (recommended)

The install script downloads the binary, installs a systemd service, clones
community rules, and writes a starter config in `observe` mode.

```bash
curl -sSL https://veilgate.dev/install.sh | sudo bash -s -- --upstream http://localhost:3000
```

After install:

```bash
systemctl status veilgate
journalctl -u veilgate -f
```

VeilGate ships **no embedded rules**. The install script clones the
[veilgate-rules](https://github.com/C0oki3s/veilgate-rules) community pack
automatically. You can update rules at any time without restarting:

```bash
veilgate update-rules
```

## Quick Start with Docker

```bash
docker run -d --name veilgate \
  --network host \
  -v /etc/veilgate/veilgate.yaml:/etc/veilgate/veilgate.yaml:ro \
  -v ~/.veilgate/rules:/home/nonroot/.veilgate/rules \
  -e VEILGATE_SECRET=$(openssl rand -hex 32) \
  ghcr.io/c0oki3s/veilgate:latest -config /etc/veilgate/veilgate.yaml
```

The image runs as root so the ML miner can always write `learned.yaml` to the
mounted rules directory without host-side permission changes.

## Build From Source

Prerequisite: Go `1.25.10` or newer.

```bash
git clone https://github.com/C0oki3s/veilgate.git
cd veilgate
make build
./veilgate -config configs/veilgate.yaml
```

Default listeners:

- Proxy: `http://localhost:8080`
- Dashboard: `http://localhost:9090`
- Metrics: `http://localhost:9090/metrics`

## First Verification

Send a normal request:

```bash
curl http://localhost:8080/
```

Send an agent-shaped request:

```bash
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
```

Check metrics:

```bash
curl http://localhost:9090/metrics | grep veilgate_requests_total
curl http://localhost:9090/metrics | grep veilgate_signal_hits_total
```

In the default `observe` mode, VeilGate scores and records both requests but
still forwards traffic upstream.

## Try Challenge Mode

Set:

```yaml
mode: "challenge"
challenge:
  secret: "replace-this-with-a-long-random-secret"
```

Or export:

```bash
export VEILGATE_SECRET="$(openssl rand -hex 32)"
```

Restart VeilGate and send a suspicious request:

```bash
curl -i -A "httpx/0.27.0" http://localhost:8080/.git/config
```

Medium-score requests receive a JavaScript proof-of-work challenge. Browsers can
solve it; simple HTTP clients usually cannot.

## Try Tarpit Mode

Set:

```yaml
mode: "tarpit"
```

Restart and send:

```bash
curl -i -A "sqlmap/1.7" "http://localhost:8080/admin-panel-v2?id=1%20UNION%20SELECT"
```

High-score requests are diverted to the shadow app. The same client receives a
consistent fake company, fake stack, fake users, and fake vulnerabilities.

## Enable TLS Fingerprinting

Generate a local certificate:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

Configure:

```yaml
tls:
  enabled: true
  cert_file: "cert.pem"
  key_file: "key.pem"
```

Test:

```bash
curl -k https://localhost:8080/
```

When TLS is enabled, VeilGate computes JA3 and JA4 fingerprints from the
ClientHello and can score known agent libraries or non-browser-like fingerprints.

## Rollout Checklist

- Start in `observe`.
- Keep metrics private.
- Set `VEILGATE_SECRET` before `challenge` or `tarpit`.
- Add only true internal clients to `detector.trusted_ips`.
- Set `detector.trusted_proxies` only to CIDRs of proxies you operate.
- Review `rules/` changes as security policy.
- Move to `challenge`, then `tarpit`, after reviewing false positives.

## Next

- [Configuration Reference](../reference/config-reference.md)
- [Deployment](../deployment/README.md)
- [Operations](../operations/README.md)
- [Threat Model](../../THREAT_MODEL.md)
