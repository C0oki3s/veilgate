# Getting Started

This guide gets VeilGate running locally, then shows how to verify scoring,
metrics, challenge behavior, and tarpit behavior.

## Prerequisites

- Go `1.25.10` or newer.
- A local upstream app on `http://localhost:3000`.

## Build From Source

```bash
git clone https://github.com/C0oki3s/veilgate.git
cd veilgate
make build
```

Run:

```bash
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

- [Configuration Reference](CONFIG_REFERENCE.md)
- [Deployment](DEPLOYMENT.md)
- [Operations](OPERATIONS.md)
- [Threat Model](../THREAT_MODEL.md)
