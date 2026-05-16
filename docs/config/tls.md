# `tls:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `tls:`
> **Reload:** restart required.

Enables HTTPS termination at the VeilGate listener. JA3 and JA4 TLS
fingerprinting only work when TLS terminates here - if your edge or CDN
terminates TLS, those signals are unavailable.

**On this page:**

- [`enabled`](#enabled)
- [`cert_file`](#cert_file)
- [`key_file`](#key_file)
- [Generating a cert](#generating-a-cert)
- [Why terminate TLS at VeilGate](#why-terminate-tls-at-veilgate)
- [Related](#related)

## Parameters

### `enabled`

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

Turn the listener at `listen` into HTTPS. When `false`, the listener
serves cleartext HTTP and the JA3/JA4 signals stay silent.

---

### `cert_file`

| Type | Required if `enabled: true` | Default |
| --- | --- | --- |
| string (path) | yes | - |

Path to the PEM-encoded server certificate (or fullchain). Must be
readable by the `veilgate` user.

```yaml
tls:
  cert_file: /etc/veilgate/tls/fullchain.pem
```

---

### `key_file`

| Type | Required if `enabled: true` | Default |
| --- | --- | --- |
| string (path) | yes | - |

Path to the PEM-encoded private key matching `cert_file`.
**File mode must be 0600** and ownership `root:veilgate` (or
`veilgate:veilgate`). The systemd unit's `ProtectSystem=strict` hides
most of `/`, so the key must live somewhere ReadWritePaths can see -
either under `/var/lib/veilgate/` or with an explicit
`ReadWritePaths=` entry pointing at the cert directory.

## Generating a cert

For testing only - production should use ACME / your CA:

```bash
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls
sudo openssl req -x509 -newkey rsa:4096 -keyout /etc/veilgate/tls/key.pem \
  -out /etc/veilgate/tls/cert.pem -days 365 -nodes \
  -subj "/CN=veilgate.local"
sudo chown root:veilgate /etc/veilgate/tls/*.pem
sudo chmod 0640 /etc/veilgate/tls/cert.pem
sudo chmod 0640 /etc/veilgate/tls/key.pem
```

For real certs, run a separate ACME client (Caddy, certbot,
cert-manager) and point `cert_file` / `key_file` at the renewed
artefacts. VeilGate does not implement ACME itself.

## Why terminate TLS at VeilGate

The detector parses the raw ClientHello before Go's stdlib consumes
it, computing both JA3 and JA4 from the verbatim bytes. The full list
of signals that depend on this:

| Signal | Needs JA3/JA4 |
| --- | --- |
| `tls_agent` | yes - exact-hash agent match |
| `tls_bot` | yes - exact-hash bot match |
| `tls_non_browser` | yes - JA4 prefix not matching any known browser |
| `ja4_prefix` (ML feature) | yes |
| `ip_rotation_fleet` | weakly - the JA4 prefix is one of four fingerprint components |

If your edge terminates TLS and forwards plaintext, every row above
turns to "silent". You can still get useful detection from HTTP-layer
and behavioral signals, but the strongest single discriminator is
gone.

## Example

```yaml
tls:
  enabled: true
  cert_file: /etc/veilgate/tls/fullchain.pem
  key_file:  /etc/veilgate/tls/privkey.pem
```

## Related

- [`listen` (top-level)](top-level.md#listen)
- [`rules/tls_fingerprints.yaml`](rules/tls-fingerprints.md)

---

*Previous: [Top-level keys](top-level.md) | Next: [`detector:`](detector.md)*
