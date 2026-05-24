# TLS Setup

VeilGate must terminate TLS itself to compute JA3 and JA4 fingerprints. When
your edge layer (CDN, load balancer) terminates TLS before VeilGate, the raw
ClientHello is consumed upstream and those fingerprint signals go silent.

This guide covers every cert source you are likely to encounter:

- [Self-signed (dev/lab)](#self-signed-devlab)
- [Let's Encrypt with certbot](#lets-encrypt-with-certbot)
- [Cloudflare Origin CA](#cloudflare-origin-ca)
- [Existing enterprise or Active Directory CA cert](#existing-enterprise-or-active-directory-ca-cert)
- [Configure VeilGate to use the cert](#configure-veilgate-to-use-the-cert)
- [Bind to port 443](#bind-to-port-443)
- [Cert renewal and hot-reload](#cert-renewal-and-hot-reload)
- [Verify TLS is working](#verify-tls-is-working)

---

## Self-signed (dev/lab)

Use this for local development, staging, or quick smoke tests. Browsers and
curl will warn about the cert; clients behind a trusted CA chain will reject it.
Never use self-signed in production.

```bash
# Create a dedicated directory.
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls

# Generate a 4096-bit RSA key and a self-signed cert valid for 365 days.
sudo openssl req -x509 \
  -newkey rsa:4096 \
  -keyout /etc/veilgate/tls/key.pem \
  -out    /etc/veilgate/tls/cert.pem \
  -days   365 \
  -nodes \
  -subj   "/CN=veilgate.local"

# Lock down permissions — only veilgate can read the key.
sudo chown root:veilgate /etc/veilgate/tls/*.pem
sudo chmod 0640 /etc/veilgate/tls/cert.pem
sudo chmod 0640 /etc/veilgate/tls/key.pem
```

Test with curl:

```bash
curl -k https://localhost:8080/
# -k ignores the self-signed warning
```

---

## Let's Encrypt with certbot

Let's Encrypt issues free, browser-trusted certificates valid for 90 days with
automatic renewal. This is the recommended path for any internet-facing server
you control.

### Install certbot

**Debian / Ubuntu:**

```bash
sudo apt install certbot
```

**RHEL / Rocky / AlmaLinux:**

```bash
sudo dnf install certbot
```

### Obtain the cert

If VeilGate is the only thing listening on port 80/443, use the standalone
authenticator (certbot runs a temporary HTTP server):

```bash
sudo certbot certonly --standalone \
  -d api.example.com \
  --non-interactive \
  --agree-tos \
  -m admin@example.com
```

If something else owns port 80, use the webroot authenticator instead:

```bash
sudo certbot certonly --webroot \
  -w /var/www/html \
  -d api.example.com \
  --non-interactive \
  --agree-tos \
  -m admin@example.com
```

Certificates land in `/etc/letsencrypt/live/api.example.com/`:

| File | Contents |
|---|---|
| `fullchain.pem` | Your cert + all intermediate CA certs (use this as `cert_file`) |
| `privkey.pem` | Your private key (use this as `key_file`) |
| `cert.pem` | Your cert only (without intermediates — usually not what you want) |
| `chain.pem` | Intermediate CA certs only |

Grant the veilgate user read access:

```bash
sudo chmod 0750 /etc/letsencrypt/live/
sudo chmod 0750 /etc/letsencrypt/archive/
sudo chgrp veilgate /etc/letsencrypt/live/ /etc/letsencrypt/archive/
sudo chgrp -R veilgate /etc/letsencrypt/live/api.example.com
sudo chgrp -R veilgate /etc/letsencrypt/archive/api.example.com
```

### Automatic renewal

certbot installs a systemd timer or cron job that renews expiring certs
automatically. After renewal you need VeilGate to reload the new cert.

Add a deploy hook:

```bash
sudo mkdir -p /etc/letsencrypt/renewal-hooks/deploy

sudo tee /etc/letsencrypt/renewal-hooks/deploy/veilgate.sh <<'EOF'
#!/bin/bash
systemctl reload-or-restart veilgate
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/veilgate.sh
```

> VeilGate does not yet support hot-reloading cert files — a restart is
> required. The deploy hook above does that automatically.

Test renewal without actually renewing:

```bash
sudo certbot renew --dry-run
```

---

## Cloudflare Origin CA

Cloudflare Origin CA certificates are issued by Cloudflare's own CA and are
trusted **only by Cloudflare's edge**. Use them when your traffic goes through
Cloudflare and you want `Full (Strict)` TLS mode (Cloudflare encrypts to your
origin with a verified cert).

> **JA3/JA4 note:** when Cloudflare is in front, it terminates TLS before
> VeilGate. VeilGate sees Cloudflare's ClientHello, not the real browser's.
> JA3/JA4 fingerprinting of real user clients is not possible in this topology.
> See [Cloudflare + VeilGate setup](cloudflare-setup.md) for the full trade-off.

### Generate an Origin CA cert in Cloudflare

1. Log in to the [Cloudflare dashboard](https://dash.cloudflare.com).
2. Go to **SSL/TLS → Origin Server**.
3. Click **Create Certificate**.
4. Choose **Let Cloudflare generate a private key and a CSR** (recommended) or
   paste your own CSR.
5. Set the hostnames: `api.example.com` and optionally `*.example.com`.
6. Choose a validity period (up to 15 years for Origin CA).
7. Click **Create**.

Cloudflare shows the certificate and private key **once**. Copy both immediately.

Save them to your server:

```bash
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls

# Paste the certificate Cloudflare showed you.
sudo tee /etc/veilgate/tls/cert.pem <<'EOF'
-----BEGIN CERTIFICATE-----
<paste Cloudflare Origin CA certificate here>
-----END CERTIFICATE-----
EOF

# Paste the private key Cloudflare showed you.
sudo tee /etc/veilgate/tls/key.pem <<'EOF'
-----BEGIN PRIVATE KEY-----
<paste private key here>
-----END PRIVATE KEY-----
EOF

sudo chown root:veilgate /etc/veilgate/tls/*.pem
sudo chmod 0640 /etc/veilgate/tls/cert.pem
sudo chmod 0640 /etc/veilgate/tls/key.pem
```

In the Cloudflare dashboard, set **SSL/TLS mode** to **Full (Strict)**. This
tells Cloudflare to verify your origin cert before forwarding traffic.

---

## Existing enterprise or Active Directory CA cert

Enterprise environments typically have a Windows Certificate Services (AD CS)
root CA. You may receive your cert in several formats. The steps below cover
the most common ones.

### Format: PKCS#12 / PFX (`.pfx` or `.p12`)

This is a container that holds both the cert and the private key, usually
password-protected.

```bash
# Extract the private key (you will be prompted for the .pfx password).
openssl pkcs12 -in server.pfx -nocerts -nodes \
  -out /tmp/key.pem

# Extract the certificate chain.
openssl pkcs12 -in server.pfx -nokeys -chain \
  -out /tmp/cert.pem

# Install with correct permissions.
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls
sudo install -m 0640 -o root -g veilgate /tmp/key.pem  /etc/veilgate/tls/key.pem
sudo install -m 0640 -o root -g veilgate /tmp/cert.pem /etc/veilgate/tls/cert.pem

# Remove the temporary files.
rm /tmp/key.pem /tmp/cert.pem
```

### Format: DER-encoded binary (`.cer` or `.der`) + separate key

```bash
# Convert cert from DER to PEM.
openssl x509 -inform DER -in server.cer -out /tmp/cert.pem

# If the key was exported as DER too:
openssl rsa -inform DER -in server.key -out /tmp/key.pem
# Or for a PKCS#8 key:
openssl pkcs8 -inform DER -in server.key -out /tmp/key.pem

# Install.
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls
sudo install -m 0640 -o root -g veilgate /tmp/cert.pem /etc/veilgate/tls/cert.pem
sudo install -m 0640 -o root -g veilgate /tmp/key.pem  /etc/veilgate/tls/key.pem
rm /tmp/cert.pem /tmp/key.pem
```

### Format: PEM already (`.pem` or `.crt` + `.key`)

```bash
sudo install -d -o root -g veilgate -m 0750 /etc/veilgate/tls
sudo install -m 0640 -o root -g veilgate server.crt /etc/veilgate/tls/cert.pem
sudo install -m 0640 -o root -g veilgate server.key /etc/veilgate/tls/key.pem
```

### Include the intermediate chain

Enterprise CAs almost always use intermediate certificates. Browsers and TLS
clients will reject the cert if the intermediates are missing from the chain.

Concatenate in this order — leaf first, root last:

```bash
cat server.pem intermediate.pem root.pem > /tmp/fullchain.pem
sudo install -m 0640 -o root -g veilgate /tmp/fullchain.pem /etc/veilgate/tls/cert.pem
rm /tmp/fullchain.pem
```

If you got the intermediates as DER files, convert each one first:

```bash
openssl x509 -inform DER -in intermediate.cer -out intermediate.pem
```

### Export from Windows Certificate Manager (MMC)

If you need to pull the cert from the Windows cert store:

1. Run `certlm.msc` (Local Computer cert store) or `certmgr.msc` (Current
   User).
2. Find your cert under **Personal → Certificates**.
3. Right-click → **All Tasks → Export**.
4. In the Export Wizard:
   - Choose **Yes, export the private key**.
   - Format: **Personal Information Exchange (.pfx)**.
   - Set a password.
5. Copy the `.pfx` to your Linux server and follow the PKCS#12 steps above.

### Verify the cert and key match

Before restarting VeilGate, confirm the certificate and key are a matching
pair. The modulus hashes must be identical:

```bash
openssl x509 -noout -modulus -in /etc/veilgate/tls/cert.pem | md5sum
openssl rsa  -noout -modulus -in /etc/veilgate/tls/key.pem  | md5sum
# Both lines must print the same hash.
```

Verify the cert chain is complete:

```bash
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt \
  /etc/veilgate/tls/cert.pem
# For an enterprise CA not in the system trust store, point -CAfile at your
# root CA cert instead:
openssl verify -CAfile /path/to/enterprise-root.pem \
  /etc/veilgate/tls/cert.pem
```

---

## Configure VeilGate to use the cert

In `/etc/veilgate/veilgate.yaml`:

```yaml
listen: ":443"
upstream: "http://127.0.0.1:3000"
rules_dir: "~veilgate/.veilgate/rules"
mode: "challenge"

tls:
  enabled:   true
  cert_file: /etc/veilgate/tls/cert.pem
  key_file:  /etc/veilgate/tls/key.pem
```

Restart VeilGate:

```bash
sudo systemctl restart veilgate
journalctl -u veilgate -n 30
# Look for: tls listener started addr=:443
```

---

## Bind to port 443

Linux blocks unprivileged processes from binding ports below 1024. VeilGate
runs as the non-root `veilgate` user by default.

**Option A — capability grant (recommended):**

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/veilgate
```

Enable the matching flag in the systemd unit:

```bash
sudo systemctl edit veilgate
```

Add:

```ini
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart veilgate
```

**Option B — run behind nginx on port 443:**

Keep VeilGate on port 8443 and let nginx own 443:

```nginx
server {
    listen 443 ssl;
    server_name api.example.com;

    ssl_certificate     /etc/veilgate/tls/cert.pem;
    ssl_certificate_key /etc/veilgate/tls/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

> **JA3/JA4 warning:** if nginx terminates TLS, VeilGate cannot compute JA3
> or JA4. Use Option A if fingerprinting matters.

---

## Cert renewal and hot-reload

VeilGate requires a restart to pick up a replaced cert file. Automate this with
a certbot deploy hook (see [Let's Encrypt](#lets-encrypt-with-certbot) above)
or a cron job that checks cert expiry and restarts the service:

```bash
# /etc/cron.d/veilgate-cert-check
0 3 * * * root \
  openssl x509 -checkend 604800 -noout \
    -in /etc/veilgate/tls/cert.pem \
  || systemctl restart veilgate
```

This checks every night at 03:00 and restarts VeilGate if the cert expires
within 7 days (604800 seconds). By then certbot or your renewal process should
have already placed a fresh cert.

---

## Verify TLS is working

```bash
# Basic TLS handshake.
curl -v https://api.example.com/ 2>&1 | grep -E "SSL|TLS|issuer|subject"

# Check the cert chain.
openssl s_client -connect api.example.com:443 -showcerts </dev/null 2>&1 \
  | grep -E "subject|issuer|depth"

# Confirm JA3/JA4 signals appear in metrics.
curl -s http://127.0.0.1:9090/metrics | grep tls_fingerprints
# Expect non-zero counter after a few HTTPS requests.

# Check the service log for fingerprint activity.
journalctl -u veilgate -n 50 | grep -i "ja[34]\|tls"
```

---

## Related

- [JA3/JA4 fingerprinting setup](ja3-ja4-fingerprinting.md) — signals, database, tuning
- [Cloudflare + VeilGate setup](cloudflare-setup.md) — TLS modes and origin certs in Cloudflare
- [Configuration reference: `tls:`](../config/tls.md)
- [Setup: SPA on CDN](setup-spa-cdn.md)
- [Setup: same-origin](setup-same-origin.md)
