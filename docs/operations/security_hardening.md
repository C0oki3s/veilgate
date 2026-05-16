# Security Hardening

This page lists security controls and configuration choices that must be
reviewed before deploying VeilGate in an enforcement-capable mode
(`challenge`, `tarpit`, or `auto`).

VeilGate is not a replacement for patching, secure coding, authentication,
authorization, rate limiting, or a WAF. It is a deception layer. Apply
defense-in-depth.

---

## Challenge Secret

**Requirement:** `VEILGATE_SECRET` must be set to a long random value before
enabling enforcement.

VeilGate uses this key to sign challenge payloads and issued pass tokens. The
key is also used to sign HMAC verifier responses when the HMAC verifier is
enabled.

VeilGate explicitly refuses to start outside `observe` mode when the
placeholder value is still in place:

```go
// cmd/veilgate/main.go (startup check)
// startup refuses to run in enforcement mode with the default secret
```

**How to set:**

```bash
export VEILGATE_SECRET="$(openssl rand -hex 32)"
```

**For systemd deployments,** use a drop-in override file:

```ini
# /etc/systemd/system/veilgate.service.d/secret.conf
[Service]
EnvironmentFile=/etc/veilgate/secret.env
```

```bash
# /etc/veilgate/secret.env (mode 600, owned by root)
VEILGATE_SECRET=<your-secret>
```

**Never:**
- Commit the secret to a version-controlled repository.
- Share the secret across environments (each deployment should have its own).
- Use a short or predictable secret.

**Rotation:** Rotate by setting a new value and restarting. Rotation
invalidates all outstanding challenge tokens. Clients mid-challenge will need
to re-solve.

---

## Metrics Listener

**Requirement:** `metrics.listen` must not be accessible from the public
internet.

```yaml
# Correct production configuration
metrics:
  listen: "127.0.0.1:9090"
```

The default value `":9090"` binds to all interfaces. Change it before
deploying to any publicly accessible host.

**Why:** The metrics endpoint exposes:
- Detector decision distribution and score histograms.
- Active signal hit counts (reveals which signals are effective).
- Attack traffic volume and patterns.
- Approximate attacker cost estimates.
- ML training activity.

This information can be used by an attacker to tune evasion techniques.

**Remote access pattern:**

```bash
# SSH tunnel from your workstation
ssh -L 9090:127.0.0.1:9090 user@yourhost
# Access: http://localhost:9090/metrics
```

---

## TLS Private Key

**Requirement:** The TLS private key must be readable only by the VeilGate
process user.

```bash
chmod 600 /etc/veilgate/key.pem
chown veilgate:veilgate /etc/veilgate/key.pem
```

Do not run VeilGate as root in production. Use a dedicated service account
with minimal privileges.

**Never:**
- Commit `key.pem` to a repository.
- Set world-readable permissions on the key file.
- Reuse the same key across different environments or services.

**When to use TLS termination at VeilGate:** Only when you need TLS
fingerprint (JA3/JA4) signals. If you do not need fingerprinting, it is
acceptable to terminate TLS at an upstream edge component (nginx, CDN, ALB)
and let VeilGate operate over plain HTTP behind it.

---

## Persistence Database

**Requirement:** The SQLite database must be restricted to the VeilGate
process user.

VeilGate sets `0600` on the database file at creation, but verify after
deployment:

```bash
ls -la /var/lib/veilgate/events.db
# Expected: -rw------- 1 veilgate veilgate ...
```

**Why:** The database contains:
- Client IP addresses.
- Request paths, user agents, and headers.
- Detector scores and signal lists.
- ML feature vectors.
- Canary tokens and client associations.

This is sufficient to reconstruct attacker patterns and potentially identify
clients. It is also a target for data exfiltration by an attacker who gains
local access.

**Operational rules:**
- Do not expose the database path via a web server or file share.
- Do not store the database on a world-readable filesystem.
- Include the database in your backup and encryption strategy.
- Set `persist.retention_days` in line with your data retention policy.

---

## Trusted Proxies

**Requirement:** `detector.trusted_proxies` must include only proxies you
operate.

```yaml
detector:
  trusted_proxies:
    - "10.10.0.5/32"   # specific load balancer IP, not a broad range
```

**Why:** If `trusted_proxies` is too broad, an attacker can inject a spoofed
IP into `X-Forwarded-For` and have VeilGate use that as the client ID. This
enables:
- Tracker poisoning (creating fake client state).
- IP spoofing to appear as `127.0.0.1` or a trusted internal IP.
- Score manipulation by cycling fake IPs to avoid stateful detection.

```go
// internal/proxy/proxy.go
// VeilGate explicitly comments on the XFF injection risk:
// "nuclei and similar probes inject things like ${jndi:ldap://...}
//  or <script>alert(1)</script> into the header"
```

**Rules:**
- Add only the direct TCP peer's IP or CIDR.
- Do not add public internet ranges.
- Do not add `0.0.0.0/0`.
- Verify the value after each infrastructure change.

---

## Trusted IPs

**Requirement:** `detector.trusted_ips` should be empty or contain only
specific, verified IP addresses.

```yaml
detector:
  trusted_ips: []   # preferred; add only if absolutely necessary
```

A trusted IP receives a score of `0` with a `trusted_ip` signal and bypasses
all detector evaluation. This is appropriate only for:
- Internal health check systems.
- CI pipeline IPs with a known non-browser user agent that would otherwise
  score high.

**Do not add `127.0.0.1`** to `trusted_ips` unless you intentionally want
loopback traffic to bypass scoring. During smoke testing, a test from
localhost will not exercise the detection pipeline if `127.0.0.1` is trusted.

---

## Rule Files

**Requirement:** Rule files must be treated as security policy, not as
application configuration.

Rule files define:
- Which User-Agent strings are considered suspicious.
- Which IP CIDRs are considered high-risk.
- What the fake application looks like.
- What decoy payloads and canary tokens are served.
- What constitutes a challenge-worthy or tarpit-worthy score.

**Operational controls:**
- Version rule files in the same repository as your deployment configuration.
- Review rule changes through the same process as code changes.
- Mount rule files read-only in Kubernetes or container deployments where
  possible:
  ```yaml
  # kubernetes/configmap.yaml
  readOnly: true
  ```
- Restrict filesystem ownership: `chown -R root:veilgate /etc/veilgate/rules`
  and `chmod 640` on each file.

---

## Tarpit Templates and Payloads

**Requirement:** Tarpit templates must not contain real secrets, real
credentials, or real infrastructure identifiers.

Templates in `rules/templates.yaml` and payloads in `rules/payloads.yaml` are
served to clients whose traffic crossed the tarpit threshold. A false positive
means a legitimate user receives fake content.

**Rules:**
- Review all template and payload content before enabling tarpit mode.
- Do not embed real database connection strings, API keys, internal hostnames,
  or real employee names.
- Fake credentials must be plausible but definitively fake (use obvious
  patterns like `FakePassword!123`).
- Do not include content that could cause harm if replayed against a third-party
  system.

---

## Deployment User

**Requirement:** VeilGate must not run as root.

Create a dedicated service account:

```bash
# Linux
useradd -r -s /sbin/nologin -d /var/lib/veilgate veilgate
chown -R veilgate:veilgate /var/lib/veilgate /etc/veilgate
```

Update the systemd unit:

```ini
# /etc/systemd/system/veilgate.service
[Service]
User=veilgate
Group=veilgate
```

If VeilGate needs to bind to port 443, use `setcap` rather than running as root:

```bash
setcap 'cap_net_bind_service=+ep' /usr/local/bin/veilgate
```

---

## Network Exposure

**Requirement:** Only the proxy listener should be publicly accessible.

| Listener | Exposure |
| --- | --- |
| `listen: ":8080"` (or 443) | Public — serves clients |
| `metrics.listen: "127.0.0.1:9090"` | Private — operator only |

Do not expose the metrics port via firewall rules, security groups, or load
balancer listeners. If using cloud infrastructure:

```hcl
# AWS security group (Terraform example from deployments/aws/main.tf)
# Allow only port 8080/443 inbound from the internet
# Allow only port 9090 inbound from VPN/bastion CIDR
```

---

## Container and Kubernetes Deployments

When running in Docker or Kubernetes:

1. **Mount rule files as a read-only volume** when possible.
2. **Inject `VEILGATE_SECRET` as a Kubernetes Secret**, not a ConfigMap.
3. **Do not expose the metrics port via an Ingress** or LoadBalancer service.
4. **Use a non-root user** in the container image (`USER veilgate`).
5. **Set `readOnlyRootFilesystem: true`** in the securityContext, and mount
   writable volumes for data and logs explicitly.
6. **Set resource limits** to prevent a tarpit flood from consuming all node
   resources:

```yaml
# kubernetes/deployment.yaml
resources:
  limits:
    memory: "512Mi"
    cpu: "500m"
  requests:
    memory: "256Mi"
    cpu: "250m"
```

---

## Security Invariants

These behaviors are intentional and must not be circumvented:

1. **Tarpit decisions are not bypassed by verifiers or challenge tokens.**
   A valid HMAC signature or solved challenge can only upgrade a `challenge`
   decision to `real`. It cannot upgrade a `tarpit` decision.
   See `internal/proxy/proxy.go`:
   ```go
   if decision != DecisionTarpit {
       // verifier / challenge bypass applies here only
   }
   ```

2. **`X-Forwarded-For` is only trusted from `trusted_proxies`.**
   An untrusted direct peer's forwarded headers are silently ignored.

3. **Score is capped at 100.**
   No combination of signals can produce a score above 100.

4. **The metrics listener is a separate server from the proxy listener.**
   They are bound to separate addresses and ports. The proxy listener cannot
   accidentally serve metrics.

---

## Limitations

VeilGate is not:

- A full WAF: it does not parse and block injection payloads.
- A DDoS protection layer: it does not rate-limit at the network level.
- A vulnerability remediation mechanism: it does not patch the upstream
  application.
- An intrusion prevention system: it does not block IP addresses at the
  network layer.
- A universal bot defense: a sophisticated attacker with a headless Chromium
  can pass the challenge. VeilGate raises cost, not an impenetrable barrier.

---

## Related

- [Rollout Guide](rollout.md)
- [Troubleshooting](troubleshooting.md)
- [THREAT_MODEL.md](../../THREAT_MODEL.md)
- [Module veilgate_challenge](../modules/veilgate_challenge.md)
- [Module veilgate_verifier](../modules/veilgate_verifier.md)
- [Module veilgate_proxy](../modules/veilgate_proxy.md)
