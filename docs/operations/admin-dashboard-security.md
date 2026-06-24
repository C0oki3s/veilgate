# Admin Dashboard Security And Private Access

The admin dashboard can edit `veilgate.yaml`, rule files, detection signals,
OpenAPI blueprints, decoy endpoints, and credentials. Treat it like a production
control plane. The recommended posture is:

```text
public internet
      |
      x  no direct admin access

operator device
      |
      v
private access layer: Tailscale, corporate VPN, bastion, or private subnet
      |
      v
veilgate-admin on 127.0.0.1:8888 or a private interface only
```

Do not expose `veilgate-admin` directly on a public IP unless another trusted
access layer sits in front of it.

## Security Goals

| Goal | Control |
| --- | --- |
| No public admin port | Bind to localhost or a private interface; block internet ingress in NSG/security group/firewall. |
| Strong operator identity | Use Tailscale, corporate VPN, SSO proxy, or bastion authentication before the dashboard login. |
| Least privilege network access | Allow only operator devices or VPN CIDRs to reach TCP 8888. |
| Credential safety | Change the seeded `admin` / `veilgate` password immediately; rotate after incidents. |
| Auditability | Keep `/audit`, `/var/lib/veilgate/admin-audit.log`, and systemd journal logs. |
| Blast-radius reduction | Keep config, DB, audit, and rule paths owned by the service account with narrow write access. |

## Recommended Deployment

Use the installer default:

```text
127.0.0.1:8888
```

This prevents direct network access to the dashboard. Operators connect through
one of these patterns:

1. SSH tunnel over a trusted path.
2. Tailscale Serve from localhost to the tailnet.
3. A Tailscale subnet router or corporate VPN into a private subnet, with the
   dashboard bound to a private IP.
4. A bastion or reverse proxy with SSO, MFA, TLS, and restrictive source rules.

## Pattern 1: SSH Tunnel Over Tailscale

This is the safest default when the server runs Tailscale and SSH is restricted
to your tailnet.

Keep the dashboard on localhost:

```bash
/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr 127.0.0.1:8888
```

Connect from your workstation:

```bash
ssh -L 8888:127.0.0.1:8888 veilgate@<server-tailnet-name>
```

Then open:

```text
http://localhost:8888
```

Security properties:

- The admin HTTP listener is not reachable from the LAN, VPC, or internet.
- Tailscale or VPN controls decide who can reach SSH.
- SSH decides who can create the tunnel.
- The dashboard still requires its own login.

Use this when you want the smallest exposed surface.

## Pattern 2: Tailscale Serve

Tailscale Serve can proxy a localhost service to other devices in the same
tailnet. This is useful when you want a stable tailnet HTTPS URL without opening
TCP 8888 on the server interface.

Keep `veilgate-admin` bound to localhost:

```bash
/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr 127.0.0.1:8888
```

Expose it inside the tailnet:

```bash
tailscale serve 8888
```

Access is still controlled by the tailnet policy. Tailscale documents that Serve
routes traffic from other tailnet devices to a local service and that access
rules apply to Serve traffic.

Do not use Tailscale Funnel for the admin dashboard. Funnel is for public
internet exposure; the admin dashboard should stay private.

## Pattern 3: Direct Tailscale IP Bind

If you do not want SSH tunnels or Serve, bind the dashboard to the host's
Tailscale IP only:

```bash
tailscale ip -4
```

Then:

```bash
/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr <tailscale-ip>:8888
```

This makes the dashboard reachable over the tailnet but not over the public
interface. Use Tailscale access rules so only the operator group can reach
`<tailscale-ip>:8888`.

Example ACL-style policy:

```json
{
  "groups": {
    "group:veilgate-admins": ["alice@example.com", "bob@example.com"]
  },
  "tagOwners": {
    "tag:veilgate-admin": ["group:veilgate-admins"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:veilgate-admins"],
      "dst": ["tag:veilgate-admin:8888"]
    }
  ]
}
```

Tailscale recommends grants for new policy work, while ACLs continue to work.
If your tailnet has migrated to grants, express the same idea there: only the
operator group can reach the admin-tagged device on TCP 8888.

## Pattern 4: Corporate VPN Or Private Subnet

For a traditional VPN, bind `veilgate-admin` to a private interface and restrict
the cloud NSG/security group to the VPN CIDR:

```bash
/usr/local/bin/veilgate-admin \
  --config /etc/veilgate/veilgate.yaml \
  --addr 10.10.2.15:8888
```

Example NSG/security-group intent:

| Direction | Protocol | Port | Source | Action |
| --- | --- | --- | --- | --- |
| Inbound | TCP | 8888 | `10.50.0.0/16` VPN CIDR | Allow |
| Inbound | TCP | 8888 | internet / `0.0.0.0/0` | Deny |
| Inbound | TCP | 22 | bastion or VPN CIDR | Allow |
| Inbound | TCP | 80/443/8080 | public load balancer only, if needed | Allow |

Keep the NSG/security group narrow even when the dashboard has login auth. The
network layer should block unauthenticated internet clients before HTTP reaches
the Go process.

## Pattern 5: Tailscale Subnet Router

Use this when the VeilGate host cannot run Tailscale directly but lives in a
private subnet reachable through a Tailscale subnet router.

Recommended layout:

```text
operator laptop with Tailscale
      |
      v
tailnet
      |
      v
subnet router advertises 10.10.2.0/24
      |
      v
veilgate-admin on 10.10.2.15:8888
```

Controls:

- Tailscale policy allows only operators to reach the advertised subnet and
  destination port.
- Cloud NSG/security group allows TCP 8888 only from the subnet router or VPN
  address range.
- The admin dashboard keeps its own login and audit trail.

Tailscale documents subnet routers as gateways from a tailnet to conventional
subnets and states that they respect Tailscale access-control policy.

## Do Not Use These Patterns

Avoid:

- `--addr 0.0.0.0:8888` with an internet-open NSG rule.
- Public DNS pointing directly at `veilgate-admin`.
- Tailscale Funnel for the admin dashboard.
- Shared default credentials after first boot.
- Wide Tailscale policies such as allowing every tailnet user to every port.
- Allowing cloud health checkers, scanners, or public load balancers to probe
  the admin dashboard.

## Dashboard-Level Controls

The admin app adds these controls:

| Control | Behavior |
| --- | --- |
| Login sessions | DB-backed users and sessions when `admin.db` is available. |
| Forced first password change | Seeded `admin` / `veilgate` account is marked `must_change`. |
| Audit log | Login attempts, settings saves, rule edits, signal edits, OpenAPI imports, and decoy changes are logged. |
| Security headers | CSP, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`. |
| Decoy catch-all | Unknown scanner paths receive fake or generic responses instead of revealing app routes. |

These controls are useful, but they are not a replacement for private network
access.

## Host Firewall Examples

If you bind directly to a private interface, also enforce host-level firewall
rules.

UFW example:

```bash
sudo ufw deny 8888/tcp
sudo ufw allow from 10.50.0.0/16 to any port 8888 proto tcp
```

Firewalld example:

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.50.0.0/16" port protocol="tcp" port="8888" accept'
sudo firewall-cmd --reload
```

Prefer cloud NSG/security-group enforcement plus host firewall enforcement.
Defense in depth matters because dashboard access can change production
behavior.

## Verification Checklist

From the public internet, the admin port should fail:

```bash
curl -I --connect-timeout 3 http://<public-ip>:8888
```

From the VPN or tailnet path, it should respond:

```bash
curl -I http://<private-ip-or-tailnet-name>:8888/api/v1/health
```

Check listeners on the host:

```bash
ss -ltnp | grep 8888
```

Expected safe bindings:

```text
127.0.0.1:8888
<tailscale-ip>:8888
<private-subnet-ip>:8888
```

Risky binding:

```text
0.0.0.0:8888
```

`0.0.0.0:8888` is acceptable only when NSG/security-group and host firewall
rules restrict source access to a trusted VPN, subnet router, or reverse proxy.

## Incident Checklist

If the admin dashboard was reachable from the internet:

1. Change the listener to `127.0.0.1:8888` or a private IP.
2. Deny TCP 8888 from `0.0.0.0/0` and `::/0` in NSG/security-group rules.
3. Restart `veilgate-admin`.
4. Rotate the admin password.
5. Review `/audit`, `/var/lib/veilgate/admin-audit.log`, and `journalctl -u veilgate-admin`.
6. Review `veilgate.yaml`, `signals.yaml`, `openapi.yaml`, decoys, and recently
   edited rule files.
7. Rotate any secrets stored in `veilgate.yaml`.
8. Preserve logs before truncating or deleting anything.

## External References

- Tailscale ACLs and grants: <https://tailscale.com/docs/features/access-control/acls>
- Tailscale subnet routers: <https://tailscale.com/docs/features/subnet-routers>
- Tailscale Serve: <https://tailscale.com/docs/features/tailscale-serve>

## Related

- [Admin dashboard operations](admin-dashboard.md)
- [Use the admin dashboard](../how-to/use-admin-dashboard.md)
- [Admin dashboard reference](../reference/admin-dashboard-reference.md)
- [Security hardening](security_hardening.md)
