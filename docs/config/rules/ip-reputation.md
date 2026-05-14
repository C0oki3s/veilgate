# `rules/ip_reputation.yaml`

> **File:** `/etc/veilgate/rules/ip_reputation.yaml` &nbsp;·&nbsp;
> **Reload:** hot-reload (~500 ms).
>
> Three things in one file: CIDR-based IP categorisation,
> fleet-rotation detection thresholds, and User-Agent rotation
> thresholds.

**On this page:**

- [`categories:`](#categories)
- [`private_cidrs:`](#private_cidrs)
- [`fleet_rotation:`](#fleet_rotation)
- [`ua_rotation:`](#ua_rotation)
- [Example](#example)
- [Related](#related)

## `categories:`

A list of (CIDR, category, points) tuples. When a request's resolved
client IP falls inside a category's CIDR, the `ip_reputation` signal
fires for the configured points.

```yaml
categories:
  - name: tor
    points: 25
    cidrs:
      - 5.61.55.0/24
      - 23.129.64.0/24
      - 51.81.93.0/24
      # …Tor exit-node list…
  - name: cloud
    points: 12
    cidrs:
      - 3.0.0.0/9            # AWS
      - 13.32.0.0/15
      - 35.180.0.0/16        # GCP
      - 40.64.0.0/10         # Azure
  - name: vpn
    points: 18
    cidrs:
      - 31.13.64.0/19
      # …commercial VPN ranges…
  - name: anonymizer
    points: 30
    cidrs:
      - 185.220.100.0/22
      # …I2P / proxy fleets…
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `name` | string | yes | category label; appears in metric labels and signal reasons |
| `points` | int | yes | added to the request score on a match |
| `cidrs` | list of CIDR strings | yes | IPv4 and IPv6 both accepted |

> **Maintenance.** The shipped defaults are conservative starting
> points. CIDR membership churns. Treat the category lists as data
> you keep in sync from an external feed (Tor exit list, AWS IP
> ranges JSON, etc.) rather than something you maintain by hand.

## `private_cidrs:`

Ranges that should be considered "private" rather than scoring as a
public-IP category. The proxy uses this to decide whether a client is
a real internet client or an internal machine.

```yaml
private_cidrs:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16
  - 100.64.0.0/10        # CGN
  - 169.254.0.0/16
  - fc00::/7
  - fe80::/10
```

The `IsPublicIP` check is what gates the
`veilgate_public_ip_requests` metric and the public-IP-rotation
panel on the dashboard.

## `fleet_rotation:`

Detects one attacker rotating through a pool of IPs. The fleet
tracker groups requests by a behavioural fingerprint
(UA family + JA4 prefix + header set + method) and counts distinct
IPs per fingerprint inside a rolling window.

| Key | Type | Default |
| --- | --- | --- |
| `enabled` | bool | `true` |
| `window_seconds` | int | `600` |
| `max_fingerprints` | int | `20000` |
| `tiers` | list of `{distinct_ips: int, points: int}`, descending | see below |

```yaml
fleet_rotation:
  enabled: true
  window_seconds: 600
  max_fingerprints: 20000
  tiers:
    - distinct_ips: 50
      points: 45
    - distinct_ips: 15
      points: 30
    - distinct_ips: 5
      points: 18
```

A request is tagged with `ip_rotation_fleet` and the points of the
first matching tier. A score of 45 is one of the highest single-signal
contributions in the system — fleet rotation is near-perfect proof of
malicious intent.

`max_fingerprints` is a soft cap on the tracker's memory use. When the
map outgrows the cap, idle entries are evicted before adding new ones.

## `ua_rotation:`

Catches one client cycling through many User-Agent strings. The
canonical pattern is `dirsearch -H` or `ffuf` with a UA pool while the
IP stays constant.

| Key | Type | Default |
| --- | --- | --- |
| `enabled` | bool | `true` |
| `distinct_uas_for_fire` | int | `5` |
| `points` | int | `35` |

```yaml
ua_rotation:
  enabled: true
  distinct_uas_for_fire: 5
  points: 35
```

The window is the per-client-tracker window from
[`detector.window_seconds`](../detector.md#window_seconds).

## Example

```yaml
categories:
  - name: tor
    points: 25
    cidrs: [...tor exits...]
  - name: cloud
    points: 12
    cidrs: [...cloud ranges...]

private_cidrs:
  - 10.0.0.0/8
  - 172.16.0.0/12
  - 192.168.0.0/16

fleet_rotation:
  enabled: true
  window_seconds: 600
  max_fingerprints: 20000
  tiers:
    - distinct_ips: 50
      points: 45
    - distinct_ips: 15
      points: 30
    - distinct_ips: 5
      points: 18

ua_rotation:
  enabled: true
  distinct_uas_for_fire: 5
  points: 35
```

## Related

- [`detector.trusted_proxies`](../detector.md#trusted_proxies) — XFF
  resolution that determines the client identifier
- [`detector.window_seconds`](../detector.md#window_seconds) — rolling
  window for UA rotation
- [`rules/tls_fingerprints.yaml`](tls-fingerprints.md) — JA4 prefix
  feeds into the fleet fingerprint
- [Use case: API recon blocking](../../usecases/api-recon-blocking.md)

---

*Previous: [`rules/tls_fingerprints.yaml`](tls-fingerprints.md) · Next: [`rules/challenge.yaml`](challenge.md)*
