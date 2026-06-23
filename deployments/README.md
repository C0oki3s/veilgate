# Deployment Artifacts

The supported deployment artifact for now is Linux with systemd:

| Path | Purpose |
| --- | --- |
| `systemd/veilgate.service` | Hardened Linux service unit. |
| `systemd/veilgate-admin.service` | Hardened Linux service unit for the admin dashboard. |

Other deployment experiments may exist in local working trees, but they are
ignored by Git until the project is ready to support them publicly.

Read [docs/deployment/README.md](../docs/deployment/README.md) for the Linux
installation flow.

Read [docs/functionalities/admin-dashboard.md](../docs/functionalities/admin-dashboard.md)
for the admin dashboard startup flow, default ports, pages, and available
actions.
