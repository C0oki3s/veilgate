# How-to: Install Community Rules

This guide covers installing, updating, and managing community detection rules
from the [veilgate-rules](https://github.com/C0oki3s/veilgate-rules) repository.

Community rules follow the same YAML schema as VeilGate's embedded defaults.
They are maintained by the open-source community and versioned as GitHub
releases. This is analogous to how Nuclei templates are distributed — rules
are managed independently from the engine binary, versioned with semantic
tags, and can be updated without recompiling or restarting VeilGate.

## Prerequisites

- `veilgate` binary with the `update-rules` subcommand.
- Outbound HTTPS access to `api.github.com` and `objects.githubusercontent.com`
  from the machine running `update-rules`.
- A configured `rules_dir` in `veilgate.yaml` (or pass `--dir` explicitly).

## Install the Latest Rules

```bash
# Install into the rules_dir configured in veilgate.yaml
veilgate update-rules --config configs/veilgate.yaml

# Or specify the directory directly (default: ~/.veilgate/rules)
veilgate update-rules --dir ~/.veilgate/rules
```

Output:

```
update-rules: downloading veilgate-rules @ v1.2.0
  detector.yaml                     → /etc/veilgate/rules
  ip_reputation.yaml                → /etc/veilgate/rules
  tls_fingerprints.yaml             → /etc/veilgate/rules
  templates.yaml                    → /etc/veilgate/rules
  injection_strategy.yaml           → /etc/veilgate/rules
  payloads.yaml                     → /etc/veilgate/rules
  fake_data.yaml                    → /etc/veilgate/rules
  challenge.yaml                    → /etc/veilgate/rules
  vulnerabilities.yaml              → /etc/veilgate/rules
update-rules: installed 9 YAML files → /etc/veilgate/rules (version v1.2.0)
update-rules: rules are hot-reloaded automatically when rules_dir is set
             restart veilgate to pick up changes to non-hot-reloadable files (payloads.yaml)
```

## Pin a Specific Version

```bash
veilgate update-rules --dir ~/.veilgate/rules --version v1.2.0
```

## List Available Releases

```bash
veilgate update-rules --list

Available releases for C0oki3s/veilgate-rules:

  v1.2.0            Community rules Jan 2026
  v1.1.0            Community rules Oct 2025
  v1.0.0            Initial community release
```

The default directory when no `--dir` flag and no `rules_dir` in config is `~/.veilgate/rules`.

## Dry-Run / Check Installed Version

Check what is currently installed:

```bash
cat ~/.veilgate/rules/.rules-version.json
```

```json
{
  "version": "v1.2.0",
  "installed_at": "2026-01-15T10:30:00Z",
  "source": "https://github.com/C0oki3s/veilgate-rules/releases/tag/v1.2.0",
  "file_count": 9
}
```

## How Hot-Reload Works After Update

Most rule files are hot-reloaded automatically when `rules_dir` is set.
After `update-rules` writes new YAML files, VeilGate's `fsnotify` watcher
detects the changes within ~500ms and applies them without a restart.

**Hot-reloaded after update** (no restart required):
- `detector.yaml`
- `ip_reputation.yaml`
- `tls_fingerprints.yaml`
- `templates.yaml`
- `injection_strategy.yaml`
- `fake_data.yaml`
- `vulnerabilities.yaml`
- `challenge.yaml`
- `ml.yaml`
- `dashboard.yaml`

**Requires restart**:
- `payloads.yaml` — loaded once at startup by `payloads.NewLibraryFromDir()`.

```bash
# After update-rules, restart only if payloads.yaml changed
veilgate -config configs/veilgate.yaml  # or: systemctl restart veilgate
```

## Automate with Cron

```cron
# Update community rules every night at 2am
0 2 * * * /usr/local/bin/veilgate update-rules --dir ~/.veilgate/rules
```

> Note: the HUP signal is not yet wired for rules reload in the current release.
> The cron entry above is shown for future compatibility. Currently, file-watcher
> hot-reload is triggered automatically by the file writes.

## CI / GitOps Workflow

For environments where all configuration is version-controlled:

```yaml
# .github/workflows/update-veilgate-rules.yml
name: Update VeilGate Community Rules
on:
  schedule:
    - cron: "0 6 * * 1"   # Every Monday at 06:00 UTC
  workflow_dispatch:

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download latest rules
        run: |
          curl -sL https://github.com/C0oki3s/veilgate-rules/releases/latest/download/rules.zip \
            -o /tmp/rules.zip
          unzip -o /tmp/rules.zip -d rules/

      - name: Open PR with updated rules
        uses: peter-evans/create-pull-request@v6
        with:
          title: "chore: update veilgate community rules"
          branch: "update-veilgate-rules"
          commit-message: "chore: update veilgate community rules"
```

## Security Notes

- `update-rules` validates that all download URLs point to `github.com` or
  `*.githubusercontent.com` before making requests. It will not follow
  redirects to arbitrary hosts.
- The archive is extracted with path traversal protection: entries containing
  `..` or absolute paths are rejected.
- Each extracted file is size-capped at 10 MB; the total archive is capped at
  50 MB.
- Existing files are backed up as `.bak` before overwrite (unless `--no-backup`).
- Treat installed rule files as security policy. Review changes before
  deploying to production, especially `detector.yaml` and `ip_reputation.yaml`.

## Rollback

If updated rules cause unexpected behavior (false positives, false negatives),
restore the previous version from backups:

```bash
# Restore all .bak files
for f in ~/.veilgate/rules/*.bak; do
  mv "$f" "${f%.bak}"
done
# Hot-reload picks up the restored files automatically
```

Or reinstall a specific version:

```bash
veilgate update-rules --dir ~/.veilgate/rules --version v1.1.0
```

## Related

- [Module veilgate_rules](../modules/veilgate_rules.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)
- [How-to: promote learned rules](promote-learned-rules.md)
- [Community rules repository](https://github.com/C0oki3s/veilgate-rules)
