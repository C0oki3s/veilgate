# `rules/dashboard.yaml`

Syntax:  dashboard configuration  
Default: embedded `dashboard.yaml`  
Context: `rules_dir`

The `dashboard.yaml` file controls the built-in metrics dashboard: refresh
cadence, event retention in memory, color palette, stat cards, quick-search
tags, graph definitions, and score thresholds used for table highlighting.

Dashboard rules affect visibility only. They do not change request scoring or
enforcement.

## Example

```yaml
refresh_seconds: 10
max_events: 200
max_history_points: 60
page_reload_seconds: 60
chartjs_cdn: "https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"

score_thresholds:
  high: 70
  medium: 40
```

## Fields

| Field | Type | Purpose |
| --- | --- | --- |
| `refresh_seconds` | int | Client-side auto-refresh interval. |
| `max_events` | int | Maximum recent events held in the dashboard ring buffer. |
| `max_history_points` | int | Rolling history size for time-series charts. |
| `page_reload_seconds` | int | Full page/event refresh cadence. |
| `chartjs_cdn` | string | Chart.js script URL; use a local file for air-gapped deployments. |
| `colours` | map | CSS color palette consumed by dashboard rendering. |
| `stat_cards` | list | Summary metric cards shown at the top. |
| `ip_rotation` | object | IP rotation detection panel configuration. |
| `public_ip_rotation` | object | Public IP rotation panel configuration. |
| `cardinality` | object | Metric names for client/fingerprint cardinality gauges. |
| `search_tags` | list | PromQL shortcut tags. |
| `graphs` | list | Chart definitions. |
| `score_thresholds` | object | High and medium score bands for event-table highlighting. |

## Code Path

- [`internal/rules/extra_loaders.go`](../../../internal/rules/extra_loaders.go)
- [`internal/telemetry/dashboard.go`](../../../internal/telemetry/dashboard.go)
- [`cmd/veilgate/main.go`](../../../cmd/veilgate/main.go)

## Operational Notes

- The file hot-reloads through the rules watcher.
- Bind `metrics.listen` to localhost or a private network. The dashboard is
  unauthenticated in the current codebase.
- In air-gapped deployments, point `chartjs_cdn` at a local static asset.
- Metric names must match metrics emitted by `internal/telemetry`.

## Validation

```bash
curl -i http://127.0.0.1:9090/
curl -sS http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

## Related

- [`metrics:`](../metrics.md)
- [Module veilgate_metrics](../../modules/veilgate_metrics.md)
- [Operations](../../operations/README.md)
