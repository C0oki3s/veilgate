# Module veilgate_capture

The `veilgate_capture` module writes one JSONL record for each scored request.
It is useful for legacy pipelines, traffic review, and training-data export.
For normal operations, the SQLite persistence module is usually preferred
because it supports canaries, ML features, candidates, and audit rows.

Capture files can contain sensitive request metadata. Treat them like logs that
may include IP addresses, paths, user agents, headers, scores, and detector
signals.

## Example Configuration

```yaml
capture:
  enabled: false
  path: "./data/requests.jsonl"
  max_mb: 100
  retention_hours: 168
  janitor_every: "1h"
  file_mode: 0o600
  scrub:
    - regex: 'Bearer [A-Za-z0-9_\-\.]{20,}'
      replace: 'Bearer <REDACTED>'
```

## Directives

- `capture.enabled`
- `capture.path`
- `capture.max_mb`
- `capture.retention_hours`
- `capture.janitor_every`
- `capture.file_mode`
- `capture.scrub`

## `capture.enabled`

Syntax:  `enabled: true | false`  
Default: `false`  
Context: `capture`

Enables JSONL capture. When enabled, `cmd/veilgate/main.go` constructs a
`telemetry.Capture` writer and installs it into `internal/proxy.Server`.
`Server.serve()` writes one event after scoring each request.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) wires capture.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) writes capture events.
- [`internal/telemetry/capture.go`](../../internal/telemetry/capture.go) implements JSONL writing.

### Operational notes

- Prefer `persist.enabled: true` unless an external system requires JSONL.
- Capture is synchronous at the writer level and protected by a mutex.
- Captured data is sensitive and should not be world-readable.

### Validation

```bash
curl http://localhost:8080/
tail -n 1 ./data/requests.jsonl
```

## `capture.path`

Syntax:  `path: "<file>"`  
Default: none  
Context: `capture`

Sets the JSONL output path. If empty, capture construction returns nil and no
capture events are written.

When a path is set, parent directories are created with mode `0700` where the
platform supports POSIX permissions.

### Code path

- [`internal/telemetry/capture.go#L88`](../../internal/telemetry/capture.go#L88)

### Operational notes

- Put capture output on storage with enough capacity for traffic volume.
- Do not place capture files in a web-served directory.
- Rotate or prune captures according to your retention policy.

## `capture.max_mb`

Syntax:  `max_mb: <megabytes>`  
Default: `100`  
Context: `capture`

Sets the live file size limit. When the writer reaches the limit, it renames
the active file to `<path>.1` and opens a new live file.

### Code path

- [`internal/telemetry/capture.go`](../../internal/telemetry/capture.go)
- `Capture.Write()`
- `Capture.rotateLocked()`

### Operational notes

- Rotation is size-based and simple. Use external log shipping if you need a
  more complex rotation scheme.
- Rotated files inherit the configured file mode.

## `capture.retention_hours`

Syntax:  `retention_hours: <hours>`  
Default: `0`  
Context: `capture`

Enables time-based pruning. A retention value of `0` disables the janitor.
When enabled, the janitor deletes rotated capture files older than the
retention window and truncates the live file when it is older than the window.

### Code path

- [`internal/telemetry/capture.go`](../../internal/telemetry/capture.go)
- `Capture.RunJanitor()`
- `Capture.sweep()`

### Operational notes

- Set this for production captures.
- The active file is truncated in place to avoid fighting the writer.

## `capture.janitor_every`

Syntax:  `janitor_every: "<duration>"`  
Default: `1h` when retention is set and parsing yields zero  
Context: `capture`

Controls how often the capture janitor runs. The value is parsed with Go
duration syntax such as `"1h"` or `"30m"`.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go)
- [`internal/telemetry/capture.go`](../../internal/telemetry/capture.go)

## `capture.file_mode`

Syntax:  `file_mode: <octal-mode>`  
Default: `0o600`  
Context: `capture`

Controls permissions for new live and rotated capture files. Existing files are
chmodded on open and rotation.

### Code path

- [`internal/config/config.go`](../../internal/config/config.go)
- [`internal/telemetry/capture.go`](../../internal/telemetry/capture.go)

### Operational notes

- Keep the default unless another local service must read the file.
- If external log shipping needs read access, grant it through group
  membership and filesystem policy rather than making the file public.

## `capture.scrub`

Syntax:  `scrub: [{regex: "<pattern>", replace: "<value>"}]`  
Default: empty  
Context: `capture`

Applies regex replacements to each encoded JSONL line before the line is
written. Invalid regexes are skipped at compile time.

### Code path

- [`internal/telemetry/capture.go`](../../internal/telemetry/capture.go)
- `CompileScrubRules()`
- `Capture.Write()`

### Operational notes

- Scrubbing is best-effort and pattern-based.
- Anything not matched by a scrub rule may still land on disk.
- Review scrub rules with sample production-like traffic before relying on
  them for privacy controls.

## Captured Fields

Each line can include timestamp, client ID, method, path, user agent, referer,
Accept headers, Sec-Fetch data, JA3/JA4, score, signal names, and final
decision.

## Related

- [Module veilgate_persistence](veilgate_persistence.md)
- [Module veilgate_metrics](veilgate_metrics.md)
- [Module veilgate_detector](veilgate_detector.md)

