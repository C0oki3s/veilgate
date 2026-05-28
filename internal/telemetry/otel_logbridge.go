package telemetry

import (
	"context"
	"encoding/json"
	"io"
	"time"

	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
)

// OTelLogWriter is an io.Writer that intercepts zerolog JSON output and
// forwards each line to the global OTel LoggerProvider as a structured
// LogRecord. It is meant to be used as a multi-writer alongside os.Stderr
// so logs always appear on the console AND flow to the remote collector.
//
// Usage in main:
//
//	w := io.MultiWriter(os.Stderr, telemetry.NewOTelLogWriter())
//	log := zerolog.New(zerolog.ConsoleWriter{Out: w, ...})
type OTelLogWriter struct{}

// NewOTelLogWriter returns a writer that forwards zerolog JSON lines to
// the global OTel LoggerProvider. If no LoggerProvider is installed
// (logs disabled in config) each Write is a no-op.
func NewOTelLogWriter() io.Writer { return &OTelLogWriter{} }

// Write implements io.Writer. Each call is expected to be exactly one
// complete JSON log line as produced by zerolog.
func (w *OTelLogWriter) Write(p []byte) (int, error) {
	// Parse the JSON line zerolog produces.
	var fields map[string]interface{}
	if err := json.Unmarshal(p, &fields); err != nil {
		// Not valid JSON (e.g. console writer output) — skip silently.
		return len(p), nil
	}

	var rec otellog.Record
	rec.SetTimestamp(time.Now())
	rec.SetObservedTimestamp(time.Now())

	// Map zerolog severity levels to OTel SeverityNumber.
	if lvl, ok := fields["level"].(string); ok {
		rec.SetSeverity(zerologLevelToOTel(lvl))
		rec.SetSeverityText(lvl)
	}

	// The log message.
	if msg, ok := fields["message"].(string); ok {
		rec.SetBody(otellog.StringValue(msg))
	}

	// All other fields become key/value attributes.
	attrs := make([]otellog.KeyValue, 0, len(fields))
	for k, v := range fields {
		switch k {
		case "level", "message", "time":
			continue
		}
		attrs = append(attrs, otellog.String(k, jsonValueToString(v)))
	}
	rec.AddAttributes(attrs...)

	global.Logger(tracerName).Emit(context.Background(), rec)
	return len(p), nil
}

func zerologLevelToOTel(level string) otellog.Severity {
	switch level {
	case "trace":
		return otellog.SeverityTrace
	case "debug":
		return otellog.SeverityDebug
	case "info":
		return otellog.SeverityInfo
	case "warn":
		return otellog.SeverityWarn
	case "error":
		return otellog.SeverityError
	case "fatal", "panic":
		return otellog.SeverityFatal
	default:
		return otellog.SeverityUndefined
	}
}

func jsonValueToString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		b, _ := json.Marshal(t)
		return string(b)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
