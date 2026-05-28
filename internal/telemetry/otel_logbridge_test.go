package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// memExporter captures exported log records for assertion.
type memExporter struct {
	mu      sync.Mutex
	records []sdklog.Record
}

func (e *memExporter) Export(_ context.Context, recs []sdklog.Record) error {
	e.mu.Lock()
	e.records = append(e.records, recs...)
	e.mu.Unlock()
	return nil
}
func (e *memExporter) Shutdown(context.Context) error  { return nil }
func (e *memExporter) ForceFlush(context.Context) error { return nil }

func (e *memExporter) drain() []sdklog.Record {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]sdklog.Record(nil), e.records...)
	e.records = e.records[:0]
	return out
}

// newTestProvider wires a provider that uses exp as its exporter and installs
// it as the global so OTelLogWriter.Write() picks it up.
func newTestProvider(t *testing.T, exp *memExporter) {
	t.Helper()
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exp)),
	)
	global.SetLoggerProvider(lp)
	t.Cleanup(func() { lp.Shutdown(context.Background()) })
}

// zerologJSON produces a single JSON line from zerolog at the given level.
func zerologJSON(level string) []byte {
	var buf bytes.Buffer
	log := zerolog.New(&buf)
	switch level {
	case "trace": log.Trace().Msg("test")
	case "debug": log.Debug().Msg("test")
	case "info":  log.Info().Msg("test")
	case "warn":  log.Warn().Msg("test")
	case "error": log.Error().Msg("test")
	case "fatal":
		// zerolog Fatal calls os.Exit — build the JSON manually instead.
		b, _ := json.Marshal(map[string]string{"level": "fatal", "message": "test"})
		return b
	}
	return buf.Bytes()
}

// ── tests ─────────────────────────────────────────────────────────────────────

func TestZerologLevelToOTel(t *testing.T) {
	cases := []struct {
		input string
		want  otellog.Severity
	}{
		{"trace", otellog.SeverityTrace},
		{"debug", otellog.SeverityDebug},
		{"info",  otellog.SeverityInfo},
		{"warn",  otellog.SeverityWarn},
		{"error", otellog.SeverityError},
		{"fatal", otellog.SeverityFatal},
		{"panic", otellog.SeverityFatal},
		{"",      otellog.SeverityUndefined},
	}
	for _, tc := range cases {
		got := zerologLevelToOTel(tc.input)
		if got != tc.want {
			t.Errorf("input=%q: got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestOTelLogBridgeSeverity(t *testing.T) {
	exp := &memExporter{}
	newTestProvider(t, exp)

	bridge := NewOTelLogWriter()

	cases := []struct {
		level    string
		wantSev  otellog.Severity
		wantText string
	}{
		{"info",  otellog.SeverityInfo,  "info"},
		{"warn",  otellog.SeverityWarn,  "warn"},
		{"error", otellog.SeverityError, "error"},
		{"debug", otellog.SeverityDebug, "debug"},
		{"fatal", otellog.SeverityFatal, "fatal"},
	}

	for _, tc := range cases {
		exp.drain()
		if _, err := bridge.Write(zerologJSON(tc.level)); err != nil {
			t.Fatalf("level=%s: Write error: %v", tc.level, err)
		}
		recs := exp.drain()
		if len(recs) == 0 {
			t.Errorf("level=%s: no OTel record emitted", tc.level)
			continue
		}
		r := recs[0]
		if r.Severity() != tc.wantSev {
			t.Errorf("level=%s: severity got %v, want %v", tc.level, r.Severity(), tc.wantSev)
		}
		if r.SeverityText() != tc.wantText {
			t.Errorf("level=%s: severity_text got %q, want %q", tc.level, r.SeverityText(), tc.wantText)
		}
	}
}

// TestOTelLogBridgeRequestFlow simulates the exact path a tarpitted request
// takes: zerolog.Error() → OTelLogWriter → OTel record with SeverityError.
func TestOTelLogBridgeRequestFlow(t *testing.T) {
	exp := &memExporter{}
	newTestProvider(t, exp)

	bridge := NewOTelLogWriter()

	var buf bytes.Buffer
	log := zerolog.New(&buf)

	// Simulate what requestLog(log, DecisionTarpit) emits.
	log.Error().
		Str("decision", "tarpit").
		Str("threat_level", "critical").
		Int("score", 90).
		Msg("request")

	bridge.Write(buf.Bytes())

	recs := exp.drain()
	if len(recs) == 0 {
		t.Fatal("no OTel record for simulated tarpit request")
	}
	r := recs[0]
	if r.Severity() != otellog.SeverityError {
		t.Errorf("tarpit request: expected SeverityError, got %v", r.Severity())
	}
	if r.SeverityText() != "error" {
		t.Errorf("tarpit request: expected severity_text=error, got %q", r.SeverityText())
	}

	// Verify the body is the message string.
	body := r.Body().AsString()
	if body != "request" {
		t.Errorf("expected body=request, got %q", body)
	}

	// Verify decision attribute is present.
	found := false
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == "decision" && kv.Value.AsString() == "tarpit" {
			found = true
		}
		return true
	})
	if !found {
		t.Error("decision=tarpit attribute not found in OTel record")
	}
}
