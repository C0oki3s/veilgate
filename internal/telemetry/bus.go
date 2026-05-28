package telemetry

import "context"

// EventKind discriminates the five event types dispatched through Bus.
type EventKind uint8

const (
	KindRequest   EventKind = iota // proxy hot path, once per scored request
	KindTarpit                     // tarpit handler, once per tarpit response
	KindChallenge                  // challenge lifecycle: issued / solved / failed
	KindMLFit                      // isolation forest refit lifecycle
	KindPeriodic                   // 30 s cardinality/gauge snapshot
)

// SignalDetail carries per-signal data from the scoring result.
type SignalDetail struct {
	Name   string
	Points int
	Reason string
}

// RequestEvent is emitted once per request after RequestDuration is observed.
// Every field needed to reconstruct all per-request Prometheus metrics is present.
type RequestEvent struct {
	Decision    string
	Score       int
	Path        string
	Method      string
	ClientIP    string
	UserAgent   string
	DurationSec float64
	Signals     []SignalDetail

	// Pre-computed per-signal derived fields so OTelSink needs no re-derivation.
	IPRepCategory   string // from ip_reputation signal: tor_exit/cloud/anonymizer/rfc1918_leak
	ToolFamily      string // from suspicious_ua signal: sqlmap/nikto/nuclei/...
	FleetTier       string // from ip_rotation_fleet signal: high/mid/low
	PubIPRotCat     string // from ClassifyIP() when public fleet rotation fires

	IsPublicIP      bool
	IsFleetRotating bool
}

// TarpitEvent is emitted at the end of tarpit.Handler.ServeHTTP.
type TarpitEvent struct {
	DelayMs     int64
	BytesServed int
	ContentType string  // "json" | "html" | "graphql" | "text" | "other"
	CostUSD     float64
}

// ChallengeEvent is emitted at each challenge lifecycle point.
type ChallengeEvent struct {
	Action     string // "issued" | "solved" | "failed"
	Form       string // "html" | "spa" | ""
	FailReason string // "bad_request" | "unauthorized" | ""
}

// MLFitEvent is emitted by the isoforest.refit goroutine for every refit
// attempt, whether it runs or is skipped.
type MLFitEvent struct {
	Status      string  // "ok" | "skipped_busy" | "skipped_cold" | "skipped_disabled"
	DurationSec float64 // non-zero only when Status == "ok"
	Rows        int     // non-zero only when Status == "ok"
	BayesObs    int64   // non-zero only when Status == "ok"
}

// PeriodicEvent is emitted by the cardinality.gauges 30 s ticker.
type PeriodicEvent struct {
	TrackedClients      int
	FleetFingerprints   int
	FleetFingerprintIPs []int // distinct-IP count per fingerprint
	PersistQueueDepth   int
	PersistDroppedDelta int64
	MLBayesEntries      int
}

// Event is the discriminated union dispatched through Bus. Only the field
// matching Kind is populated; the rest are zero values.
type Event struct {
	Kind      EventKind
	Request   RequestEvent
	Tarpit    TarpitEvent
	Challenge ChallengeEvent
	MLFit     MLFitEvent
	Periodic  PeriodicEvent
}

// Sink receives every event dispatched by Bus. Implementations switch on
// Event.Kind and read the matching embedded struct.
type Sink interface {
	OnEvent(Event)
}

// Bus is a non-blocking async dispatcher: Emit enqueues without blocking the
// hot path; a background goroutine fans the event out to all registered sinks.
// If the channel is full the event is silently dropped rather than stalling
// the reverse proxy — same pattern as LiteLLM's async callback queue.
type Bus struct {
	ch    chan Event
	sinks []Sink
}

// DefaultBus is the global dispatcher. Always non-nil; sinks are only
// attached when telemetry.metrics_push is enabled, so Emit is safe to call
// regardless of config.
var DefaultBus = newBus(512)

func newBus(bufSize int) *Bus {
	b := &Bus{ch: make(chan Event, bufSize)}
	go b.drain()
	return b
}

// Register adds a sink. Must be called before the first Emit (i.e. from
// InitTelemetry during startup). Not goroutine-safe after first Emit.
func (b *Bus) Register(s Sink) {
	b.sinks = append(b.sinks, s)
}

// Emit queues an event for async fan-out. Never blocks — drops if full.
func (b *Bus) Emit(e Event) {
	if len(b.sinks) == 0 {
		return
	}
	select {
	case b.ch <- e:
	default:
	}
}

// Shutdown drains remaining events and stops the background goroutine.
func (b *Bus) Shutdown(ctx context.Context) {
	close(b.ch)
}

func (b *Bus) drain() {
	for e := range b.ch {
		for _, s := range b.sinks {
			s.OnEvent(e)
		}
	}
}
