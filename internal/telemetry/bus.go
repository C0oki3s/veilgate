package telemetry

import "context"

// RequestEvent carries the per-request data that every Sink receives.
// It mirrors what proxy.go already knows at the ObserveEndpoint call site.
type RequestEvent struct {
	Decision    string
	Score       int
	Path        string
	Method      string
	SignalNames []string
}

// Sink is the callback interface. Each backend (OTel, future webhooks, etc.)
// implements it independently — no shared state, no cross-dependency.
type Sink interface {
	OnRequest(RequestEvent)
}

// Bus is a non-blocking async dispatcher: Emit enqueues without blocking the
// hot path; a background goroutine fans the event out to all registered sinks.
// This mirrors LiteLLM's async callback queue — if the channel is full the
// event is silently dropped rather than stalling the reverse proxy.
type Bus struct {
	ch    chan RequestEvent
	sinks []Sink
}

// DefaultBus is the global dispatcher. It is always non-nil; sinks are only
// attached when telemetry.metrics_push is enabled, so Emit is always safe to
// call regardless of config.
var DefaultBus = newBus(512)

func newBus(bufSize int) *Bus {
	b := &Bus{ch: make(chan RequestEvent, bufSize)}
	go b.drain()
	return b
}

// Register adds a sink. Must be called before the first Emit (i.e. from
// InitTelemetry during startup). Not goroutine-safe after first Emit.
func (b *Bus) Register(s Sink) {
	b.sinks = append(b.sinks, s)
}

// Emit queues an event for async fan-out. Never blocks — drops if full.
func (b *Bus) Emit(e RequestEvent) {
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
			s.OnRequest(e)
		}
	}
}
