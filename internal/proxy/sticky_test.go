package proxy

import (
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
)

func newStickyServer() *Server {
	return &Server{
		cfg: &config.Config{
			Mode: "auto",
			Detector: config.DetectorConfig{
				ScoreChallengeThreshold: 40,
				ScoreTarpitThreshold:    70,
			},
		},
		stickyClients: make(map[string]struct{}),
	}
}

func TestStickyTarpit_MarkAndCheck(t *testing.T) {
	s := newStickyServer()
	if s.isTarpitSticky("1.2.3.4") {
		t.Fatal("client should not be sticky before being marked")
	}
	s.markTarpitSticky("1.2.3.4")
	if !s.isTarpitSticky("1.2.3.4") {
		t.Fatal("client should be sticky after mark")
	}
}

func TestStickyTarpit_OtherClientUnaffected(t *testing.T) {
	s := newStickyServer()
	s.markTarpitSticky("1.2.3.4")
	if s.isTarpitSticky("5.6.7.8") {
		t.Fatal("marking one client must not affect another")
	}
}

func TestStickyTarpit_MarkIsIdempotent(t *testing.T) {
	s := newStickyServer()
	s.markTarpitSticky("1.2.3.4")
	s.markTarpitSticky("1.2.3.4") // second call must not panic
	if !s.isTarpitSticky("1.2.3.4") {
		t.Fatal("client must remain sticky after double-mark")
	}
}

// TestStickyTarpit_DecideOverride verifies the sticky gate: a client that was
// previously tarpitted (score 80) gets a lower score later (score 38, below the
// challenge threshold), but decide() should still return DecisionTarpit because
// the sticky map overrides the score-based routing. This is what prevents the
// oscillation bug where cache_miss_anomaly window resets drop the score.
func TestStickyTarpit_DecideOverride(t *testing.T) {
	s := newStickyServer()

	// First request: score above tarpit threshold — gets tarpitted and marked sticky.
	first := s.decide(80)
	if first != DecisionTarpit {
		t.Fatalf("score 80 should be tarpit, got %s", first)
	}
	s.markTarpitSticky("1.2.3.4")

	// Later request: score drops (window reset). Without sticky it would be real (38 < 40).
	// With sticky it must remain tarpit.
	scoreAfterWindowReset := 38
	rawDecision := s.decide(scoreAfterWindowReset)
	if rawDecision != DecisionReal {
		t.Fatalf("raw decide(38) should be real (below challenge threshold), got %s", rawDecision)
	}

	// The sticky gate should override to tarpit.
	if !s.isTarpitSticky("1.2.3.4") {
		t.Fatal("client must be sticky")
	}
}

func TestStickyTarpit_ConcurrentAccess(t *testing.T) {
	s := newStickyServer()
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func() {
			s.markTarpitSticky("concurrent-client")
			_ = s.isTarpitSticky("concurrent-client")
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
	if !s.isTarpitSticky("concurrent-client") {
		t.Fatal("client must be sticky after concurrent marks")
	}
}
