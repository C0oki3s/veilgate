package ml

import (
	"testing"

	"github.com/C0oki3s/veilgate/internal/rules"
)

func baseMLConfig() *rules.ML {
	m := &rules.ML{
		Enabled:        true,
		ScoreMaxPoints: 40,
		Alpha:          0.7,
		BurnInEvents:   0,
	}
	m.Bayes.LaplaceSmoothing = 1.0
	return m
}

func TestScorerZeroWhenDisabled(t *testing.T) {
	cfg := baseMLConfig()
	cfg.Enabled = false
	s := NewScorer(rules.NewHolder(cfg))
	r := s.Score(Vec{Categorical: []Feature{{Name: "ua", Bucket: "x"}}})
	if r.Points != 0 || r.Fired {
		t.Fatalf("disabled scorer fired: %+v", r)
	}
}

func TestScorerBurnInSuppressesScore(t *testing.T) {
	cfg := baseMLConfig()
	cfg.BurnInEvents = 10
	s := NewScorer(rules.NewHolder(cfg))
	agent := Vec{Categorical: []Feature{{Name: "ua", Bucket: "bot"}}}
	// Feed fewer than burn-in agent observations.
	for i := 0; i < 5; i++ {
		s.Observe(agent, 80, 40)
	}
	r := s.Score(agent)
	if r.Fired {
		t.Fatalf("scorer fired during burn-in: %+v", r)
	}
}

func TestScorerFiresAfterTraining(t *testing.T) {
	cfg := baseMLConfig()
	s := NewScorer(rules.NewHolder(cfg))
	agent := Vec{Categorical: []Feature{{Name: "ua", Bucket: "bot"}}, Numeric: []float64{5, 1, 0, 4}}
	human := Vec{Categorical: []Feature{{Name: "ua", Bucket: "browser"}}, Numeric: []float64{1, 0, 1, 30}}
	for i := 0; i < 60; i++ {
		s.Observe(agent, 80, 40)
		s.Observe(human, 0, 40)
	}
	r := s.Score(agent)
	if !r.Fired {
		t.Fatalf("scorer did not fire on trained agent-like vector: %+v", r)
	}
	if r.Points > cfg.ScoreMaxPoints {
		t.Fatalf("Points=%d exceeds ScoreMaxPoints=%d", r.Points, cfg.ScoreMaxPoints)
	}
}

func TestScorerObserveAbstainsInMiddle(t *testing.T) {
	cfg := baseMLConfig()
	s := NewScorer(rules.NewHolder(cfg))
	v := Vec{Categorical: []Feature{{Name: "ua", Bucket: "x"}}}
	// Score between 0 and threshold — should not train.
	s.Observe(v, 20, 40)
	if s.Observed() != 0 {
		t.Fatalf("Observe trained on abstain-range sample")
	}
}

// Regression for the 33-34% false-positive on real browsers. A trained
// classifier must NOT score an unseen feature combination — Bayes
// returns Posterior≈0.5 ("no information") for unseen buckets, and
// anomaly is 0 before the forest fits. The old formula treated 0.5 as
// "half-agent" and emitted ~14 points; the new one rescales so the
// neutral-midpoint contributes zero, and the min_confidence_to_fire
// gate keeps sub-threshold combined scores silent.
func TestScorerNoFalsePositiveOnUnseenFeatures(t *testing.T) {
	cfg := baseMLConfig()
	s := NewScorer(rules.NewHolder(cfg))
	// Train on a known agent bucket + a known human bucket; neither
	// touches the bucket we score with.
	agentTrain := Vec{Categorical: []Feature{{Name: "ua", Bucket: "bot"}}}
	humanTrain := Vec{Categorical: []Feature{{Name: "ua", Bucket: "browser"}}}
	for i := 0; i < 50; i++ {
		s.Observe(agentTrain, 80, 40)
		s.Observe(humanTrain, 0, 40)
	}
	// Score a never-before-seen bucket — the "legit user on a fresh
	// session" case that was producing 34% before the fix.
	unseen := Vec{Categorical: []Feature{{Name: "ua", Bucket: "unseen-firefox"}}}
	r := s.Score(unseen)
	if r.Fired || r.Points > 0 {
		t.Fatalf("unseen-feature vector fired: Points=%d Posterior=%.3f (want Points=0)",
			r.Points, r.PosteriorAgent)
	}
	// The posterior itself should be near 0.5 — sanity check that the
	// test is exercising the right code path.
	if r.PosteriorAgent < 0.4 || r.PosteriorAgent > 0.6 {
		t.Fatalf("Posterior=%.3f outside [0.4, 0.6] — test no longer exercises the neutral-midpoint case",
			r.PosteriorAgent)
	}
}

// Explicit coverage for the min_confidence_to_fire floor: a weak
// agent-leaning signal (combined just under the floor) must stay
// silent. Without the floor, tiny posteriors accumulated a few points
// per request and combined with other detectors into the 33-34% FP.
func TestScorerMinConfidenceFloor(t *testing.T) {
	cfg := baseMLConfig()
	cfg.MinConfidenceToFire = 0.5 // very high floor — suppress almost everything
	s := NewScorer(rules.NewHolder(cfg))
	agent := Vec{Categorical: []Feature{{Name: "ua", Bucket: "bot"}}}
	human := Vec{Categorical: []Feature{{Name: "ua", Bucket: "browser"}}}
	// Train unbalanced so Bayes leans weakly toward agent on "bot".
	for i := 0; i < 20; i++ {
		s.Observe(agent, 80, 40)
	}
	for i := 0; i < 5; i++ {
		s.Observe(human, 0, 40)
	}
	r := s.Score(agent)
	// Even on the trained agent bucket, the floor should gate weak
	// combined scores. Posterior will be high here, so this only
	// proves the floor runs — it's the unseen-case test above that
	// locks in the browser FP fix.
	if r.Fired && r.Points < int(0.5*float64(cfg.ScoreMaxPoints)) {
		t.Fatalf("min_confidence_to_fire floor leaked weak signal: Points=%d (want 0 or ≥%d)",
			r.Points, int(0.5*float64(cfg.ScoreMaxPoints)))
	}
}
