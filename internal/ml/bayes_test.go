package ml

import "testing"

func TestBayesPosteriorOnUntrainedReturnsHalf(t *testing.T) {
	b := NewBayes(1.0)
	v := Vec{Categorical: []Feature{{Name: "ua", Bucket: "curl"}}}
	if got := b.Posterior(v); got != 0.5 {
		t.Fatalf("untrained posterior = %v, want 0.5", got)
	}
}

func TestBayesSeparatesClassesAfterTraining(t *testing.T) {
	b := NewBayes(1.0)
	agent := Vec{Categorical: []Feature{
		{Name: "ua", Bucket: "python-requests"},
		{Name: "method", Bucket: "GET"},
	}}
	human := Vec{Categorical: []Feature{
		{Name: "ua", Bucket: "mozilla"},
		{Name: "method", Bucket: "GET"},
	}}
	for i := 0; i < 100; i++ {
		b.Update(agent, "agent")
		b.Update(human, "human")
	}
	if p := b.Posterior(agent); p < 0.9 {
		t.Fatalf("agent-like vector posterior %v < 0.9", p)
	}
	if p := b.Posterior(human); p > 0.1 {
		t.Fatalf("human-like vector posterior %v > 0.1", p)
	}
}

func TestBayesIgnoresUnknownLabels(t *testing.T) {
	b := NewBayes(1.0)
	v := Vec{Categorical: []Feature{{Name: "ua", Bucket: "x"}}}
	b.Update(v, "maybe")
	if b.Seen() != 0 {
		t.Fatalf("Seen=%d, expected unknown label to be dropped", b.Seen())
	}
}

func TestBayesFeatureAgentProbSupport(t *testing.T) {
	b := NewBayes(1.0)
	v := Vec{Categorical: []Feature{{Name: "ua", Bucket: "scanner"}}}
	for i := 0; i < 10; i++ {
		b.Update(v, "agent")
	}
	p, s := b.FeatureAgentProb("ua", "scanner")
	if s != 10 {
		t.Fatalf("support=%d, want 10", s)
	}
	if p < 0.9 {
		t.Fatalf("feature posterior %v, want >=0.9", p)
	}
	if _, zero := b.FeatureAgentProb("ua", "unseen"); zero != 0 {
		t.Fatalf("unseen bucket should have zero support, got %d", zero)
	}
}
