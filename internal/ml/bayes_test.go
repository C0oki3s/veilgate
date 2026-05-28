package ml

import (
	"fmt"
	"sync"
	"testing"
)

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

func TestBayesCapEvictsOnOverflow(t *testing.T) {
	// Use a very small cap to exercise eviction without MaxBayesEntries overhead.
	// We insert cap+1 distinct buckets; totalEntries must stay <= cap.
	const cap = 10
	b := NewBayes(1.0)

	// Flood cap+5 distinct buckets all under the same feature.
	for i := 0; i < cap+5; i++ {
		v := Vec{Categorical: []Feature{{Name: "path", Bucket: fmt.Sprintf("bucket-%d", i)}}}
		b.Update(v, "agent")
	}
	b.mu.RLock()
	te := b.totalEntries
	b.mu.RUnlock()

	// We can't override MaxBayesEntries from outside the package (it's a
	// package-level constant), so with MaxBayesEntries=100_000 the cap won't
	// trigger at 15 entries. Instead, assert totalEntries == 15 (all stored)
	// and verify the eviction path with an internal white-box call.
	if te != cap+5 {
		t.Fatalf("totalEntries = %d, want %d", te, cap+5)
	}

	// White-box: manually drive totalEntries above MaxBayesEntries and call
	// evictLowest to verify it decrements correctly and removes a bucket.
	b.mu.Lock()
	b.totalEntries = MaxBayesEntries + 1
	beforeFeat := len(b.counts["path"])
	b.evictLowest()
	afterFeat := len(b.counts["path"])
	afterEntries := b.totalEntries
	b.mu.Unlock()

	if afterEntries != MaxBayesEntries {
		t.Fatalf("after eviction totalEntries=%d, want %d", afterEntries, MaxBayesEntries)
	}
	if afterFeat != beforeFeat-1 {
		t.Fatalf("after eviction bucket count=%d, want %d", afterFeat, beforeFeat-1)
	}
}

func TestBayesCapAdversarialUUIDFlood(t *testing.T) {
	// Simulate adversarial traffic: inject MaxBayesEntries*2 distinct high-
	// cardinality path buckets. totalEntries must never exceed MaxBayesEntries.
	b := NewBayes(1.0)
	for i := 0; i < MaxBayesEntries*2; i++ {
		// Every bucket is distinct (simulating UUID paths).
		v := Vec{Categorical: []Feature{{Name: "path", Bucket: fmt.Sprintf("uuid-%d", i)}}}
		b.Update(v, "agent")
	}
	b.mu.RLock()
	te := b.totalEntries
	b.mu.RUnlock()
	if te > MaxBayesEntries {
		t.Fatalf("totalEntries %d exceeded MaxBayesEntries %d", te, MaxBayesEntries)
	}
}

func TestBayesCapConcurrentFlood(t *testing.T) {
	b := NewBayes(1.0)
	const workers = 8
	const perWorker = 5000
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				bucket := fmt.Sprintf("w%d-uuid-%d", w, i)
				v := Vec{Categorical: []Feature{{Name: "path", Bucket: bucket}}}
				b.Update(v, "agent")
			}
		}()
	}
	wg.Wait()
	b.mu.RLock()
	te := b.totalEntries
	b.mu.RUnlock()
	if te > MaxBayesEntries {
		t.Fatalf("concurrent flood: totalEntries %d exceeded cap %d", te, MaxBayesEntries)
	}
}

func TestBayesSeedTracksEntries(t *testing.T) {
	b := NewBayes(1.0)
	b.Seed("ua", "curl", 5, 0)
	b.Seed("ua", "wget", 3, 2)
	b.mu.RLock()
	te := b.totalEntries
	b.mu.RUnlock()
	if te != 2 {
		t.Fatalf("Seed: totalEntries=%d, want 2", te)
	}
	// Seeding same bucket again must not double-count.
	b.Seed("ua", "curl", 1, 0)
	b.mu.RLock()
	te = b.totalEntries
	b.mu.RUnlock()
	if te != 2 {
		t.Fatalf("Seed repeat: totalEntries=%d, want still 2", te)
	}
}
