package ml

import (
	"math"
	"sync"

	"github.com/C0oki3s/veilgate/internal/telemetry"
)

// MaxBayesEntries is the hard ceiling on the number of distinct
// (feature, bucket) pairs stored in the histogram. Without a cap,
// adversarial traffic with high-cardinality path n-grams (e.g. random
// UUIDs in URLs) grows the map unboundedly. When the cap is hit the
// entry with the lowest total count (agent+human) is evicted — it is
// below the miner's min_support threshold anyway and would never be
// promoted.
const MaxBayesEntries = 100_000

// Bayes is a streaming multinomial Naive Bayes classifier with Laplace
// smoothing. We keep per-feature counts instead of per-(feature,class)
// so updates are O(|Vec.Categorical|) and Posterior is the same.
//
// Labels are fixed to two: "agent" and "human". Abstain (don't call
// Update at all) on samples that don't clear a weak-label threshold.
type Bayes struct {
	mu sync.RWMutex

	// Class priors — simple integer counts.
	agentCount int
	humanCount int
	total      int

	// counts[featureName][bucket] = [agent, human].
	counts map[string]map[string][2]int

	// Per-feature vocabulary size (distinct buckets observed) — cached
	// so we don't rebuild it on every Posterior call.
	vocab map[string]int

	smoothing   float64
	totalEntries int // cached count of distinct (feature, bucket) pairs
}

// NewBayes constructs an empty classifier.
func NewBayes(laplace float64) *Bayes {
	if laplace <= 0 {
		laplace = 1.0
	}
	return &Bayes{
		counts:    make(map[string]map[string][2]int),
		vocab:     make(map[string]int),
		smoothing: laplace,
	}
}

// Seen reports total labeled examples ingested (both classes).
func (b *Bayes) Seen() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.total
}

// Update ingests one labeled sample. label must be "agent" or "human".
func (b *Bayes) Update(v Vec, label string) {
	if label != "agent" && label != "human" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if label == "agent" {
		b.agentCount++
	} else {
		b.humanCount++
	}
	b.total++

	for _, f := range v.Categorical {
		m, ok := b.counts[f.Name]
		if !ok {
			m = make(map[string][2]int)
			b.counts[f.Name] = m
		}
		existing, seen := m[f.Bucket]
		if !seen {
			b.vocab[f.Name]++
			b.totalEntries++
			if b.totalEntries > MaxBayesEntries {
				b.evictLowest()
			}
		}
		if label == "agent" {
			existing[0]++
		} else {
			existing[1]++
		}
		m[f.Bucket] = existing
	}
}

// evictLowest removes a low-count (feature, bucket) pair. Uses random sampling
// (examine up to 16 candidates, evict the minimum among them) so the operation
// is O(1) under adversarial UUID floods rather than O(n). Called under write lock.
func (b *Bayes) evictLowest() {
	const sampleSize = 16
	var minFeat, minBucket string
	minTotal := math.MaxInt64
	sampled := 0
outer:
	for feat, m := range b.counts {
		for bk, pair := range m {
			if t := pair[0] + pair[1]; t < minTotal {
				minTotal = t
				minFeat = feat
				minBucket = bk
			}
			sampled++
			if sampled >= sampleSize {
				break outer
			}
		}
	}
	if minFeat == "" {
		return
	}
	delete(b.counts[minFeat], minBucket)
	b.vocab[minFeat]--
	if b.vocab[minFeat] <= 0 {
		delete(b.vocab, minFeat)
		delete(b.counts, minFeat)
	}
	b.totalEntries--
	telemetry.MLBayesEvictionsTotal.Inc()
	telemetry.BayesEvictionsCount.Add(1)
}

// TotalEntries returns the current number of distinct (feature, bucket) pairs
// stored in the histogram. Safe for concurrent use.
func (b *Bayes) TotalEntries() int {
	b.mu.RLock()
	n := b.totalEntries
	b.mu.RUnlock()
	return n
}

// Posterior returns P(agent | v) using additive-smoothed multinomial NB
// in log space. Returns 0.5 for an empty vector or an untrained model —
// "no information, assume coin flip".
func (b *Bayes) Posterior(v Vec) float64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.total == 0 || len(v.Categorical) == 0 {
		return 0.5
	}

	// Start with log-priors.
	pA := math.Log(float64(b.agentCount+1)) - math.Log(float64(b.total+2))
	pH := math.Log(float64(b.humanCount+1)) - math.Log(float64(b.total+2))

	for _, f := range v.Categorical {
		m := b.counts[f.Name]
		vocab := b.vocab[f.Name]
		if vocab == 0 {
			vocab = 1
		}
		pair := m[f.Bucket] // zero-value if unseen; Laplace smooths this

		// P(bucket | agent) and P(bucket | human).
		pA += math.Log(float64(pair[0])+b.smoothing) -
			math.Log(float64(b.agentCount)+b.smoothing*float64(vocab))
		pH += math.Log(float64(pair[1])+b.smoothing) -
			math.Log(float64(b.humanCount)+b.smoothing*float64(vocab))
	}
	// Convert log-odds to probability.
	// P = e^pA / (e^pA + e^pH); compute stably.
	diff := pA - pH
	if diff > 50 {
		return 1
	}
	if diff < -50 {
		return 0
	}
	return 1.0 / (1.0 + math.Exp(-diff))
}

// FeatureAgentProb returns P(agent | feature=bucket) for miner use.
// Returns (posterior, support) where support is agent+human counts for
// that bucket.
func (b *Bayes) FeatureAgentProb(name, bucket string) (float64, int) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.total == 0 {
		return 0, 0
	}
	m, ok := b.counts[name]
	if !ok {
		return 0, 0
	}
	pair := m[bucket]
	a, h := pair[0], pair[1]
	support := a + h
	if support == 0 {
		return 0, 0
	}
	// Bayesian estimate with Beta(1,1) prior to avoid 0/1 on tiny support.
	return float64(a+1) / float64(support+2), support
}

// Seed primes the classifier with pre-computed (feature, bucket) counts
// derived from a learned candidate's posterior and support values. It is
// used at startup to warm up the classifier with community-contributed
// or operator-promoted rules before any live traffic is observed.
//
// agentCount and humanCount are additive — calling Seed twice for the
// same bucket accumulates counts rather than replacing them.
func (b *Bayes) Seed(feature, bucket string, agentCount, humanCount int) {
	if agentCount < 0 {
		agentCount = 0
	}
	if humanCount < 0 {
		humanCount = 0
	}
	if agentCount+humanCount == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	m, ok := b.counts[feature]
	if !ok {
		m = make(map[string][2]int)
		b.counts[feature] = m
	}
	existing := m[bucket]
	if existing[0] == 0 && existing[1] == 0 {
		b.vocab[feature]++
		b.totalEntries++
	}
	existing[0] += agentCount
	existing[1] += humanCount
	m[bucket] = existing
	b.agentCount += agentCount
	b.humanCount += humanCount
	b.total += agentCount + humanCount
}

// Snapshot holds a read-only view of the counts for the miner.
type Snapshot struct {
	Agent, Human, Total int
	Counts              map[string]map[string][2]int
}

func (b *Bayes) Snapshot() Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := Snapshot{
		Agent: b.agentCount,
		Human: b.humanCount,
		Total: b.total,
		Counts: make(map[string]map[string][2]int, len(b.counts)),
	}
	for k, m := range b.counts {
		cm := make(map[string][2]int, len(m))
		for bk, v := range m {
			cm[bk] = v
		}
		out.Counts[k] = cm
	}
	return out
}
