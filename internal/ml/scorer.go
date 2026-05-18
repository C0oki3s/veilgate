package ml

import (
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// Result is what Scorer returns for a single request. The detector
// wraps this into its own Signal type to avoid an import cycle.
type Result struct {
	// Points in [0, config.ScoreMaxPoints]. Zero during burn-in.
	Points int
	// Reason is a short operator-readable explanation.
	Reason string
	// PosteriorAgent is the Bayes P(agent | v) ∈ [0,1].
	PosteriorAgent float64
	// Anomaly is the Isolation Forest score ∈ [0,1]. 0 if the forest
	// hasn't been fit yet.
	Anomaly float64
	// Fired is true when Points > 0 (convenience for callers).
	Fired bool
}

// Scorer is the online ML signal producer. One instance per process,
// shared between the request path (Score + Observe) and the periodic
// retrain goroutine (RefitIsoForest).
type Scorer struct {
	cfg *rules.Holder[rules.ML]

	bayes *Bayes
	iso   *IsoForest

	// Ring buffer of recent numeric vectors for the next IF refit.
	// Protected by bufMu; the refit goroutine drains it.
	bufMu   sync.Mutex
	recent  [][]float64
	bufCap  int

	// observed counts labeled examples sent to Bayes — the burn-in gate.
	observed atomic.Int64

	// refitting guards against two concurrent IF fits stacking on top
	// of each other. The 1-minute ticker in main.go uses RefitAsync
	// which CAS's this flag — if a previous fit is still running the
	// tick is simply skipped rather than queued.
	refitting atomic.Bool

	// Stats exported for metrics and debugging. Updated after every
	// fit; unprotected because single-writer (RefitIsoForest) and
	// monotonic.
	lastFitDuration atomic.Int64 // nanoseconds
	lastFitRows     atomic.Int64
	fitCount        atomic.Int64
}

// NewScorer constructs a scorer. Pass a rules holder so retrains and
// hot-reloads see live config.
func NewScorer(cfg *rules.Holder[rules.ML]) *Scorer {
	m := cfg.Load()
	laplace := 1.0
	bufCap := 5000
	if m != nil {
		if m.Bayes.LaplaceSmoothing > 0 {
			laplace = m.Bayes.LaplaceSmoothing
		}
		if m.IsoForest.RetrainEveryNEvents > 0 {
			bufCap = m.IsoForest.RetrainEveryNEvents
		}
	}
	return &Scorer{
		cfg:    cfg,
		bayes:  NewBayes(laplace),
		iso:    NewIsoForest(),
		bufCap: bufCap,
	}
}

// Bayes exposes the underlying classifier (for the miner's Snapshot).
func (s *Scorer) Bayes() *Bayes { return s.bayes }

// Score produces an ml_agent_score result for one feature vector.
// Returns zeros when ML is disabled or still in burn-in.
func (s *Scorer) Score(v Vec) Result {
	m := s.cfg.Load()
	if !m.Enabled {
		return Result{}
	}
	if int(s.observed.Load()) < m.BurnInEvents {
		return Result{}
	}
	maxPts := m.ScoreMaxPoints
	if maxPts <= 0 {
		maxPts = 40
	}
	alpha := m.Alpha
	if alpha < 0 {
		alpha = 0
	} else if alpha > 1 {
		alpha = 1
	}

	pAgent := s.bayes.Posterior(v)

	// CRITICAL: Bayes returns 0.5 when it has no information. The previous
	// formula alpha*pAgent treated that as "half-agent" (≈14 pts at alpha=0.7,
	// maxPts=40), which caused legit browsers with never-before-seen feature
	// combinations to score ~14-34%. Rescale so only the *agent-leaning half*
	// of the posterior contributes: pAgent=0.5 → 0, pAgent=0.75 → 0.5,
	// pAgent=1.0 → 1.0. Isolation Forest's raw output already uses the same
	// "rescale around 0.5" convention (see anomaly block below), so the two
	// inputs to `combined` are now on matching scales.
	pAgentRescaled := (pAgent - 0.5) * 2
	if pAgentRescaled < 0 {
		pAgentRescaled = 0
	}

	anomaly := 0.0
	if s.iso.TreeCount() > 0 && len(v.Numeric) > 0 {
		// Isolation Forest convention: scores >= 0.5 are candidate
		// anomalies. Rescale so only the anomalous half contributes.
		raw := s.iso.Score(v.Numeric)
		anomaly = (raw - 0.5) * 2
		if anomaly < 0 {
			anomaly = 0
		}
	}
	combined := alpha*pAgentRescaled + (1-alpha)*anomaly
	if combined < 0 {
		combined = 0
	} else if combined > 1 {
		combined = 1
	}

	// Minimum-confidence gate: below this floor the signal stays silent
	// so tiny noise doesn't accumulate across requests. Operators can
	// tune via ml.yaml -> min_confidence_to_fire (default 0.2 = 8 pts at
	// maxPts=40). Set to 0 to restore the old "fire on any positive".
	floor := m.MinConfidenceToFire
	if floor <= 0 {
		floor = 0.2
	}
	if combined < floor {
		return Result{PosteriorAgent: pAgent, Anomaly: anomaly}
	}

	points := int(math.Round(float64(maxPts) * combined))
	if points <= 0 {
		return Result{PosteriorAgent: pAgent, Anomaly: anomaly}
	}
	return Result{
		Points:         points,
		Reason:         reasonFor(pAgent, anomaly),
		PosteriorAgent: pAgent,
		Anomaly:        anomaly,
		Fired:          true,
	}
}

func reasonFor(pAgent, anomaly float64) string {
	switch {
	case pAgent >= 0.8 && anomaly >= 0.4:
		return "classifier + anomaly both flag agent-like behavior"
	case pAgent >= 0.8:
		return "features match learned agent pattern"
	case anomaly >= 0.5:
		return "feature combination is unusual for observed traffic"
	default:
		return "weak agent-leaning signal"
	}
}

// Observe feeds one request's features + rule-based score into the online
// learner using the same weak-labeling rule the detector uses elsewhere:
// score >= agentThreshold is "agent", score == 0 is "human", anything in
// between is abstained on. The numeric vector is buffered for the next
// IF refit.
func (s *Scorer) Observe(v Vec, ruleScore, agentThreshold int) {
	label := ""
	switch {
	case ruleScore >= agentThreshold:
		label = "agent"
	case ruleScore == 0:
		label = "human"
	}
	if label != "" {
		s.bayes.Update(v, label)
		s.observed.Add(1)
	}

	if len(v.Numeric) == 0 {
		return
	}
	cp := make([]float64, len(v.Numeric))
	copy(cp, v.Numeric)
	s.bufMu.Lock()
	if len(s.recent) >= s.bufCap {
		// Ring behavior: drop the oldest row.
		s.recent = append(s.recent[1:], cp)
	} else {
		s.recent = append(s.recent, cp)
	}
	s.bufMu.Unlock()
}

// RefitIsoForest rebuilds the forest from the buffered numeric rows.
// Safe to call from a background goroutine; blocks readers only during
// the final pointer swap inside IsoForest.Fit. Prefer RefitIsoForestAsync
// in production so the caller doesn't block on a slow fit.
//
// Training-row cap: when ml.yaml sets iso_forest.train_max_rows > 0, the
// buffered data is reservoir-sampled down to that cap BEFORE Fit. Iso
// Forest plateaus at a few thousand rows — capping keeps fit-time
// bounded as ingestion volume grows.
func (s *Scorer) RefitIsoForest() {
	m := s.cfg.Load()
	if !m.Enabled {
		return
	}
	s.bufMu.Lock()
	data := make([][]float64, len(s.recent))
	copy(data, s.recent)
	s.bufMu.Unlock()

	if len(data) < 32 {
		return // not enough to be meaningful
	}

	if cap := m.IsoForest.TrainMaxRows; cap > 0 && len(data) > cap {
		data = reservoirSample(data, cap)
	}

	start := time.Now()
	s.iso.Fit(data, m.IsoForest.TreeCount, m.IsoForest.SampleSize, m.IsoForest.MaxDepth)
	s.lastFitDuration.Store(int64(time.Since(start)))
	s.lastFitRows.Store(int64(len(data)))
	s.fitCount.Add(1)
}

// RefitIsoForestAsync kicks off a refit on a background goroutine
// unless one is already in flight. Returns true when a fit was
// started, false when skipped. onDone is invoked after the fit with
// the row count and duration so the caller can log / export metrics
// without reaching into Scorer internals.
//
// This is the path main.go should use: the 1-minute ticker fires and
// forgets; if the previous fit is still running we simply skip this
// tick, which keeps ingestion (Observe) completely undisturbed and
// prevents worker pile-up during high-traffic bursts.
func (s *Scorer) RefitIsoForestAsync(onDone func(rows int, dur time.Duration)) bool {
	if !s.refitting.CompareAndSwap(false, true) {
		return false
	}
	go func() {
		defer s.refitting.Store(false)
		s.RefitIsoForest()
		if onDone != nil {
			onDone(int(s.lastFitRows.Load()), time.Duration(s.lastFitDuration.Load()))
		}
	}()
	return true
}

// LastFitDuration returns how long the most recent Fit took. 0 before
// the first fit has completed.
func (s *Scorer) LastFitDuration() time.Duration {
	return time.Duration(s.lastFitDuration.Load())
}

// FitCount returns the number of Fits the scorer has run. Exported so
// metrics / health-checks can spot a retrain goroutine that stalled.
func (s *Scorer) FitCount() int64 {
	return s.fitCount.Load()
}

// reservoirSample picks n rows uniformly-at-random from data, without
// shuffling the source slice. When len(data) <= n, returns data as-is.
// Uses its own rand.Rand so each fit is deterministic given the same
// input — important for unit tests.
func reservoirSample(data [][]float64, n int) [][]float64 {
	if n >= len(data) {
		return data
	}
	out := make([][]float64, n)
	copy(out, data[:n])
	rng := rand.New(rand.NewSource(int64(len(data))))
	for i := n; i < len(data); i++ {
		j := rng.Intn(i + 1)
		if j < n {
			out[j] = data[i]
		}
	}
	return out
}

// BufferedRows reports how many numeric rows are queued for the next refit.
// Main.go's retrain goroutine can use this to skip cycles where nothing new arrived.
func (s *Scorer) BufferedRows() int {
	s.bufMu.Lock()
	defer s.bufMu.Unlock()
	return len(s.recent)
}

// Observed reports total labeled updates sent to Bayes (burn-in progress).
func (s *Scorer) Observed() int64 {
	return s.observed.Load()
}

// knownBadPosterior and knownBadSupport are the synthetic values used
// when an active candidate has no observed posterior/support — i.e. it
// was authored from human knowledge or tool-fingerprint research rather
// than from miner output. They give the bucket a small but firm agent
// prior without overwhelming the classifier.
const (
	knownBadPosterior = 0.99
	knownBadSupport   = 10
)

// SeedFromLearned primes s's Bayes classifier with active candidates from
// loaded learned rules. Each active candidate is converted to synthetic
// observation counts and injected via Bayes.Seed.
//
// posterior and support are optional:
//   - If both are zero (human-knowledge / tool-fingerprint rule with no
//     observed traffic), knownBadPosterior=0.99 and knownBadSupport=10
//     are used — a small but firm agent prior.
//   - If only posterior is set (and support is zero), support defaults to
//     knownBadSupport so the value is still contributed.
//   - If support is set but posterior is zero, the entry is skipped
//     (posterior=0 would contribute zero agent counts).
//
// Returns the number of candidates seeded.
func (s *Scorer) SeedFromLearned(candidates []rules.LearnedCandidate) int {
	seeded := 0
	for _, c := range candidates {
		if !c.Active {
			continue
		}
		posterior := c.Posterior
		support := c.Support
		switch {
		case posterior == 0 && support == 0:
			// Human-knowledge rule: no observed data — use synthetic defaults.
			posterior = knownBadPosterior
			support = knownBadSupport
		case posterior > 0 && support == 0:
			// Operator specified confidence but no count.
			support = knownBadSupport
		case posterior == 0:
			// Support without posterior — cannot compute meaningful seed.
			continue
		}
		agentCount := int(math.Round(posterior * float64(support)))
		humanCount := support - agentCount
		s.bayes.Seed(c.Feature, c.Bucket, agentCount, humanCount)
		seeded++
	}
	return seeded
}
