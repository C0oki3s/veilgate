package ml

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/telemetry"
)

// Miner walks the Bayes snapshot on a schedule, discovers high-confidence
// (feature, bucket) pairs, writes them to rules/learned.yaml as inactive
// candidates, and mirrors the same rows into rule_candidates in the store
// so operators can promote/reject from either surface.
//
// Miner does not mutate any operator-authored YAML. learned.yaml is
// considered miner-owned; operators flip `active: true` per entry after
// review.
type Miner struct {
	bayes *Bayes
	cfg   *rules.Holder[rules.ML]
	store *persist.Store // optional; nil disables DB mirroring

	// Path to the YAML we write. Resolved against rulesDir on each tick
	// so hot-reload of ml.yaml's write_path takes effect.
	rulesDir string

	// mergePrior carries forward existing active flags from the last
	// learned.yaml we wrote — otherwise every tick would clobber
	// operator promotions.
	mergePrior bool
}

// NewMiner constructs a miner. rulesDir is the directory where
// learned.yaml lives; store may be nil.
func NewMiner(b *Bayes, cfg *rules.Holder[rules.ML], store *persist.Store, rulesDir string) *Miner {
	return &Miner{bayes: b, cfg: cfg, store: store, rulesDir: rulesDir, mergePrior: true}
}

// Run blocks until ctx is done, firing one mining pass per configured
// interval. Errors are non-fatal — the miner logs via the supplied
// onError callback (nil = discard) and keeps running.
func (m *Miner) Run(ctx context.Context, onError func(error)) {
	for {
		interval := m.interval()
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
		if err := m.Tick(); err != nil && onError != nil {
			onError(err)
		}
	}
}

func (m *Miner) interval() time.Duration {
	mc := m.cfg.Load()
	if mc == nil {
		return time.Hour
	}
	mins := mc.Miner.IntervalMinutes
	if mins <= 0 {
		mins = 60
	}
	return time.Duration(mins) * time.Minute
}

// Tick runs one mining pass. Exported so tests can drive it without a
// goroutine.
func (m *Miner) Tick() error {
	mc := m.cfg.Load()
	if mc == nil {
		return nil
	}
	if !mc.Miner.Enabled {
		return nil
	}
	minSupport := mc.Miner.MinSupport
	if minSupport <= 0 {
		minSupport = 200
	}
	minPost := mc.Miner.MinPosterior
	if minPost <= 0 {
		minPost = 0.9
	}
	snap := m.bayes.Snapshot()
	if snap.Total == 0 {
		return nil
	}

	// Walk the snapshot, apply thresholds.
	var cands []rules.LearnedCandidate
	now := time.Now().UTC().Format(time.RFC3339)
	for feat, buckets := range snap.Counts {
		for bucket, pair := range buckets {
			a, h := pair[0], pair[1]
			support := a + h
			if support < minSupport {
				continue
			}
			// Same Beta(1,1) prior as Bayes.FeatureAgentProb.
			post := float64(a+1) / float64(support+2)
			if post < minPost {
				continue
			}
			active := false
			if ap := mc.Miner.AutoPromoteConfidence; ap > 0 && post >= ap {
				active = true
			}
			cands = append(cands, rules.LearnedCandidate{
				Feature:    feat,
				Bucket:     bucket,
				Posterior:  post,
				Support:    support,
				Active:     active,
				ProposedAt: now,
			})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Posterior == cands[j].Posterior {
			return cands[i].Support > cands[j].Support
		}
		return cands[i].Posterior > cands[j].Posterior
	})

	// Persist feature/bucket/posterior/support to SQLite first — this
	// preserves any previously-set active flag across restarts. Then we
	// read active flags back out so both learned.yaml and in-memory cands
	// reflect the durable state.
	if m.store != nil {
		for _, c := range cands {
			_ = m.store.UpsertCandidate(persist.Candidate{
				Feature:   c.Feature,
				Bucket:    c.Bucket,
				Posterior: c.Posterior,
				Support:   c.Support,
			})
		}
	}

	if len(cands) > 0 {
		telemetry.MinerCandidates.Add(float64(len(cands)))
		telemetry.MinerCandidatesCount.Add(int64(len(cands)))
	}

	if err := m.writeYAML(cands, mc); err != nil {
		return fmt.Errorf("miner: write learned.yaml: %w", err)
	}

	// After writeYAML merges active flags from (SQLite ∪ prior YAML),
	// push any YAML-originated promotions back into SQLite so the next
	// restart picks them up even if the YAML is later deleted.
	if m.store != nil {
		for _, c := range cands {
			if c.Active {
				_ = m.store.SetCandidateActive(c.Feature, c.Bucket, true)
			}
		}
	}
	return nil
}

// writeYAML persists candidates to learned.yaml (or the path configured
// under ml.yaml -> miner.write_path). Writes through a temp file + rename
// so a half-written file can never be loaded.
func (m *Miner) writeYAML(cands []rules.LearnedCandidate, mc *rules.ML) error {
	path := mc.Miner.WritePath
	if path == "" {
		path = "learned.yaml"
	}
	if !filepath.IsAbs(path) && m.rulesDir != "" {
		path = filepath.Join(m.rulesDir, path)
	}

	// Defensive: if an operator wrote `rules/learned.yaml` in ml.yaml and
	// rulesDir already ends in `rules`, collapse the redundant segment so
	// we don't try to write into rules/rules/learned.yaml.
	if m.rulesDir != "" {
		rdBase := filepath.Base(filepath.Clean(m.rulesDir))
		doubled := filepath.Join(m.rulesDir, rdBase, filepath.Base(path))
		if filepath.Clean(path) == filepath.Clean(doubled) {
			path = filepath.Join(m.rulesDir, filepath.Base(path))
		}
	}

	// os.WriteFile won't create missing parent dirs; make sure they exist
	// before we try to drop the temp file. This keeps the miner resilient
	// when rulesDir is a fresh clone or the write_path points deeper.
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("miner: mkdir %s: %w", dir, err)
		}
	}

	if m.mergePrior {
		// Build a lookup of active flags from both durable sources:
		//   1. SQLite rule_candidates (survives YAML deletion)
		//   2. The prior learned.yaml on disk (picks up hand-edits)
		// Union semantics: active if either source says active.
		activeMap := make(map[string]bool)
		if m.store != nil {
			if existing, err := m.store.ListAllCandidates(); err == nil {
				for _, e := range existing {
					if e.Active {
						activeMap[e.Feature+"|"+e.Bucket] = true
					}
				}
			}
		}
		if prior, err := loadExisting(path); err == nil && prior != nil {
			for _, p := range prior.Candidates {
				if p.Active {
					activeMap[p.Feature+"|"+p.Bucket] = true
				}
			}
		}
		for i := range cands {
			if activeMap[cands[i].Feature+"|"+cands[i].Bucket] {
				cands[i].Active = true
			}
		}
	}

	doc := rules.Learned{Candidates: cands}
	body, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}

	// Prepend a short header so operators know not to hand-edit beyond
	// flipping `active:`.
	header := []byte("# Auto-managed by the ML miner. Flip `active: true` on entries you want\n" +
		"# promoted into detector evaluation. Everything else is regenerated each tick.\n")
	payload := append(header, body...)

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadExisting(path string) (*rules.Learned, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l rules.Learned
	if err := yaml.Unmarshal(raw, &l); err != nil {
		return nil, err
	}
	return &l, nil
}
