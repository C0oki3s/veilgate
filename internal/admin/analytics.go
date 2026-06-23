package admin

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"sort"
	"time"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/recommender"
)

// openEventStore opens the proxy's SQLite event store (the correlation DB) for
// reading when persist is enabled in the config. The admin and the proxy point
// at the same file; SQLite WAL allows the admin to read concurrently while the
// proxy writes. A failure is non-fatal — analytics simply fall back to empty.
func (s *Server) openEventStore() {
	if s.cfg == nil || !s.cfg.Persist.Enabled || s.cfg.Persist.Path == "" {
		return
	}
	st, err := persist.Open(persist.Config{Path: s.cfg.Persist.Path})
	if err != nil {
		log.Printf("admin: event store unavailable (%v) — analytics disabled", err)
		return
	}
	s.store = st
	log.Printf("admin: event store opened (correlation DB): %s", s.cfg.Persist.Path)
}

// splitDecisions folds a decision→count map into the five chart classes,
// collapsing the various "passed through" decisions into observe.
func splitDecisions(by map[string]int) (observe, challenge, tarpit, clean, other int) {
	for dec, n := range by {
		switch dec {
		case "observe", "allow", "pass":
			observe += n
		case "challenge":
			challenge += n
		case "tarpit":
			tarpit += n
		case "clean":
			clean += n
		default:
			other += n
		}
	}
	return
}

// scoreThresholds returns the configured challenge/tarpit score cutoffs, used to
// colour the score histogram. Falls back to the engine defaults (40/70).
func (s *Server) scoreThresholds() (challenge, tarpit int) {
	challenge, tarpit = 40, 70
	if s.cfg != nil {
		if v := s.cfg.Detector.ScoreChallengeThreshold; v > 0 {
			challenge = v
		}
		if v := s.cfg.Detector.ScoreTarpitThreshold; v > 0 {
			tarpit = v
		}
	}
	return
}

// ── Dashboard analytics ─────────────────────────────────────────────────────

// Analytics is the request breakdown shown on the dashboard.
type Analytics struct {
	Available bool   // true when the event store is open
	Window    string // human label for the lookback window
	Total     int
	Observe   int
	Challenge int
	Tarpit    int
	Clean     int
	Other     int

	// Server-rendered SVG charts (empty when there is nothing to draw). These
	// are pre-escaped template.HTML produced by charts.go — no client-side JS,
	// CSP-safe. HasCharts is true once at least one chart has data.
	HasCharts    bool
	TimelineSVG  template.HTML
	DonutSVG     template.HTML
	HistogramSVG template.HTML
	TopPathsSVG  template.HTML
}

// loadAnalytics aggregates events by decision over the last 24h and renders the
// dashboard charts from the correlation event store.
func (s *Server) loadAnalytics() Analytics {
	a := Analytics{Window: "last 24h"}
	if s.store == nil {
		return a
	}
	since := time.Now().Add(-24 * time.Hour)

	dc, err := s.store.CountDecisions(since)
	if err != nil {
		log.Printf("admin: analytics query failed: %v", err)
		return a
	}
	a.Available = true
	a.Total = dc.Total
	a.Observe, a.Challenge, a.Tarpit, a.Clean, a.Other = splitDecisions(dc.ByDecision)

	// Decision-mix donut (reuses the aggregate counts above).
	a.DonutSVG = donutSVG([]donutSeg{
		{a.Clean, colClean, "Clean"},
		{a.Observe, colObserve, "Observe"},
		{a.Challenge, colChallenge, "Challenge"},
		{a.Tarpit, colTarpit, "Tarpit"},
		{a.Other, colOther, "Other"},
	}, a.Total)

	// Requests-over-time stacked bars (hourly buckets across the window).
	if buckets, bErr := s.store.DecisionTimeSeries(since, 13); bErr == nil {
		a.TimelineSVG = timelineSVG(buckets)
	} else {
		log.Printf("admin: timeline query failed: %v", bErr)
	}

	// Score-distribution histogram, coloured by the configured thresholds.
	challenge, tarpit := s.scoreThresholds()
	if bins, hErr := s.store.ScoreHistogram(since, 10); hErr == nil {
		a.HistogramSVG = histogramSVG(bins, challenge, tarpit)
	} else {
		log.Printf("admin: histogram query failed: %v", hErr)
	}

	// Top probed paths.
	if paths, pErr := s.store.TopPaths(since, 8); pErr == nil {
		a.TopPathsSVG = topPathsSVG(paths)
	} else {
		log.Printf("admin: top-paths query failed: %v", pErr)
	}

	a.HasCharts = a.TimelineSVG != "" || a.DonutSVG != "" || a.HistogramSVG != "" || a.TopPathsSVG != ""
	return a
}

// ── Analytics page (dedicated, range-selectable, live-refreshing) ───────────

// analyticsRange is one selectable lookback window. Bucket is the RFC3339
// prefix length DecisionTimeSeries groups on (16=minute, 13=hour, 10=day).
type analyticsRange struct {
	Key    string
	Label  string
	Dur    time.Duration
	Bucket int
}

var analyticsRanges = []analyticsRange{
	{"1h", "1 hour", time.Hour, 16},
	{"24h", "24 hours", 24 * time.Hour, 13},
	{"7d", "7 days", 7 * 24 * time.Hour, 13},
	{"30d", "30 days", 30 * 24 * time.Hour, 10},
}

// rangeByKey resolves a ?range= value, defaulting to 24h.
func rangeByKey(key string) analyticsRange {
	for _, r := range analyticsRanges {
		if r.Key == key {
			return r
		}
	}
	return analyticsRanges[1]
}

// AnalyticsPage backs the dedicated /analytics page. It carries the same charts
// as the dashboard plus top-clients, top-user-agents and signal-frequency
// breakdowns, all scoped to the selected range.
type AnalyticsPage struct {
	Available  bool             // event store open?
	Ranges     []analyticsRange // selector options
	Range      string           // selected key
	RangeLabel string           // human label for the selected range
	Updated    string           // wall-clock time this snapshot was built

	Total, Observe, Challenge, Tarpit, Clean, Other int

	HasCharts     bool
	TimelineSVG   template.HTML
	DonutSVG      template.HTML
	HistogramSVG  template.HTML
	TopPathsSVG   template.HTML
	TopClientsSVG template.HTML
	TopUASVG      template.HTML
	TopSignalsSVG template.HTML
}

// buildAnalyticsPage assembles every chart for the given window from the event
// store. All queries are read-only and individually fault-tolerant — a failing
// query just leaves its chart empty rather than failing the page.
func (s *Server) buildAnalyticsPage(rng analyticsRange) *AnalyticsPage {
	p := &AnalyticsPage{
		Ranges:     analyticsRanges,
		Range:      rng.Key,
		RangeLabel: rng.Label,
		Updated:    time.Now().Format("15:04:05"),
	}
	if s.store == nil {
		return p
	}
	since := time.Now().Add(-rng.Dur)

	dc, err := s.store.CountDecisions(since)
	if err != nil {
		log.Printf("admin: analytics page query failed: %v", err)
		return p
	}
	p.Available = true
	p.Total = dc.Total
	p.Observe, p.Challenge, p.Tarpit, p.Clean, p.Other = splitDecisions(dc.ByDecision)

	p.DonutSVG = donutSVG([]donutSeg{
		{p.Clean, colClean, "Clean"},
		{p.Observe, colObserve, "Observe"},
		{p.Challenge, colChallenge, "Challenge"},
		{p.Tarpit, colTarpit, "Tarpit"},
		{p.Other, colOther, "Other"},
	}, p.Total)

	if buckets, bErr := s.store.DecisionTimeSeries(since, rng.Bucket); bErr == nil {
		p.TimelineSVG = timelineSVG(buckets)
	} else {
		log.Printf("admin: timeline query failed: %v", bErr)
	}

	challenge, tarpit := s.scoreThresholds()
	if bins, hErr := s.store.ScoreHistogram(since, 10); hErr == nil {
		p.HistogramSVG = histogramSVG(bins, challenge, tarpit)
	} else {
		log.Printf("admin: histogram query failed: %v", hErr)
	}

	if paths, pErr := s.store.TopPaths(since, 10); pErr == nil {
		p.TopPathsSVG = topPathsSVG(paths)
	} else {
		log.Printf("admin: top-paths query failed: %v", pErr)
	}
	if clients, cErr := s.store.TopClients(since, 10); cErr == nil {
		p.TopClientsSVG = topClientsSVG(clients)
	} else {
		log.Printf("admin: top-clients query failed: %v", cErr)
	}
	if uas, uErr := s.store.TopUserAgents(since, 10); uErr == nil {
		p.TopUASVG = topUserAgentsSVG(uas)
	} else {
		log.Printf("admin: top-user-agents query failed: %v", uErr)
	}
	if sigs, sErr := s.store.TopSignals(since, 12); sErr == nil {
		p.TopSignalsSVG = topSignalsSVG(sigs)
	} else {
		log.Printf("admin: top-signals query failed: %v", sErr)
	}

	p.HasCharts = p.TimelineSVG != "" || p.DonutSVG != "" || p.HistogramSVG != "" ||
		p.TopPathsSVG != "" || p.TopClientsSVG != "" || p.TopUASVG != "" || p.TopSignalsSVG != ""
	return p
}

// handleAnalytics serves the dedicated analytics page. The full page renders the
// shell + range selector; htmx auto-refresh requests (?partial=1) get only the
// inner chart fragment so the live region swaps in place without a reload.
func (s *Server) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	rng := rangeByKey(r.URL.Query().Get("range"))
	data := s.buildAnalyticsPage(rng)

	if r.URL.Query().Get("partial") == "1" {
		t, ok := s.templates["analytics"]
		if !ok {
			http.Error(w, "template not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := t.ExecuteTemplate(w, "analytics-fragment", &PageData{Data: data}); err != nil {
			log.Printf("admin: analytics fragment render failed: %v", err)
		}
		return
	}

	s.render(w, r, "analytics", &PageData{
		Title:      "Analytics",
		ActivePage: "analytics",
		Data:       data,
	})
}

// ── Recommender tab ─────────────────────────────────────────────────────────

// RecommenderData backs the recommender page.
type RecommenderData struct {
	Available  bool // event store open?
	Recs       []recommender.SignalRecommendation
	YAML       string // rendered report YAML ("loading yaml")
	Err        string
	Candidates []persist.Candidate // ML rule candidates (correlation fitting)
}

// handleRecommender runs the ML-based signal recommender against the event
// store and renders both a recommendation table and the report YAML.
func (s *Server) handleRecommender(w http.ResponseWriter, r *http.Request) {
	data := &RecommenderData{}
	if s.store == nil {
		s.render(w, r, "recommender", &PageData{
			Title:      "Recommender",
			ActivePage: "recommender",
			Data:       data,
		})
		return
	}
	data.Available = true

	tarpit := 70
	if s.cfg != nil && s.cfg.Detector.ScoreTarpitThreshold > 0 {
		tarpit = s.cfg.Detector.ScoreTarpitThreshold
	}

	// nil ML holder is safe — the recommender falls back to sane defaults.
	rec := recommender.New(s.store, nil, s.rulesDir(), tarpit)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	recs, err := rec.Analyze(ctx)
	if err != nil {
		data.Err = err.Error()
	} else {
		data.Recs = recs
		if y, yErr := recommender.RenderReportYAML(recs); yErr == nil {
			data.YAML = string(y)
		} else {
			data.Err = yErr.Error()
		}
	}

	// ML correlation fitting: surface the current rule candidates.
	if cands, cErr := s.store.ListAllCandidates(); cErr == nil {
		sort.Slice(cands, func(i, j int) bool { return cands[i].Posterior > cands[j].Posterior })
		if len(cands) > 50 {
			cands = cands[:50]
		}
		data.Candidates = cands
	}

	s.render(w, r, "recommender", &PageData{
		Title:      "Recommender",
		ActivePage: "recommender",
		Data:       data,
	})
}
