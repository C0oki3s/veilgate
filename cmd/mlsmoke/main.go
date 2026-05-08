// Package main is a self-contained ML smoke test for VeilGate.
//
// It wires the production detector + ml + persist + miner packages
// in-process (no HTTP, no subprocesses), drives a scripted pair of
// agent- and human-like fake requests through the scorer, then:
//
//  1. queries the resulting SQLite event store,
//  2. triggers one miner pass,
//  3. reads back rules/learned.yaml,
//
// and prints a pass/fail report. The same fake requests are also shown
// as equivalent curl one-liners so you can replay any of them against
// a live veilgate instance (default target http://localhost:8080).
//
// Run with:
//
//	go run ./cmd/mlsmoke
//	go run ./cmd/mlsmoke -target http://localhost:8080 -curl-only
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"

	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/ml"
	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
)

type fakeRequest struct {
	Label       string // "agent" or "human" — the expected weak label
	Persona     string // human-readable tag
	Method      string
	Path        string
	UserAgent   string
	ExtraHeader map[string]string
}

var agentFleet = []fakeRequest{
	{Label: "agent", Persona: "sqlmap recon on .git leak", Method: "GET", Path: "/.git/config", UserAgent: "sqlmap/1.7.2#stable (https://sqlmap.org)"},
	{Label: "agent", Persona: "nikto hitting honeypot admin", Method: "GET", Path: "/admin-panel-v2", UserAgent: "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"},
	{Label: "agent", Persona: "python-requests probing legacy auth", Method: "GET", Path: "/api/v3/legacy-auth", UserAgent: "python-requests/2.31.0"},
	{Label: "agent", Persona: "curl pulling .env.backup", Method: "GET", Path: "/.env.backup", UserAgent: "curl/8.4.0"},
	{Label: "agent", Persona: "Go HTTP client on internal debug", Method: "POST", Path: "/api/internal/debug", UserAgent: "Go-http-client/1.1"},
	{Label: "agent", Persona: "feroxbuster dir bust", Method: "GET", Path: "/wp-admin-old", UserAgent: "feroxbuster/2.10.0"},
}

var humanFleet = []fakeRequest{
	{Label: "human", Persona: "Chrome 124 desktop", Method: "GET", Path: "/",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		ExtraHeader: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.9",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Mode":  "navigate",
			"Referer":         "https://www.google.com/",
		}},
	{Label: "human", Persona: "Firefox 124 desktop", Method: "GET", Path: "/about",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; rv:124.0) Gecko/20100101 Firefox/124.0",
		ExtraHeader: map[string]string{
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.5",
			"Accept-Encoding": "gzip, deflate",
			"Sec-Fetch-Site":  "same-origin",
			"Sec-Fetch-Mode":  "navigate",
		}},
	{Label: "human", Persona: "Safari 17 iPhone", Method: "GET", Path: "/login",
		UserAgent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
		ExtraHeader: map[string]string{
			"Accept":          "text/html",
			"Accept-Language": "en-US",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Mode":  "navigate",
		}},
	{Label: "human", Persona: "Edge desktop search", Method: "GET", Path: "/products",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
		ExtraHeader: map[string]string{
			"Accept":          "text/html,application/xhtml+xml",
			"Accept-Language": "en-US,en;q=0.8",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Site":  "same-origin",
			"Sec-Fetch-Mode":  "navigate",
		}},
}

func (f fakeRequest) toHTTP() *http.Request {
	req, _ := http.NewRequest(f.Method, "http://veilgate.local"+f.Path, nil)
	req.Header.Set("User-Agent", f.UserAgent)
	for k, v := range f.ExtraHeader {
		req.Header.Set(k, v)
	}
	return req
}

func (f fakeRequest) curl(target string) string {
	var sb strings.Builder
	sb.WriteString("curl -s -o /dev/null -w '%{http_code} %{time_total}s\\n' ")
	if f.Method != "GET" {
		sb.WriteString("-X " + f.Method + " ")
	}
	sb.WriteString(fmt.Sprintf("-H %q ", "User-Agent: "+f.UserAgent))
	keys := make([]string, 0, len(f.ExtraHeader))
	for k := range f.ExtraHeader {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteString(fmt.Sprintf("-H %q ", k+": "+f.ExtraHeader[k]))
	}
	sb.WriteString(target + f.Path)
	return sb.String()
}

func main() {
	target := flag.String("target", "http://localhost:8080", "base URL for curl examples")
	curlOnly := flag.Bool("curl-only", false, "just print the curl checklist and exit")
	agentRounds := flag.Int("agent", 30, "agent requests per persona")
	humanRounds := flag.Int("human", 30, "human requests per persona")
	flag.Parse()

	printChecklist(*target)
	if *curlOnly {
		return
	}

	if err := run(*agentRounds, *humanRounds); err != nil {
		fmt.Fprintf(os.Stderr, "smoke failed: %v\n", err)
		os.Exit(1)
	}
}

func printChecklist(target string) {
	fmt.Println("=== VeilGate ML smoke checklist ===")
	fmt.Printf("Target: %s\n\n", target)

	fmt.Println("-- AGENT-like fake requests (should score >=40 via honeypot/UA rules) --")
	for i, r := range agentFleet {
		fmt.Printf("[A%d] %s\n    %s\n", i+1, r.Persona, r.curl(target))
	}
	fmt.Println("\n-- HUMAN-like fake requests (should score 0) --")
	for i, r := range humanFleet {
		fmt.Printf("[H%d] %s\n    %s\n", i+1, r.Persona, r.curl(target))
	}
	fmt.Println()
}

func run(agentRounds, humanRounds int) error {
	tmp, err := os.MkdirTemp("", "veilgate-smoke-")
	if err != nil {
		return err
	}
	fmt.Printf("=== Running smoke in %s ===\n", tmp)

	rulesDir := filepath.Join(tmp, "rules")
	if err := copyRules("rules", rulesDir); err != nil {
		return fmt.Errorf("copy rules: %w", err)
	}
	if err := writeSmokeMLYaml(rulesDir); err != nil {
		return err
	}
	// Empty learned.yaml so we can detect new writes.
	if err := os.WriteFile(filepath.Join(rulesDir, "learned.yaml"), []byte("candidates: []\n"), 0o644); err != nil {
		return err
	}

	// 1. Persist store.
	store, err := persist.Open(persist.Config{
		Path:          filepath.Join(tmp, "events.db"),
		FlushInterval: 200 * time.Millisecond,
	})
	if err != nil {
		return fmt.Errorf("persist.Open: %w", err)
	}
	defer store.Close()

	// 2. ML wiring.
	mlCfg, err := rules.LoadML(rulesDir)
	if err != nil {
		return fmt.Errorf("LoadML: %w", err)
	}
	mlHolder := rules.NewHolder(mlCfg)
	mlScorer := ml.NewScorer(mlHolder)
	extractor := ml.NewExtractor()
	extractor.TimingBuckets = mlCfg.Bayes.TimingBucketsSeconds
	extractor.MaxNgramLength = mlCfg.Bayes.MaxNgramLength

	// 3. Detector wiring.
	detRules, err := rules.LoadDetector(rulesDir)
	if err != nil {
		return fmt.Errorf("LoadDetector: %w", err)
	}
	tracker := detector.NewTracker(90)
	scorer := detector.NewScorer(tracker,
		[]string{"/admin-panel-v2", "/api/internal/debug", "/.git/config", "/.env.backup", "/wp-admin-old", "/api/v3/legacy-auth"},
		[]string{"127.0.0.1"})
	scorer.SetRules(detRules)
	scorer.SetML(mlScorer, extractor, 40)

	// 4. Miner — driven manually via Tick(), not goroutine.
	miner := ml.NewMiner(mlScorer.Bayes(), mlHolder, store, rulesDir)

	// 5. Drive training traffic. Each request gets a unique client ID
	// (derived from index) so history-based signals stay quiet — we're
	// stress-testing the per-request ML features, not the timing heuristic.
	fmt.Println()
	fmt.Println("--- Training phase ---")
	t0 := time.Now()
	mlFiresSeen := 0
	agentTrained, humanTrained := 0, 0
	for i := 0; i < agentRounds; i++ {
		for j, r := range agentFleet {
			score := scorer.Score(fmt.Sprintf("10.0.%d.%d", i, j+1), r.toHTTP())
			if isAgentScore(score) {
				agentTrained++
			}
			recordEvent(store, score, r, "10.0."+fmt.Sprint(i)+"."+fmt.Sprint(j+1))
			if containsSignal(score, "ml_agent_score") {
				mlFiresSeen++
			}
		}
	}
	for i := 0; i < humanRounds; i++ {
		for j, r := range humanFleet {
			score := scorer.Score(fmt.Sprintf("192.168.%d.%d", i, j+1), r.toHTTP())
			if score.Total == 0 {
				humanTrained++
			}
			recordEvent(store, score, r, "192.168."+fmt.Sprint(i)+"."+fmt.Sprint(j+1))
		}
	}
	fmt.Printf("trained: agent=%d human=%d (in %s)\n", agentTrained, humanTrained, time.Since(t0).Round(time.Millisecond))

	// 6. Test phase — one fresh agent and one fresh human request, with
	// a client ID the scorer hasn't seen before.
	fmt.Println()
	fmt.Println("--- Test phase (post-burn-in) ---")

	testAgent := fakeRequest{
		Label: "agent", Persona: "test: fresh sqlmap probe",
		Method: "GET", Path: "/.git/config",
		UserAgent: "sqlmap/1.7.2#stable (https://sqlmap.org)",
	}
	testHuman := fakeRequest{
		Label: "human", Persona: "test: fresh Chrome request",
		Method: "GET", Path: "/",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		ExtraHeader: map[string]string{
			"Accept":          "text/html",
			"Accept-Language": "en-US",
			"Accept-Encoding": "gzip, deflate, br",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-Mode":  "navigate",
		},
	}
	fresh := scorer.Score("203.0.113.42", testAgent.toHTTP())
	mlPts, mlReason := 0, ""
	for _, s := range fresh.Signals {
		if s.Name == "ml_agent_score" {
			mlPts, mlReason = s.Points, s.Reason
		}
	}
	fmt.Printf("[%s] total=%d signals=%s ml_pts=%d reason=%q\n",
		testAgent.Persona, fresh.Total, signalNames(fresh), mlPts, mlReason)

	freshH := scorer.Score("198.51.100.7", testHuman.toHTTP())
	mlPtsH := 0
	for _, s := range freshH.Signals {
		if s.Name == "ml_agent_score" {
			mlPtsH = s.Points
		}
	}
	fmt.Printf("[%s] total=%d signals=%s ml_pts=%d\n",
		testHuman.Persona, freshH.Total, signalNames(freshH), mlPtsH)

	// 7. Flush and query persist.
	time.Sleep(500 * time.Millisecond)
	fmt.Println()
	fmt.Println("--- SQLite events.db peek ---")
	if err := dumpRecentEvents(filepath.Join(tmp, "events.db"), 5); err != nil {
		return err
	}

	// 8. Trigger miner.
	fmt.Println()
	fmt.Println("--- Miner tick ---")
	if err := miner.Tick(); err != nil {
		return fmt.Errorf("miner.Tick: %w", err)
	}
	learned, err := os.ReadFile(filepath.Join(rulesDir, "learned.yaml"))
	if err != nil {
		return err
	}
	var doc rules.Learned
	if err := yaml.Unmarshal(learned, &doc); err != nil {
		return fmt.Errorf("parse learned.yaml: %w", err)
	}
	fmt.Printf("learned.yaml candidates: %d\n", len(doc.Candidates))
	for _, c := range doc.Candidates[:min(len(doc.Candidates), 8)] {
		fmt.Printf("  feature=%s bucket=%q posterior=%.3f support=%d active=%t\n",
			c.Feature, c.Bucket, c.Posterior, c.Support, c.Active)
	}

	// 9. Verdict.
	fmt.Println()
	fmt.Println("--- Verdict ---")
	ok := true
	checkf(&ok, "agent requests weak-labeled as agent", agentTrained > 0)
	checkf(&ok, "human requests weak-labeled as human", humanTrained > 0)
	checkf(&ok, "ml_agent_score fired at least once during training", mlFiresSeen > 0)
	checkf(&ok, "ml_agent_score fires on fresh agent test request", mlPts > 0)
	checkf(&ok, "ml_agent_score is zero on fresh human test request", mlPtsH == 0)
	checkf(&ok, "miner produced at least one learned candidate", len(doc.Candidates) > 0)

	_ = context.Background() // silence import if unused above
	if !ok {
		return fmt.Errorf("one or more smoke assertions failed")
	}
	fmt.Println("\nALL CHECKS PASSED")
	return nil
}

func isAgentScore(s detector.Score) bool { return s.Total >= 40 }

func containsSignal(s detector.Score, name string) bool {
	for _, sig := range s.Signals {
		if sig.Name == name {
			return true
		}
	}
	return false
}

func signalNames(s detector.Score) string {
	parts := make([]string, 0, len(s.Signals))
	for _, sig := range s.Signals {
		parts = append(parts, fmt.Sprintf("%s(%d)", sig.Name, sig.Points))
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func recordEvent(store *persist.Store, score detector.Score, r fakeRequest, clientID string) {
	names := make([]string, 0, len(score.Signals))
	for _, s := range score.Signals {
		names = append(names, s.Name)
	}
	decision := "real"
	if score.Total >= 70 {
		decision = "tarpit"
	} else if score.Total >= 40 {
		decision = "challenge"
	}
	store.Record(persist.Event{
		Time:      time.Now().UTC(),
		ClientID:  clientID,
		Method:    r.Method,
		Path:      r.Path,
		UserAgent: r.UserAgent,
		Score:     score.Total,
		Signals:   names,
		Decision:  decision,
	})
}

func dumpRecentEvents(path string, limit int) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	rows, err := db.Query(`SELECT method, path, score, signals_json, decision FROM events ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var method, path, signals, decision string
		var score int
		if err := rows.Scan(&method, &path, &score, &signals, &decision); err != nil {
			return err
		}
		fmt.Printf("  %-6s %-24s score=%-3d decision=%-9s signals=%s\n",
			method, path, score, decision, signals)
	}
	return rows.Err()
}

func writeSmokeMLYaml(dir string) error {
	body := strings.TrimLeft(`
enabled: true
score_max_points: 40
alpha: 0.7
burn_in_events: 20

bayes:
  laplace_smoothing: 1.0
  max_ngram_length: 3
  timing_buckets_seconds: [0.1, 0.5, 1, 2, 5, 10, 30, 60, 300]

iso_forest:
  tree_count: 20
  sample_size: 64
  retrain_every_n_events: 200
  max_depth: 6

miner:
  enabled: true
  interval_minutes: 9999
  min_support: 5
  min_posterior: 0.9
  auto_promote_confidence: 0.0
  write_path: learned.yaml
`, "\n")
	return os.WriteFile(filepath.Join(dir, "ml.yaml"), []byte(body), 0o644)
}

func copyRules(src, dst string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		in, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), in, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func checkf(ok *bool, label string, cond bool) {
	mark := "PASS"
	if !cond {
		mark = "FAIL"
		*ok = false
	}
	fmt.Printf("  [%s] %s\n", mark, label)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
