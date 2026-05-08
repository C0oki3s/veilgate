// Command replay re-scores every event in a persisted events.db with the
// current detector rules and prints a before/after breakdown. Use this to
// validate that newly-added rules actually catch the tools you found in
// production, without having to re-run the tools against a live proxy.
//
//   go build -o replay.exe ./cmd/replay && ./replay.exe -db data/events.db
package main

import (
	"database/sql"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"

	_ "modernc.org/sqlite"

	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/rules"
)

func main() {
	dbPath := flag.String("db", "data/events.db", "path to events.db produced by veilgate")
	rulesDir := flag.String("rules", "rules", "rules directory to load (empty = embedded defaults)")
	limit := flag.Int("limit", 0, "only replay first N rows (0 = all)")
	agent := flag.Int("agent-threshold", 40, "score at or above which a row is labeled agent")
	flag.Parse()

	db, err := sql.Open("sqlite", "file:"+*dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	fatal(err, "open db")
	defer db.Close()

	tr := detector.NewTracker(90)
	honeypots := []string{"/admin-panel-v2", "/api/internal/debug", "/.git/config",
		"/.env.backup", "/wp-admin-old", "/phpmyadmin-backup", "/api/v3/legacy-auth"}
	// No trusted_ips — we want every stored row re-scored.
	s := detector.NewScorer(tr, honeypots, nil)
	d, err := rules.LoadDetector(*rulesDir)
	fatal(err, "load detector rules")
	s.SetRules(d)

	q := `SELECT ts, client_id, method, path, user_agent, signals_json, score
	      FROM events ORDER BY id`
	if *limit > 0 {
		q += fmt.Sprintf(" LIMIT %d", *limit)
	}
	rows, err := db.Query(q)
	fatal(err, "query events")
	defer rows.Close()

	var (
		total          int
		oldFired       int
		newFired       int
		newCatchesOld0 int
		signalCount    = map[string]int{}
	)

	for rows.Next() {
		var ts, cid, method, path, ua, oldSigs string
		var oldScore int
		if err := rows.Scan(&ts, &cid, &method, &path, &ua, &oldSigs, &oldScore); err != nil {
			fatal(err, "scan row")
		}
		u, _ := url.Parse(path)
		if u == nil {
			u = &url.URL{Path: path}
		}
		r := &http.Request{Method: method, URL: u, Header: http.Header{}, Host: "replay.local"}
		r.Header.Set("User-Agent", ua)
		// NOTE: we lost the original request headers when persisting (only UA
		// is stored), so header-based injection_marker hits under-count here.
		// The replay still captures path/query/UA rules, which is the
		// majority of what we added.

		score := s.Score(cid, r)
		total++
		if oldScore >= *agent {
			oldFired++
		}
		if score.Total >= *agent {
			newFired++
			if oldScore == 0 {
				newCatchesOld0++
			}
		}
		for _, sig := range score.Signals {
			signalCount[sig.Name]++
		}
	}
	fatal(rows.Err(), "iterate rows")

	fmt.Println("=== Replay summary ===")
	fmt.Printf("rows replayed:                    %d\n", total)
	fmt.Printf("rows agent-labeled in stored:     %d  (stored_score >= %d)\n", oldFired, *agent)
	fmt.Printf("rows agent-labeled after patch:   %d  (delta %+d)\n", newFired, newFired-oldFired)
	fmt.Printf("  of which were stored_score==0:  %d   <- newly caught false negatives\n", newCatchesOld0)

	fmt.Println("\nsignal firing counts (replay):")
	type kv struct {
		k string
		v int
	}
	kvs := make([]kv, 0, len(signalCount))
	for k, v := range signalCount {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v })
	for _, p := range kvs {
		fmt.Printf("  %-24s %d\n", p.k, p.v)
	}

	fmt.Println("\nper-tool recall @ threshold:")
	for _, t := range toolProbes() {
		caught, seen := toolRecall(db, s, *agent, t.like)
		pct := 0.0
		if seen > 0 {
			pct = 100 * float64(caught) / float64(seen)
		}
		fmt.Printf("  %-14s caught %d / %d  (%.1f%%)\n", t.name, caught, seen, pct)
	}
}

type toolProbe struct {
	name string
	like string // SQLite LIKE pattern; empty = exact-empty UA
}

func toolProbes() []toolProbe {
	return []toolProbe{
		{"nikto", "%Nikto%"},
		{"sqlmap", "%sqlmap%"},
		{"nuclei-UA", "%Nuclei%"},
		{"python-reqs", "%python-requests%"},
		{"go-http", "%Go-http-client%"},
		{"empty-ua", ""},
	}
}

func toolRecall(db *sql.DB, s *detector.Scorer, threshold int, like string) (int, int) {
	var q string
	var args []any
	if like == "" {
		q = "SELECT method, path, user_agent, client_id FROM events WHERE user_agent = ''"
	} else {
		q = "SELECT method, path, user_agent, client_id FROM events WHERE user_agent LIKE ?"
		args = []any{like}
	}
	rows, err := db.Query(q, args...)
	if err != nil {
		return 0, 0
	}
	defer rows.Close()
	var caught, seen int
	for rows.Next() {
		var method, path, ua, cid string
		if err := rows.Scan(&method, &path, &ua, &cid); err != nil {
			continue
		}
		u, _ := url.Parse(path)
		if u == nil {
			u = &url.URL{Path: path}
		}
		r := &http.Request{Method: method, URL: u, Header: http.Header{}, Host: "replay.local"}
		r.Header.Set("User-Agent", ua)
		score := s.Score(cid, r)
		seen++
		if score.Total >= threshold {
			caught++
		}
	}
	return caught, seen
}

func fatal(err error, ctx string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, ctx+":", err)
		os.Exit(1)
	}
}
