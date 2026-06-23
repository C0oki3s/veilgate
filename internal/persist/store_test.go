package persist

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(Config{Path: path, QueueSize: 64, FlushInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreRoundTrip(t *testing.T) {
	s := newTestStore(t)
	s.Record(Event{
		Time: time.Now(), ClientID: "1.2.3.4", Method: "GET", Path: "/x",
		UserAgent: "curl/8.0", Score: 40, Signals: []string{"suspicious_ua"},
		Decision: "challenge", FeaturesJSON: `{"method":"GET"}`,
	})
	time.Sleep(60 * time.Millisecond) // wait for flush

	feats, err := s.RecentFeatures(10)
	if err != nil {
		t.Fatalf("recent: %v", err)
	}
	if len(feats) != 1 {
		t.Fatalf("want 1 row, got %d", len(feats))
	}
	if feats[0] == "" {
		t.Fatalf("empty features_json")
	}
}

func TestStoreRollupAggregates(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 5; i++ {
		s.RollupUpdate(RollupDelta{Feature: "ua_token", Bucket: "curl", Label: "agent"})
	}
	for i := 0; i < 3; i++ {
		s.RollupUpdate(RollupDelta{Feature: "ua_token", Bucket: "curl", Label: "human"})
	}
	time.Sleep(60 * time.Millisecond)

	rows, err := s.QueryRollup()
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 rollup, got %d", len(rows))
	}
	if rows[0].AgentCount != 5 || rows[0].HumanCount != 3 {
		t.Fatalf("counts: agent=%d human=%d", rows[0].AgentCount, rows[0].HumanCount)
	}
}

func TestStoreCandidatesUpsert(t *testing.T) {
	s := newTestStore(t)
	if err := s.UpsertCandidate(Candidate{Feature: "ua_token", Bucket: "nikto", Posterior: 0.95, Support: 300}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s.UpsertCandidate(Candidate{Feature: "ua_token", Bucket: "nikto", Posterior: 0.97, Support: 400}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	cands, err := s.ListCandidates()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(cands) != 1 {
		t.Fatalf("want 1 candidate after re-upsert, got %d", len(cands))
	}
	if cands[0].Support != 400 || cands[0].Posterior < 0.96 {
		t.Fatalf("not overwritten: %+v", cands[0])
	}
}

func TestStoreCandidatesActivePersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	cfg := Config{Path: path, QueueSize: 16, FlushInterval: 20 * time.Millisecond}

	// Round 1: insert a candidate, flip it active, close the store.
	s1, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s1.UpsertCandidate(Candidate{Feature: "ua_token", Bucket: "nikto", Posterior: 0.95, Support: 300}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := s1.SetCandidateActive("ua_token", "nikto", true); err != nil {
		t.Fatalf("set active: %v", err)
	}
	s1.Close()

	// Round 2: reopen, re-upsert with new support. Active flag must survive.
	s2, err := Open(cfg)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if err := s2.UpsertCandidate(Candidate{Feature: "ua_token", Bucket: "nikto", Posterior: 0.98, Support: 500}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	all, err := s2.ListAllCandidates()
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(all))
	}
	if !all[0].Active {
		t.Fatalf("active flag lost across restart + re-upsert: %+v", all[0])
	}
	if all[0].Support != 500 {
		t.Fatalf("support not updated: %+v", all[0])
	}
}

func TestStoreTrim(t *testing.T) {
	s := newTestStore(t)
	old := time.Now().Add(-48 * time.Hour)
	fresh := time.Now()
	s.Record(Event{Time: old, ClientID: "a", Method: "GET", Path: "/", Signals: []string{}, FeaturesJSON: "{}"})
	s.Record(Event{Time: fresh, ClientID: "b", Method: "GET", Path: "/", Signals: []string{}, FeaturesJSON: "{}"})
	time.Sleep(60 * time.Millisecond)

	n, err := s.Trim(time.Now().Add(-24 * time.Hour))
	if err != nil {
		t.Fatalf("trim: %v", err)
	}
	if n != 1 {
		t.Fatalf("want 1 trimmed, got %d", n)
	}
	feats, _ := s.RecentFeatures(10)
	if len(feats) != 1 {
		t.Fatalf("want 1 remaining, got %d", len(feats))
	}
}

func TestAnalyticsBreakdownQueries(t *testing.T) {
	s := newTestStore(t)
	now := time.Now()
	mk := func(client, ua, path, decision string, score int, sigs []string) Event {
		return Event{
			Time: now, ClientID: client, Method: "GET", Path: path,
			UserAgent: ua, Score: score, Signals: sigs, Decision: decision,
			FeaturesJSON: "{}",
		}
	}
	// scanner A: heavy sqlmap, tarpitted
	for i := 0; i < 5; i++ {
		s.Record(mk("10.0.0.1", "sqlmap/1.7", "/admin.php", "tarpit", 90, []string{"scanner_ua", "path_php"}))
	}
	// scanner B: lighter
	for i := 0; i < 2; i++ {
		s.Record(mk("10.0.0.2", "nuclei", "/.git/config", "challenge", 55, []string{"path_git"}))
	}
	// clean client, no signals
	s.Record(mk("10.0.0.3", "Mozilla/5.0", "/", "observe", 0, nil))
	time.Sleep(80 * time.Millisecond)

	since := now.Add(-time.Hour)

	clients, err := s.TopClients(since, 10)
	if err != nil {
		t.Fatalf("TopClients: %v", err)
	}
	if len(clients) == 0 || clients[0].ClientID != "10.0.0.1" || clients[0].Count != 5 || clients[0].Tarpit != 5 {
		t.Fatalf("TopClients unexpected: %+v", clients)
	}

	uas, err := s.TopUserAgents(since, 10)
	if err != nil {
		t.Fatalf("TopUserAgents: %v", err)
	}
	if len(uas) == 0 || uas[0].Label != "sqlmap/1.7" || uas[0].Count != 5 {
		t.Fatalf("TopUserAgents unexpected: %+v", uas)
	}

	sigs, err := s.TopSignals(since, 10)
	if err != nil {
		t.Fatalf("TopSignals: %v", err)
	}
	got := map[string]int{}
	for _, sc := range sigs {
		got[sc.Label] = sc.Count
	}
	if got["scanner_ua"] != 5 || got["path_php"] != 5 || got["path_git"] != 2 {
		t.Fatalf("TopSignals unexpected: %+v", sigs)
	}
}
