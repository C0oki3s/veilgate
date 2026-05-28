package detector

// Tests for the signals.yaml registry system:
//   • applySignalConfig — disable signals and override points
//   • scoreCustomSignals + matchCondition — all condition types
//   • SetSignals — precompiles path_regex, nil-safe, hot-swap
//   • LoadSignals integration — canonical signals.yaml loads cleanly

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeSignals(entries map[string]rules.SignalEntry, custom []rules.CustomSignal) *rules.Signals {
	return &rules.Signals{
		Signals:       entries,
		CustomSignals: custom,
	}
}

// ── applySignalConfig ────────────────────────────────────────────────────────

func TestApplySignalConfigDisablesSignal(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(map[string]rules.SignalEntry{
		"suspicious_ua": {Enabled: false},
	}, nil))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "sqlmap/1.7.2#stable")
	score := s.Score("10.5.0.1", r)

	for _, sig := range score.Signals {
		if sig.Name == "suspicious_ua" {
			t.Fatal("disabled signal suspicious_ua should not appear in score")
		}
	}
}

func TestApplySignalConfigOverridesPoints(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(map[string]rules.SignalEntry{
		"empty_ua": {Enabled: true, Points: 5},
	}, nil))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Del("User-Agent")
	score := s.Score("10.5.0.2", r)

	for _, sig := range score.Signals {
		if sig.Name == "empty_ua" {
			if sig.Points != 5 {
				t.Fatalf("points override not applied: got %d, want 5", sig.Points)
			}
			return
		}
	}
	t.Fatal("empty_ua signal not found")
}

func TestApplySignalConfigZeroPointsKeepsDefault(t *testing.T) {
	// points:0 in signals.yaml means "keep config.yaml default"
	s, _ := newScorer()
	defaultScore := func() int {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Del("User-Agent")
		return s.Score("10.5.0.3a", r).Total
	}()

	s.SetSignals(makeSignals(map[string]rules.SignalEntry{
		"empty_ua": {Enabled: true, Points: 0},
	}, nil))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Del("User-Agent")
	score := s.Score("10.5.0.3b", r)

	if score.Total != defaultScore {
		t.Fatalf("points:0 should keep config.yaml default, got %d want %d", score.Total, defaultScore)
	}
}

func TestApplySignalConfigSignalNotInRegistryIsEnabled(t *testing.T) {
	// A signal absent from signals.yaml must still fire with default points.
	s, _ := newScorer()
	s.SetSignals(makeSignals(map[string]rules.SignalEntry{
		// only configure one unrelated signal; empty_ua not mentioned
		"honeypot_hit": {Enabled: true},
	}, nil))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Del("User-Agent")
	score := s.Score("10.5.0.4", r)

	found := false
	for _, sig := range score.Signals {
		if sig.Name == "empty_ua" {
			found = true
		}
	}
	if !found {
		t.Fatal("signal absent from registry should default to enabled")
	}
}

func TestSetSignalsNilIsNoOp(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(nil) // must not panic
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Del("User-Agent")
	score := s.Score("10.5.0.5", r)
	if score.Total == 0 {
		t.Fatal("after nil SetSignals, scorer should still fire signals normally")
	}
}

func TestSetSignalsHotSwap(t *testing.T) {
	s, _ := newScorer()

	// First: override empty_ua to 1 point
	s.SetSignals(makeSignals(map[string]rules.SignalEntry{
		"empty_ua": {Enabled: true, Points: 1},
	}, nil))

	score1 := func() int {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Del("User-Agent")
		for _, sig := range s.Score("10.5.0.6a", r).Signals {
			if sig.Name == "empty_ua" {
				return sig.Points
			}
		}
		return -1
	}()
	if score1 != 1 {
		t.Fatalf("before hot-swap: expected 1pt, got %d", score1)
	}

	// Hot-swap to disable empty_ua entirely
	s.SetSignals(makeSignals(map[string]rules.SignalEntry{
		"empty_ua": {Enabled: false},
	}, nil))

	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Del("User-Agent")
	for _, sig := range s.Score("10.5.0.6b", r).Signals {
		if sig.Name == "empty_ua" {
			t.Fatal("after hot-swap to disabled, empty_ua must not appear")
		}
	}
}

// ── custom signals — condition types ────────────────────────────────────────

func makeCustom(name string, points int, conds ...rules.CustomSignalCondition) rules.CustomSignal {
	return rules.CustomSignal{
		Name:        name,
		Description: name + " test signal",
		Enabled:     true,
		Points:      points,
		Conditions:  conds,
	}
}

func cond(typ, val, name string) rules.CustomSignalCondition {
	return rules.CustomSignalCondition{Type: typ, Value: val, Name: name}
}

func TestCustomSignalPathPrefix(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("internal_probe", 15, cond("path_prefix", "/internal/", "")),
	}))
	r := httptest.NewRequest("GET", "/internal/debug", nil)
	if !hasSignal(s.Score("10.6.0.1", r), "internal_probe") {
		t.Fatal("path_prefix condition should fire for /internal/debug")
	}
	r2 := httptest.NewRequest("GET", "/api/public", nil)
	if hasSignal(s.Score("10.6.0.1b", r2), "internal_probe") {
		t.Fatal("path_prefix should not fire for /api/public")
	}
}

func TestCustomSignalPathContains(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("backup_probe", 10, cond("path_contains", "backup", "")),
	}))
	r := httptest.NewRequest("GET", "/files/backup.sql", nil)
	if !hasSignal(s.Score("10.6.0.2", r), "backup_probe") {
		t.Fatal("path_contains should fire for /files/backup.sql")
	}
}

func TestCustomSignalPathSuffix(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("php_probe", 10, cond("path_suffix", ".php", "")),
	}))
	r := httptest.NewRequest("GET", "/wp-login.php", nil)
	if !hasSignal(s.Score("10.6.0.3", r), "php_probe") {
		t.Fatal("path_suffix should fire for /wp-login.php")
	}
	r2 := httptest.NewRequest("GET", "/login.html", nil)
	if hasSignal(s.Score("10.6.0.3b", r2), "php_probe") {
		t.Fatal("path_suffix should not fire for .html")
	}
}

func TestCustomSignalPathRegex(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("versioned_admin", 20, cond("path_regex", `^/v[0-9]+/admin`, "")),
	}))
	r := httptest.NewRequest("GET", "/v2/admin/users", nil)
	if !hasSignal(s.Score("10.6.0.4", r), "versioned_admin") {
		t.Fatal("path_regex should fire for /v2/admin/users")
	}
	r2 := httptest.NewRequest("GET", "/api/admin", nil)
	if hasSignal(s.Score("10.6.0.4b", r2), "versioned_admin") {
		t.Fatal("path_regex should not fire for /api/admin (no version prefix)")
	}
}

func TestCustomSignalUAContains(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("curl_probe", 8, cond("ua_contains", "curl", "")),
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "curl/7.84.0")
	if !hasSignal(s.Score("10.6.0.5", r), "curl_probe") {
		t.Fatal("ua_contains should fire for curl UA")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	r2.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124")
	if hasSignal(s.Score("10.6.0.5b", r2), "curl_probe") {
		t.Fatal("ua_contains should not fire for Chrome UA")
	}
}

func TestCustomSignalHeaderPresent(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("debug_header", 12, cond("header_present", "", "X-Debug-Token")),
	}))
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Debug-Token", "anything")
	if !hasSignal(s.Score("10.6.0.6", r), "debug_header") {
		t.Fatal("header_present should fire when X-Debug-Token is set")
	}
	r2 := httptest.NewRequest("GET", "/", nil)
	if hasSignal(s.Score("10.6.0.6b", r2), "debug_header") {
		t.Fatal("header_present should not fire when header is absent")
	}
}

func TestCustomSignalHeaderValue(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("multipart_upload", 10,
			cond("header_value", "multipart", "Content-Type")),
	}))
	r := httptest.NewRequest("POST", "/upload", nil)
	r.Header.Set("Content-Type", "multipart/form-data; boundary=----WebKit")
	if !hasSignal(s.Score("10.6.0.7", r), "multipart_upload") {
		t.Fatal("header_value should fire on multipart content-type")
	}
}

func TestCustomSignalQueryContains(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("debug_mode", 8, cond("query_contains", "debug=1", "")),
	}))
	r := httptest.NewRequest("GET", "/api/data?debug=1&page=2", nil)
	if !hasSignal(s.Score("10.6.0.8", r), "debug_mode") {
		t.Fatal("query_contains should fire for debug=1 in query")
	}
}

func TestCustomSignalMethod(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("delete_probe", 15, cond("method", "DELETE", "")),
	}))
	r := httptest.NewRequest("DELETE", "/api/users/1", nil)
	if !hasSignal(s.Score("10.6.0.9", r), "delete_probe") {
		t.Fatal("method condition should fire for DELETE")
	}
	r2 := httptest.NewRequest("GET", "/api/users/1", nil)
	if hasSignal(s.Score("10.6.0.9b", r2), "delete_probe") {
		t.Fatal("method condition should not fire for GET when expecting DELETE")
	}
}

func TestCustomSignalMethodCaseInsensitive(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("put_probe", 10, cond("method", "put", "")),
	}))
	r := httptest.NewRequest("PUT", "/resource/1", nil)
	if !hasSignal(s.Score("10.6.0.10", r), "put_probe") {
		t.Fatal("method condition should be case-insensitive")
	}
}

// ── AND logic for multiple conditions ────────────────────────────────────────

func TestCustomSignalANDAllConditionsMustMatch(t *testing.T) {
	s, _ := newScorer()
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("api_write", 20,
			cond("path_prefix", "/api/v1/", ""),
			cond("method", "POST", ""),
		),
	}))

	// Both match → fires
	r1 := httptest.NewRequest("POST", "/api/v1/items", nil)
	if !hasSignal(s.Score("10.6.1.1", r1), "api_write") {
		t.Fatal("signal with all conditions matching should fire")
	}

	// Only path matches (wrong method) → does not fire
	r2 := httptest.NewRequest("GET", "/api/v1/items", nil)
	if hasSignal(s.Score("10.6.1.2", r2), "api_write") {
		t.Fatal("signal should not fire when method condition fails")
	}

	// Only method matches (wrong path) → does not fire
	r3 := httptest.NewRequest("POST", "/public/items", nil)
	if hasSignal(s.Score("10.6.1.3", r3), "api_write") {
		t.Fatal("signal should not fire when path condition fails")
	}
}

// ── disabled custom signal ────────────────────────────────────────────────────

func TestCustomSignalDisabledDoesNotFire(t *testing.T) {
	s, _ := newScorer()
	disabled := rules.CustomSignal{
		Name:        "disabled_custom",
		Enabled:     false,
		Points:      20,
		Conditions:  []rules.CustomSignalCondition{cond("path_prefix", "/", "")},
	}
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{disabled}))

	r := httptest.NewRequest("GET", "/anything", nil)
	if hasSignal(s.Score("10.6.2.1", r), "disabled_custom") {
		t.Fatal("disabled custom signal must not fire")
	}
}

func TestCustomSignalZeroPointsDoesNotFire(t *testing.T) {
	s, _ := newScorer()
	zeroPts := rules.CustomSignal{
		Name:       "zero_pts",
		Enabled:    true,
		Points:     0, // zero points → skip
		Conditions: []rules.CustomSignalCondition{cond("path_prefix", "/", "")},
	}
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{zeroPts}))

	r := httptest.NewRequest("GET", "/anything", nil)
	if hasSignal(s.Score("10.6.2.2", r), "zero_pts") {
		t.Fatal("custom signal with points:0 must not fire")
	}
}

func TestCustomSignalEmptyConditionsDoesNotFire(t *testing.T) {
	s, _ := newScorer()
	noConditions := rules.CustomSignal{
		Name:       "no_conds",
		Enabled:    true,
		Points:     20,
		Conditions: nil, // no conditions — must not fire
	}
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{noConditions}))

	r := httptest.NewRequest("GET", "/anything", nil)
	if hasSignal(s.Score("10.6.2.3", r), "no_conds") {
		t.Fatal("custom signal with no conditions must not fire")
	}
}

// ── regex precompilation ─────────────────────────────────────────────────────

func TestSetSignalsPrecompilesPathRegex(t *testing.T) {
	s, _ := newScorer()
	pat := `^/admin/[0-9]+$`
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("admin_id", 10, cond("path_regex", pat, "")),
	}))

	if len(s.customRegexes) == 0 {
		t.Fatal("SetSignals should precompile path_regex conditions")
	}
	if _, ok := s.customRegexes[pat]; !ok {
		t.Fatalf("regex %q not found in precompiled map", pat)
	}

	r := httptest.NewRequest("GET", "/admin/42", nil)
	if !hasSignal(s.Score("10.6.3.1", r), "admin_id") {
		t.Fatal("precompiled regex should match /admin/42")
	}
}

func TestSetSignalsInvalidRegexIgnored(t *testing.T) {
	s, _ := newScorer()
	// Invalid regex should not cause a panic; the signal is simply un-matchable
	s.SetSignals(makeSignals(nil, []rules.CustomSignal{
		makeCustom("bad_regex", 10, cond("path_regex", "[invalid", "")),
	}))
	r := httptest.NewRequest("GET", "/test", nil)
	_ = s.Score("10.6.3.2", r) // must not panic
}

// ── rules.Signals helpers ─────────────────────────────────────────────────────

func TestSignalsIsEnabled(t *testing.T) {
	sg := makeSignals(map[string]rules.SignalEntry{
		"sparse_headers": {Enabled: false},
		"empty_ua":       {Enabled: true},
	}, nil)

	if sg.IsEnabled("sparse_headers") {
		t.Fatal("sparse_headers should be disabled")
	}
	if !sg.IsEnabled("empty_ua") {
		t.Fatal("empty_ua should be enabled")
	}
	if !sg.IsEnabled("toolchain_hmm") {
		t.Fatal("signal not in registry should default to enabled")
	}
	if !(*new(rules.Signals)).IsEnabled("anything") {
		t.Fatal("empty Signals should return enabled for any signal")
	}
}

func TestSignalsPointsFor(t *testing.T) {
	sg := makeSignals(map[string]rules.SignalEntry{
		"empty_ua": {Enabled: true, Points: 5},
	}, nil)

	if got := sg.PointsFor("empty_ua", 20); got != 5 {
		t.Fatalf("PointsFor with override: got %d, want 5", got)
	}
	if got := sg.PointsFor("suspicious_ua", 35); got != 35 {
		t.Fatalf("PointsFor without override: got %d, want 35 (default)", got)
	}
	if got := (*new(rules.Signals)).PointsFor("anything", 99); got != 99 {
		t.Fatalf("nil Signals.PointsFor should return default: got %d", got)
	}
}

// ── LoadSignals + canonical signals.yaml integration ─────────────────────────

func TestLoadSignalsCanonicalFile(t *testing.T) {
	sg, err := rules.LoadSignals(testRulesDir)
	if err != nil {
		t.Fatalf("LoadSignals failed: %v", err)
	}
	if sg == nil {
		t.Fatal("LoadSignals returned nil for existing signals.yaml")
	}
	// Canonical file has all built-in signals with enabled:true
	required := []string{
		"empty_ua", "suspicious_ua", "sparse_headers",
		"regular_timing", "toolchain_full", "toolchain_hmm",
		"path_bruteforce", "wordlist_path", "injection_marker",
		"ip_reputation", "ip_rotation_fleet", "ua_rotation",
		"header_mutation", "schema_first", "cache_miss_anomaly",
		"no_cookie_return", "auth_probe_sequence",
		"ml_agent_score", "honeypot_hit", "canary_replay",
	}
	for _, name := range required {
		entry, ok := sg.Signals[name]
		if !ok {
			t.Errorf("signals.yaml missing entry for %q", name)
			continue
		}
		if !entry.Enabled {
			t.Errorf("signal %q should be enabled:true in canonical file", name)
		}
	}
}

func TestLoadSignalsMissingFileReturnsEmptyRegistry(t *testing.T) {
	sg, err := rules.LoadSignals(t.TempDir()) // empty dir — no signals.yaml
	if err != nil {
		t.Fatalf("LoadSignals should not error on missing file: %v", err)
	}
	if sg == nil || sg.Signals == nil {
		t.Fatal("missing signals.yaml should return empty (non-nil) registry")
	}
	// Empty registry: all signals default to enabled
	if !sg.IsEnabled("empty_ua") {
		t.Fatal("empty registry should report all signals as enabled")
	}
}

func TestLoadSignalsCustomSignalRoundTrip(t *testing.T) {
	// Write a temp signals.yaml with one custom signal and reload
	import_yaml := `
signals:
  empty_ua:
    enabled: false
custom_signals:
  - name: test_custom
    description: "unit test"
    enabled: true
    points: 13
    conditions:
      - type: path_prefix
        value: /test/
`
	dir := t.TempDir()
	if err := writeFile(dir, "signals.yaml", import_yaml); err != nil {
		t.Fatalf("write temp signals.yaml: %v", err)
	}
	sg, err := rules.LoadSignals(dir)
	if err != nil {
		t.Fatalf("LoadSignals: %v", err)
	}
	if sg.IsEnabled("empty_ua") {
		t.Fatal("empty_ua should be disabled after loading custom file")
	}
	if len(sg.CustomSignals) != 1 {
		t.Fatalf("expected 1 custom signal, got %d", len(sg.CustomSignals))
	}
	cs := sg.CustomSignals[0]
	if cs.Name != "test_custom" || cs.Points != 13 || len(cs.Conditions) != 1 {
		t.Fatalf("custom signal round-trip mismatch: %+v", cs)
	}
	if cs.Conditions[0].Type != "path_prefix" || cs.Conditions[0].Value != "/test/" {
		t.Fatalf("condition round-trip mismatch: %+v", cs.Conditions[0])
	}
}

func TestCustomSignalFiresEndToEnd(t *testing.T) {
	// Full end-to-end: load a signals.yaml with a custom signal, wire to
	// scorer, verify the custom signal appears in Score() output.
	yaml := `
custom_signals:
  - name: php_ext_probe
    description: "PHP extension on non-PHP service"
    enabled: true
    points: 10
    conditions:
      - type: path_suffix
        value: .php
`
	dir := t.TempDir()
	if err := writeFile(dir, "signals.yaml", yaml); err != nil {
		t.Fatalf("write: %v", err)
	}
	sg, _ := rules.LoadSignals(dir)

	s, _ := newScorer()
	s.SetSignals(sg)

	r := httptest.NewRequest("GET", "/wp-admin/setup.php", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124")
	score := s.Score("10.7.0.1", r)

	if !hasSignal(score, "php_ext_probe") {
		t.Fatalf("custom signal php_ext_probe should appear in score; got signals=%v", score.Signals)
	}
	for _, sig := range score.Signals {
		if sig.Name == "php_ext_probe" && sig.Points != 10 {
			t.Fatalf("custom signal points: got %d, want 10", sig.Points)
		}
	}
}

// writeFile writes content to name inside dir (test helper).
func writeFile(dir, name, content string) error {
	return os.WriteFile(dir+"/"+name, []byte(content), 0o644)
}
