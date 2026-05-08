package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDetectorEmbedded(t *testing.T) {
	d, err := LoadDetector("")
	if err != nil {
		t.Fatalf("LoadDetector with empty dir should succeed via embed: %v", err)
	}
	if len(d.SuspiciousUserAgents.Substrings) == 0 {
		t.Fatal("embedded detector rules have empty UA list")
	}
	if d.Timing.MinEvents == 0 {
		t.Fatal("embedded detector rules have zero min_events")
	}
	if d.SuspiciousUserAgents.Points == 0 {
		t.Fatal("embedded detector rules have zero UA points")
	}
}

func TestLoadDetectorOverride(t *testing.T) {
	dir := t.TempDir()
	content := `
suspicious_user_agents:
  points: 99
  substrings:
    - custom-scanner
browser_headers:
  hints: [X-Test]
  tiers:
    - missing: 1
      points: 7
empty_user_agent:
  points: 20
toolchain:
  recon_paths: [/a]
  probe_paths: [/b]
  exploit_markers: ["xx"]
  points:
    full: 5
    partial: 3
timing:
  min_events: 2
  min_mean_seconds: 0.5
  max_mean_seconds: 5
  strict_cv_max: 0.1
  strict_points: 1
  loose_cv_max: 0.2
  loose_points: 1
`
	if err := os.WriteFile(filepath.Join(dir, "detector.yaml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := LoadDetector(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d.SuspiciousUserAgents.Points != 99 {
		t.Errorf("expected override points=99, got %d", d.SuspiciousUserAgents.Points)
	}
	if len(d.SuspiciousUserAgents.Substrings) != 1 || d.SuspiciousUserAgents.Substrings[0] != "custom-scanner" {
		t.Errorf("expected override UA list, got %v", d.SuspiciousUserAgents.Substrings)
	}
}

func TestLoadDetectorMissingFileFallsBack(t *testing.T) {
	dir := t.TempDir() // empty dir, no detector.yaml
	d, err := LoadDetector(dir)
	if err != nil {
		t.Fatalf("missing file should fall back to embed, got error: %v", err)
	}
	if len(d.SuspiciousUserAgents.Substrings) == 0 {
		t.Fatal("fallback to embedded should populate UA list")
	}
}

func TestLoadTLSEmbedded(t *testing.T) {
	tls, err := LoadTLS("")
	if err != nil {
		t.Fatal(err)
	}
	if len(tls.JA4Exact) == 0 {
		t.Fatal("embedded TLS db has no JA4 entries")
	}
	if len(tls.JA4Prefix) == 0 {
		t.Fatal("embedded TLS db has no JA4 prefix entries")
	}
}

func TestLoadPayloadsEmbedded(t *testing.T) {
	p, err := LoadPayloads("")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Termination) == 0 {
		t.Fatal("embedded payloads missing termination category")
	}
	if len(p.CostBomb) == 0 {
		t.Fatal("embedded payloads missing cost_bomb category")
	}
	if p.CostBomb[0].Generator != "log_burst" {
		t.Errorf("expected cost_bomb[0].generator=log_burst, got %q", p.CostBomb[0].Generator)
	}
}
