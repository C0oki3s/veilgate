package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDetectorEmptyDirErrors(t *testing.T) {
	_, err := LoadDetector("")
	if err == nil {
		t.Fatal("LoadDetector with empty dir should return an error")
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

func TestLoadDetectorMissingFileReturnsZero(t *testing.T) {
	dir := t.TempDir() // empty dir, no detector.yaml or detector/ subdir
	d, err := LoadDetector(dir)
	if err != nil {
		t.Fatalf("missing root file should return zero-value detector, not error: %v", err)
	}
	if d == nil {
		t.Fatal("expected non-nil zero-value detector")
	}
}

func TestLoadTLSEmptyDirErrors(t *testing.T) {
	_, err := LoadTLS("")
	if err == nil {
		t.Fatal("LoadTLS with empty dir should return an error")
	}
}

func TestLoadPayloadsEmptyDirErrors(t *testing.T) {
	_, err := LoadPayloads("")
	if err == nil {
		t.Fatal("LoadPayloads with empty dir should return an error")
	}
}
