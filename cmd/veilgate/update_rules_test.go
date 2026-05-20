package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveUpdateRulesTargetDirUsesExplicitDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".veilgate", "rules")
	if got := resolveUpdateRulesTargetDir("~/.veilgate/rules", "ignored.yaml"); got != want {
		t.Fatalf("resolveUpdateRulesTargetDir() = %q, want %q", got, want)
	}
}

func TestResolveUpdateRulesTargetDirUsesConfigRulesDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cfg := filepath.Join(t.TempDir(), "veilgate.yaml")
	if err := os.WriteFile(cfg, []byte("rules_dir: \"~/.veilgate/rules\"\n"), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	want := filepath.Join(home, ".veilgate", "rules")
	if got := resolveUpdateRulesTargetDir("", cfg); got != want {
		t.Fatalf("resolveUpdateRulesTargetDir() = %q, want %q", got, want)
	}
}

func TestResolveUpdateRulesTargetDirDefaultsToHomeRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".veilgate", "rules")
	if got := resolveUpdateRulesTargetDir("", filepath.Join(t.TempDir(), "missing.yaml")); got != want {
		t.Fatalf("resolveUpdateRulesTargetDir() = %q, want %q", got, want)
	}
}

func TestDownloadAcceptHeaderUsesGitHubMediaTypeForAPIZipball(t *testing.T) {
	rawURL := rulesAPIBase + "/zipball/v0.1.0"
	if got := downloadAcceptHeader(rawURL); got != "application/vnd.github+json" {
		t.Fatalf("downloadAcceptHeader() = %q, want GitHub JSON media type", got)
	}
}

func TestDownloadAcceptHeaderUsesOctetStreamForReleaseAsset(t *testing.T) {
	rawURL := rulesHTMLBase + "/releases/download/v0.1.0/rules.zip"
	if got := downloadAcceptHeader(rawURL); got != "application/octet-stream" {
		t.Fatalf("downloadAcceptHeader() = %q, want octet-stream", got)
	}
}
