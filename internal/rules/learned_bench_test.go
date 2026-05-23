package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// rulesDir resolves the repo-root rules directory relative to this test file.
func rulesDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// internal/rules/ -> ../../veilgate-rules/ after the community rules were
	// split into github.com/C0oki3s/veilgate-rules. Fall back to ../../rules/
	// for older checkouts and downstream packagers.
	root := filepath.Join(filepath.Dir(file), "..", "..")
	if dir := filepath.Join(root, "veilgate-rules"); dirExists(dir) {
		return dir
	}
	return filepath.Join(root, "rules")
}

// TestLoadLearnedSubdirTree verifies that LoadLearned walks the nested
// learned/ subdirectory tree and returns candidates from every community file.
func TestLoadLearnedSubdirTree(t *testing.T) {
	dir := rulesDir(t)
	got, err := LoadLearned(dir)
	if err != nil {
		t.Fatalf("LoadLearned: %v", err)
	}
	if len(got.Candidates) == 0 {
		t.Fatal("expected at least one candidate, got 0")
	}

	// Count active community candidates (those with an id like VG-*)
	var active, withID int
	for _, c := range got.Candidates {
		if c.Active {
			active++
		}
		if c.ID != "" {
			withID++
		}
	}
	t.Logf("total candidates=%d  active=%d  with_id=%d", len(got.Candidates), active, withID)

	if active == 0 {
		t.Error("expected at least one active candidate from community rules")
	}
	if withID == 0 {
		t.Error("expected at least one candidate with an ID field from community rules")
	}
}

// BenchmarkLoadLearned measures the time to parse learned.yaml + the full
// learned/ subdirectory tree (both sources merged).
func BenchmarkLoadLearned(b *testing.B) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		b.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	dir := filepath.Join(root, "veilgate-rules")
	if !dirExists(dir) {
		dir = filepath.Join(root, "rules")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := LoadLearned(dir); err != nil {
			b.Fatalf("LoadLearned: %v", err)
		}
	}
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
