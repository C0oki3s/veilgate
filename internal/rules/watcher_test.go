package rules

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcherDebouncedReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	w, err := NewWatcher(dir)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	w.debounce = 30 * time.Millisecond

	var calls atomic.Int64
	w.Register("sample.yaml", func() error {
		calls.Add(1)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, nil)

	// Three rapid writes must coalesce into a single reload.
	for i := 0; i < 3; i++ {
		if err := os.WriteFile(path, []byte("a: 2\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("want 1 reload, got %d", got)
	}
	ok, fail := w.Stats()
	if ok != 1 || fail != 0 {
		t.Fatalf("stats ok=%d fail=%d", ok, fail)
	}
}

func TestHolderAtomicSwap(t *testing.T) {
	type cfg struct{ N int }
	h := NewHolder(&cfg{N: 1})
	if h.Load().N != 1 {
		t.Fatalf("initial load: %d", h.Load().N)
	}
	h.Store(&cfg{N: 42})
	if h.Load().N != 42 {
		t.Fatalf("post-store load: %d", h.Load().N)
	}
}
