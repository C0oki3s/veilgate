package rules

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watcher watches the rules directory for changes and invokes a per-file
// reload callback. Callbacks are expected to do their own YAML parsing
// and to swap an atomic.Pointer holding the loaded value, so readers on
// the hot path never take a lock.
//
// A rebuild-and-swap is debounced (default 500ms) so editors that write
// in two flush cycles don't trigger two reloads.
//
// Subdirectory watching: AddSubdir registers an additional directory to
// watch. Any .yaml/.yml change inside that directory fires a named handler
// registered via Register. This is used for the learned/ subdirectory so
// community rule files hot-reload the learned rules set.
type Watcher struct {
	dir      string
	fsw      *fsnotify.Watcher
	handlers map[string]func() error
	debounce time.Duration

	// subdirMap maps a cleaned subdirectory absolute path → handler name.
	// When an fsnotify event arrives from a subdirectory, the event is
	// dispatched to the named handler instead of looking up by basename.
	subdirMap map[string]string

	pendingMu sync.Mutex
	pending   map[string]*time.Timer
	seq       map[string]uint64
	stats     WatcherStats
}

// WatcherStats exposes reload metrics. All fields atomic.
type WatcherStats struct {
	ReloadOK   atomic.Uint64
	ReloadFail atomic.Uint64
}

// NewWatcher constructs a watcher on dir. Returns a nil watcher when
// dir is empty so callers can use embedded defaults without conditional
// wiring.
func NewWatcher(dir string) (*Watcher, error) {
	if dir == "" {
		return nil, nil
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	if err := fsw.Add(dir); err != nil {
		fsw.Close()
		return nil, err
	}
	return &Watcher{
		dir:       dir,
		fsw:       fsw,
		handlers:  make(map[string]func() error),
		debounce:  500 * time.Millisecond,
		subdirMap: make(map[string]string),
		pending:   make(map[string]*time.Timer),
		seq:       make(map[string]uint64),
	}, nil
}

// Register attaches a reload callback to a filename (not path). Callbacks
// run on a dedicated goroutine; long work is the caller's problem.
func (w *Watcher) Register(filename string, reload func() error) {
	if w == nil {
		return
	}
	w.handlers[filename] = reload
}

// AddSubdir watches an additional subdirectory. Any .yaml or .yml file
// change inside subdir fires the handler registered under handlerName.
// This is the mechanism for community learned/ rules: any file added or
// edited inside learned/ re-triggers the "learned.yaml" reload callback.
// A nil watcher is a no-op.
func (w *Watcher) AddSubdir(subdir, handlerName string) error {
	if w == nil {
		return nil
	}
	if err := w.fsw.Add(subdir); err != nil {
		return err
	}
	w.subdirMap[filepath.Clean(subdir)] = handlerName
	return nil
}

// Stats returns a snapshot of reload counters.
func (w *Watcher) Stats() (ok, fail uint64) {
	if w == nil {
		return 0, 0
	}
	return w.stats.ReloadOK.Load(), w.stats.ReloadFail.Load()
}

// Run blocks until ctx is done, dispatching reload events.
func (w *Watcher) Run(ctx context.Context, onError func(filename string, err error)) {
	if w == nil {
		return
	}
	defer w.fsw.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return
			}
			// Only act on writes/creates/renames — ignore chmod.
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			// Determine which handler name to fire.
			// First check whether the event came from a watched subdirectory;
			// if so, map to the registered handler name regardless of basename.
			name := filepath.Base(ev.Name)
			if handler, ok := w.subdirMap[filepath.Clean(filepath.Dir(ev.Name))]; ok {
				// Only act on YAML files inside the subdirectory.
				ext := strings.ToLower(filepath.Ext(ev.Name))
				if ext == ".yaml" || ext == ".yml" {
					name = handler
				} else {
					continue
				}
			}
			if _, ok := w.handlers[name]; !ok {
				continue
			}
			w.schedule(name, onError)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return
			}
			if onError != nil {
				onError("", err)
			}
		}
	}
}

func (w *Watcher) schedule(name string, onError func(string, error)) {
	w.pendingMu.Lock()
	w.seq[name]++
	seq := w.seq[name]
	if t, ok := w.pending[name]; ok {
		t.Stop()
	}
	w.pending[name] = time.AfterFunc(w.debounce, func() {
		w.pendingMu.Lock()
		if w.seq[name] != seq {
			w.pendingMu.Unlock()
			return
		}
		delete(w.pending, name)
		w.pendingMu.Unlock()

		if err := w.handlers[name](); err != nil {
			w.stats.ReloadFail.Add(1)
			if onError != nil {
				onError(name, err)
			}
			return
		}
		w.stats.ReloadOK.Add(1)
	})
	w.pendingMu.Unlock()
}

// Holder[T] wraps an atomic.Pointer with a typed Load/Store API. Every
// rule subsystem that wants hot-reload stores its parsed config in a
// Holder and reads via Load() on the hot path — no mutex.
type Holder[T any] struct {
	p atomic.Pointer[T]
}

func NewHolder[T any](initial *T) *Holder[T] {
	h := &Holder[T]{}
	h.p.Store(initial)
	return h
}

func (h *Holder[T]) Load() *T {
	if h == nil {
		return nil
	}
	return h.p.Load()
}

func (h *Holder[T]) Store(v *T) {
	if h == nil || v == nil {
		return
	}
	h.p.Store(v)
}
