package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// CaptureEvent is one JSONL line written per request. This is the raw
// training-data feed: each line carries the features needed to rebuild a
// labeled dataset later (agent vs human, per session).
type CaptureEvent struct {
	Time      time.Time `json:"ts"`
	Client    string    `json:"client"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	UserAgent string    `json:"ua"`
	Referer   string    `json:"referer,omitempty"`
	Accept    string    `json:"accept,omitempty"`
	AcceptLan string    `json:"accept_language,omitempty"`
	AcceptEnc string    `json:"accept_encoding,omitempty"`
	SecFetch  string    `json:"sec_fetch_site,omitempty"`
	JA3       string    `json:"ja3,omitempty"`
	JA4       string    `json:"ja4,omitempty"`
	Score     int       `json:"score"`
	Signals   []string  `json:"signals"` // signal names only
	Decision  string    `json:"decision"`
}

// ScrubRule is one regex-replace pair applied to the encoded JSONL line
// before write. Cheap; the proxy already pays the JSON-encode cost so a
// few extra regex passes per line are negligible.
type ScrubRule struct {
	Pattern *regexp.Regexp
	Replace string
}

// CaptureOptions extends NewCapture with retention, scrub, and POSIX
// permissions. Zero-valued options keep the legacy behaviour.
type CaptureOptions struct {
	// MaxBytes caps the live file before rotation to <path>.1. 0 falls
	// back to MaxMB or the legacy 100 MiB default.
	MaxMB int

	// RetentionHours: the janitor deletes the file (and rotated siblings)
	// once their mtime is older than this. 0 disables time-based pruning.
	RetentionHours int

	// FileMode is the chmod applied to the live file and rotated files.
	// 0 = use the package default 0o600. Older configs that relied on
	// 0644 should explicitly set this.
	FileMode os.FileMode

	// Scrub is a list of regex patterns applied to each JSONL line
	// before it is written. Use it for obvious-PII redactions (Bearer
	// tokens, password=… in query strings) you don't want on disk.
	Scrub []ScrubRule
}

// Capture is a size-capped JSONL writer. Rotates to <path>.1 on overflow.
// Safe for concurrent Write calls.
type Capture struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	mode     os.FileMode
	scrub    []ScrubRule
	retention time.Duration

	f       *os.File
	written int64
}

// NewCapture opens (or creates) the capture file with the legacy default
// settings (0644, no retention, no scrub). Most callers should now use
// NewCaptureWithOptions instead.
func NewCapture(path string, maxMB int) (*Capture, error) {
	return NewCaptureWithOptions(path, CaptureOptions{MaxMB: maxMB})
}

// NewCaptureWithOptions is the canonical constructor. A nil Capture is
// valid and silently no-ops, so callers can wire it unconditionally.
func NewCaptureWithOptions(path string, opts CaptureOptions) (*Capture, error) {
	if path == "" {
		return nil, nil
	}
	mode := opts.FileMode
	if mode == 0 {
		mode = 0o600
	}
	maxMB := opts.MaxMB
	if maxMB <= 0 {
		maxMB = 100
	}
	// Parent dir 0700 — only the proxy user should walk the directory.
	// We don't ratchet down an existing dir's mode, just ensure new ones
	// are tight by default.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("capture mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, mode)
	if err != nil {
		return nil, fmt.Errorf("capture open: %w", err)
	}
	// Clamp permissions on every reopen — protects against operators
	// who manually chmod'd the live file.
	_ = os.Chmod(path, mode)

	info, _ := f.Stat()
	var size int64
	if info != nil {
		size = info.Size()
	}
	c := &Capture{
		path:     path,
		maxBytes: int64(maxMB) * 1024 * 1024,
		mode:     mode,
		scrub:    opts.Scrub,
		f:        f,
		written:  size,
	}
	if opts.RetentionHours > 0 {
		c.retention = time.Duration(opts.RetentionHours) * time.Hour
	}
	return c, nil
}

// Write appends one JSONL line. Rotates when the file exceeds maxBytes.
func (c *Capture) Write(ev CaptureEvent) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.written >= c.maxBytes {
		c.rotateLocked()
	}
	// Encode then scrub. Encoding by hand (rather than json.Encoder) so
	// we can inspect and mutate the line before it touches disk.
	raw, err := json.Marshal(ev)
	if err != nil {
		return
	}
	for _, rule := range c.scrub {
		raw = rule.Pattern.ReplaceAll(raw, []byte(rule.Replace))
	}
	raw = append(raw, '\n')
	n, err := c.f.Write(raw)
	if err != nil {
		return
	}
	c.written += int64(n)
}

func (c *Capture) rotateLocked() {
	_ = c.f.Close()
	_ = os.Rename(c.path, c.path+".1")
	// After rename, clamp the rotated file's mode too — useful when the
	// process previously ran with a looser umask.
	_ = os.Chmod(c.path+".1", c.mode)
	f, err := os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, c.mode)
	if err != nil {
		return
	}
	c.f = f
	c.written = 0
	_ = os.Chmod(c.path, c.mode)
}

// Close flushes and closes the file.
func (c *Capture) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f != nil {
		return c.f.Close()
	}
	return nil
}

// RunJanitor blocks until ctx is done, deleting rotated capture files
// older than RetentionHours and truncating the live file when it would
// otherwise outlive retention. Safe to call from a single background
// goroutine; running multiple instances against the same capture file
// is undefined.
//
// onError is invoked with any os errors so the caller can surface them
// via its preferred logger; nil discards.
func (c *Capture) RunJanitor(ctx context.Context, every time.Duration, onError func(error)) {
	if c == nil || c.retention == 0 {
		return
	}
	if every <= 0 {
		every = time.Hour
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.sweep(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

func (c *Capture) sweep() error {
	cutoff := time.Now().Add(-c.retention)
	dir := filepath.Dir(c.path)
	base := filepath.Base(c.path)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if name != base && !looksLikeRotated(name, base) {
			continue
		}
		full := filepath.Join(dir, name)
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(cutoff) {
			continue
		}
		// Live file: truncate in place so we don't fight with the writer.
		if name == base {
			c.mu.Lock()
			_ = c.f.Truncate(0)
			_, _ = c.f.Seek(0, 0)
			c.written = 0
			c.mu.Unlock()
			continue
		}
		_ = os.Remove(full)
	}
	return nil
}

func looksLikeRotated(name, base string) bool {
	// Matches the rotation scheme used by rotateLocked: <base>.1
	if len(name) <= len(base)+1 {
		return false
	}
	if name[:len(base)] != base {
		return false
	}
	if name[len(base)] != '.' {
		return false
	}
	for _, r := range name[len(base)+1:] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CompileScrubRules turns operator-supplied (regex, replace) pairs into
// runtime ScrubRules. Invalid regexes are skipped — a bad pattern in a
// hot-reloaded YAML must not take down the proxy.
func CompileScrubRules(specs []struct{ Pattern, Replace string }) []ScrubRule {
	out := make([]ScrubRule, 0, len(specs))
	for _, s := range specs {
		if s.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(s.Pattern)
		if err != nil {
			continue
		}
		out = append(out, ScrubRule{Pattern: re, Replace: s.Replace})
	}
	return out
}
