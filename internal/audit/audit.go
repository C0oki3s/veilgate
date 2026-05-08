// Package audit provides an append-only hash-chained audit log for
// operator actions. Every entry carries the SHA-256 of the previous
// entry, so an external auditor can detect tampering without trusting
// the server clock or the host filesystem.
//
// Two backends ship: a JSONL file writer (the default) and a
// SQLite-table writer that piggybacks on the existing persist.Store.
// Both implement the same Writer interface so callers don't care.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry is one audit-log row. The runtime fills PrevHash and Hash
// from the chain — callers populate everything else.
type Entry struct {
	Time     time.Time         `json:"ts"`
	Actor    string            `json:"actor"`            // user / api-key / "system"
	Action   string            `json:"action"`           // canonical verb, e.g. "config.reload"
	Target   string            `json:"target,omitempty"` // resource the action touched
	Outcome  string            `json:"outcome"`          // "ok" | "error"
	Detail   string            `json:"detail,omitempty"` // human-readable note
	Meta     map[string]string `json:"meta,omitempty"`   // structured context, optional
	PrevHash string            `json:"prev_hash"`
	Hash     string            `json:"hash"`
}

// Writer is what the rest of the codebase calls. nil-Writer is a valid
// no-op so callers can wire it unconditionally.
type Writer interface {
	Append(e Entry) error
}

// Logger is the canonical entry point: a thin wrapper that fills in
// timestamps + hash chain and forwards to one or more backends.
type Logger struct {
	mu       sync.Mutex
	writers  []Writer
	prevHash string
}

// NewLogger constructs a logger over zero-or-more backends. Pass nil
// backends and you get a no-op logger — useful for tests.
func NewLogger(writers ...Writer) *Logger {
	out := make([]Writer, 0, len(writers))
	for _, w := range writers {
		if w != nil {
			out = append(out, w)
		}
	}
	return &Logger{writers: out}
}

// SetSeedHash lets the caller pre-populate the chain head from a prior
// run (read from disk on startup). Without seeding, every restart begins
// a fresh chain — that's still tamper-detectable, just not contiguous.
func (l *Logger) SetSeedHash(h string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.prevHash = h
	l.mu.Unlock()
}

// Log records one audit entry. Best-effort: a backend error is returned
// but the chain head still advances so downstream readers can detect
// the gap.
func (l *Logger) Log(e Entry) error {
	if l == nil || len(l.writers) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Outcome == "" {
		e.Outcome = "ok"
	}
	e.PrevHash = l.prevHash
	e.Hash = chainHash(e)
	l.prevHash = e.Hash

	var firstErr error
	for _, w := range l.writers {
		if err := w.Append(e); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// chainHash returns SHA-256 over the canonical JSON of the entry's
// content fields plus the previous hash. Excluding Hash itself keeps
// the function pure on its inputs.
func chainHash(e Entry) string {
	core := struct {
		Time     time.Time         `json:"ts"`
		Actor    string            `json:"actor"`
		Action   string            `json:"action"`
		Target   string            `json:"target,omitempty"`
		Outcome  string            `json:"outcome"`
		Detail   string            `json:"detail,omitempty"`
		Meta     map[string]string `json:"meta,omitempty"`
		PrevHash string            `json:"prev_hash"`
	}{e.Time.UTC(), e.Actor, e.Action, e.Target, e.Outcome, e.Detail, e.Meta, e.PrevHash}
	b, _ := json.Marshal(core)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileWriter writes JSONL entries to a hash-chained append-only file.
// The file is opened with O_APPEND and chmod 0600; rotated rolls don't
// happen here — operators ship the file to a SIEM.
type FileWriter struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileWriter opens the audit log at path. Creates parent dirs at
// 0700 and the file at 0600. Returns the last-known hash as the
// second value so callers can seed Logger to keep the chain
// contiguous across restarts.
func NewFileWriter(path string) (*FileWriter, string, error) {
	if path == "" {
		return nil, "", nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, "", err
	}
	_ = os.Chmod(path, 0o600)
	last := readLastHash(path)
	return &FileWriter{f: f}, last, nil
}

// Append writes one entry as a JSON line.
func (w *FileWriter) Append(e Entry) error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = w.f.Write(b)
	return err
}

// Close flushes the file.
func (w *FileWriter) Close() error {
	if w == nil || w.f == nil {
		return nil
	}
	return w.f.Close()
}

// readLastHash scans the file for the last full line and returns its
// `hash` field. Returns "" when the file is empty or unreadable — a
// fresh chain is fine, just not contiguous with the prior run.
func readLastHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	// Walk backwards for the last newline-terminated line.
	end := len(data)
	if data[end-1] == '\n' {
		end--
	}
	start := end
	for start > 0 && data[start-1] != '\n' {
		start--
	}
	if start >= end {
		return ""
	}
	var e Entry
	if err := json.Unmarshal(data[start:end], &e); err != nil {
		return ""
	}
	return e.Hash
}

// SQLWriter is implemented by callers that want audit entries also
// committed to an audit_log SQLite table. The persist package supplies
// the actual implementation — this type-only declaration lets the
// audit package compile without importing persist.
type SQLWriter interface {
	AppendAudit(ts time.Time, actor, action, target, outcome, detail, meta, prevHash, hash string) error
}

// SQLBackend wraps a SQLWriter so it satisfies audit.Writer.
type SQLBackend struct{ DB SQLWriter }

func (s *SQLBackend) Append(e Entry) error {
	if s == nil || s.DB == nil {
		return nil
	}
	meta := ""
	if len(e.Meta) > 0 {
		b, _ := json.Marshal(e.Meta)
		meta = string(b)
	}
	return s.DB.AppendAudit(e.Time, e.Actor, e.Action, e.Target, e.Outcome, e.Detail, meta, e.PrevHash, e.Hash)
}

// FmtMeta is a small convenience for callers that want to embed a
// structured context map without depending on this package's types.
func FmtMeta(kv ...string) map[string]string {
	if len(kv) == 0 || len(kv)%2 != 0 {
		return nil
	}
	m := make(map[string]string, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

// Errorf formats an outcome/detail pair for an error path.
func Errorf(format string, args ...interface{}) (string, string) {
	return "error", fmt.Sprintf(format, args...)
}
