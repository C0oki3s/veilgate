package admin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is one audit event.
type AuditEntry struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	IP     string `json:"ip"`
	Action string `json:"action"`
	Detail string `json:"detail"`
	OK     bool   `json:"ok"`
}

// AuditStats are summary counters.
type AuditStats struct {
	Total        int
	Failures     int
	Logins       int
	ConfigSaves  int
	RuleSaves    int
	SignalSaves  int
	OpenAPISaves int
}

// AuditLogger writes structured audit events.
// When db is set, events go to SQLite (primary) and JSONL (secondary).
// When db is nil, events go to JSONL only.
type AuditLogger struct {
	db   *AdminDB // nil = JSONL-only
	path string   // JSONL path; empty = skip file
	mu   sync.Mutex
	f    *os.File
}

// NewAuditLogger opens (or creates) the JSONL audit log file.
// Pass db to enable SQLite write-through.
func NewAuditLogger(path string, db *AdminDB) (*AuditLogger, error) {
	al := &AuditLogger{db: db, path: path}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("audit dir: %w", err)
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, fmt.Errorf("audit open: %w", err)
		}
		al.f = f
	}
	return al, nil
}

// Log writes one audit entry to both DB (if set) and JSONL file (if set).
func (a *AuditLogger) Log(r *http.Request, action, detail string, ok bool) {
	entry := AuditEntry{
		Time:   time.Now().UTC().Format(time.RFC3339),
		User:   requestUser(r),
		IP:     remoteIP(r),
		Action: action,
		Detail: detail,
		OK:     ok,
	}

	// DB write (primary)
	if a.db != nil {
		a.db.WriteAudit(entry.Time, entry.User, entry.IP, action, detail, ok)
	}

	// JSONL write (secondary / grep-able backup)
	if a.f != nil {
		if b, err := json.Marshal(entry); err == nil {
			a.mu.Lock()
			_, _ = a.f.Write(append(b, '\n'))
			a.mu.Unlock()
		}
	}
}

// Read returns up to n most-recent audit entries (newest first).
// Prefers DB when available; falls back to JSONL.
func (a *AuditLogger) Read(n int) ([]AuditEntry, error) {
	if a.db != nil {
		return a.db.ReadAudit(n)
	}
	return a.readJSONL(n)
}

// Stats returns summary statistics.
func (a *AuditLogger) Stats() AuditStats {
	if a.db != nil {
		return a.db.AuditStatsDB()
	}
	entries, _ := a.readJSONL(0)
	return computeStats(entries)
}

func (a *AuditLogger) readJSONL(n int) ([]AuditEntry, error) {
	if a.path == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.Open(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e AuditEntry
		if json.Unmarshal(scanner.Bytes(), &e) == nil {
			entries = append(entries, e)
		}
	}
	// Reverse: newest first
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	if n > 0 && len(entries) > n {
		entries = entries[:n]
	}
	return entries, scanner.Err()
}

func computeStats(entries []AuditEntry) AuditStats {
	var s AuditStats
	s.Total = len(entries)
	for _, e := range entries {
		if !e.OK {
			s.Failures++
		}
		switch e.Action {
		case "login":
			s.Logins++
		case "settings.save":
			s.ConfigSaves++
		case "rule.save":
			s.RuleSaves++
		case "signals.save":
			s.SignalSaves++
		case "openapi.import":
			s.OpenAPISaves++
		}
	}
	return s
}

// ── Request log reader ────────────────────────────────────────────────────

// RequestLogEntry is one line from the JSONL capture file.
type RequestLogEntry struct {
	Level    string    `json:"level"`
	Time     time.Time `json:"time"`
	Client   string    `json:"client"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Score    int       `json:"score"`
	Decision string    `json:"decision"`
	Threat   string    `json:"threat_level"`
}

// ReadRequestLogs tails up to n lines from a JSONL capture file.
func ReadRequestLogs(path string, n int) ([]RequestLogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, _ := f.Stat()
	size := info.Size()
	seekBack := int64(n * 300)
	if seekBack > size {
		seekBack = size
	}
	if _, err := f.Seek(-seekBack, io.SeekEnd); err == nil {
		// Skip partial first line after seek
		scanner := bufio.NewScanner(f)
		scanner.Scan()
	}
	f.Seek(-seekBack, io.SeekEnd) //nolint:errcheck

	var entries []RequestLogEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var e RequestLogEntry
		if json.Unmarshal(scanner.Bytes(), &e) == nil && e.Client != "" {
			entries = append(entries, e)
		}
	}
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries, nil
}

// ── Context helpers ────────────────────────────────────────────────────────

type ctxKeyUser struct{}

func requestUser(r *http.Request) string {
	if u, ok := r.Context().Value(ctxKeyUser{}).(string); ok && u != "" {
		return u
	}
	return "admin"
}

// ctxUser returns the authenticated username from the request context.
func ctxUser(r *http.Request) string { return requestUser(r) }

func remoteIP(r *http.Request) string {
	// Prefer X-Forwarded-For when running behind a proxy
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for i := len(xff) - 1; i >= 0; i-- {
			if xff[i] == ',' {
				return xff[i+1:]
			}
		}
		return xff
	}
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
