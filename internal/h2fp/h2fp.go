// Package h2fp computes an Akamai-style HTTP/2 SETTINGS fingerprint and
// classifies it against a small built-in database. Distinct from JA4 —
// JA4 hashes the TLS ClientHello; h2fp hashes the H2 SETTINGS frame
// preamble + window-size + the order of pseudo-headers. The two together
// catch a much wider class of agents than either alone.
//
// The package is deliberately small: it does *not* parse the H2 wire
// format itself (Go's http2 stack hides the SETTINGS frame from us).
// Instead, callers register a fingerprint they captured during the
// connection-establishment hook (e.g. via http2.Server.ConnState or a
// custom http2.Framer wrapper). This keeps h2fp a pure data layer that
// the detector can read on every request without owning the wire.
package h2fp

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Settings is the captured H2 SETTINGS frame contents from one client
// connection. Field names mirror the H2 spec; missing fields stay 0.
type Settings struct {
	HeaderTableSize      uint32
	EnablePush           uint32
	MaxConcurrentStreams uint32
	InitialWindowSize    uint32
	MaxFrameSize         uint32
	MaxHeaderListSize    uint32
	// Order is the verbatim order in which the SETTINGS appeared on the
	// wire. Real browsers emit a stable order; libs often emit a
	// different one. Each element is one of the SETTINGS identifiers as
	// a uint16 (e.g. 0x0001 for HEADER_TABLE_SIZE).
	Order []uint16
	// Pseudo is the order of pseudo-headers on the first request frame
	// (":method", ":scheme", ":authority", ":path"). Browsers vary;
	// this is a strong tell.
	Pseudo []string
	// WindowUpdate is the WINDOW_UPDATE increment the client sent
	// immediately after the SETTINGS frame (a peer-level flow control
	// hint). 0 means "not observed".
	WindowUpdate uint32
}

// Fingerprint is a stable 12-char hex hash over the captured settings.
// Cheap to compute, small enough to store on every connection.
func (s Settings) Fingerprint() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d|%d|%d|%d|%d|%d|",
		s.HeaderTableSize, s.EnablePush, s.MaxConcurrentStreams,
		s.InitialWindowSize, s.MaxFrameSize, s.MaxHeaderListSize)
	for _, o := range s.Order {
		fmt.Fprintf(&b, "%04x.", o)
	}
	b.WriteByte('|')
	b.WriteString(strings.Join(s.Pseudo, ","))
	fmt.Fprintf(&b, "|w=%d", s.WindowUpdate)
	sum := sha1.Sum([]byte(b.String()))
	return hex.EncodeToString(sum[:6])
}

// Match is the classifier output for one fingerprint.
type Match struct {
	Label      string // e.g. "go-http-client", "python-httpx"
	Category   string // "browser" | "agent" | "scanner" | "bot" | "unknown"
	Confidence int    // 0..100
}

// Database is the known-fingerprint table. Operators ship overrides via
// rules/h2_fingerprints.yaml (parsed by the rules package; this package
// stays IO-free).
type Database struct {
	mu      sync.RWMutex
	exact   map[string]Match
	pseudo  map[string]Match // exact match on Pseudo joined by ","
}

// NewDatabase returns an empty database. Apply() populates it.
func NewDatabase() *Database {
	return &Database{
		exact:  make(map[string]Match),
		pseudo: make(map[string]Match),
	}
}

// Entry is one row from rules/h2_fingerprints.yaml.
type Entry struct {
	Hash       string
	Pseudo     string
	Label      string
	Category   string
	Confidence int
}

// Apply replaces the database contents. Safe to call from a hot-reload
// goroutine; readers see the swap atomically.
func (d *Database) Apply(rows []Entry) {
	exact := make(map[string]Match, len(rows))
	pseudo := make(map[string]Match, len(rows))
	for _, r := range rows {
		m := Match{Label: r.Label, Category: r.Category, Confidence: r.Confidence}
		if r.Hash != "" {
			exact[r.Hash] = m
		}
		if r.Pseudo != "" {
			pseudo[r.Pseudo] = m
		}
	}
	d.mu.Lock()
	d.exact = exact
	d.pseudo = pseudo
	d.mu.Unlock()
}

// Classify resolves a Settings against the database. Exact-hash match
// wins; pseudo-header order is a fallback signal with lower confidence.
func (d *Database) Classify(s Settings) (Match, bool) {
	if d == nil {
		return Match{}, false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if m, ok := d.exact[s.Fingerprint()]; ok {
		return m, true
	}
	if len(s.Pseudo) > 0 {
		key := strings.Join(s.Pseudo, ",")
		if m, ok := d.pseudo[key]; ok {
			// Pseudo-only match — drop confidence since it's weaker.
			if m.Confidence > 60 {
				m.Confidence = 60
			}
			return m, true
		}
	}
	return Match{}, false
}

// Store keeps the captured Settings keyed by remote address with a TTL.
// Mirrors the layout of internal/tlsfp.Store so the wiring code in the
// proxy stays symmetric.
type Store struct {
	mu      sync.RWMutex
	entries map[string]storeEntry
	ttl     time.Duration
}

type storeEntry struct {
	S  Settings
	At time.Time
}

// NewStore returns a Store with the given TTL. Pass 0 for the default
// 10 minutes.
func NewStore(ttl time.Duration) *Store {
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	return &Store{entries: make(map[string]storeEntry), ttl: ttl}
}

// Put records a Settings observation for a remote address.
func (s *Store) Put(remote string, settings Settings) {
	s.mu.Lock()
	s.entries[remote] = storeEntry{S: settings, At: time.Now()}
	s.mu.Unlock()
}

// Get returns the Settings for a remote address, or (Settings{}, false)
// when none was captured or the entry is stale.
func (s *Store) Get(remote string) (Settings, bool) {
	s.mu.RLock()
	e, ok := s.entries[remote]
	s.mu.RUnlock()
	if !ok || time.Since(e.At) > s.ttl {
		return Settings{}, false
	}
	return e.S, true
}

// GC drops stale entries. Call on a timer.
func (s *Store) GC() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.entries {
		if now.Sub(v.At) > s.ttl {
			delete(s.entries, k)
		}
	}
}

// Snapshot returns a read-only copy of every captured remote → fp pair.
// Used by the metrics exporter; not on the hot path.
func (s *Store) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.entries))
	for k, v := range s.entries {
		out[k] = v.S.Fingerprint()
	}
	return out
}

// Classifier glues a Store to a Database — the detector consults this
// once per request via the Classify(remote) call.
type Classifier struct {
	store *Store
	db    *Database
}

// NewClassifier returns a Classifier. Both arguments may be nil; in that
// case Classify returns ok=false unconditionally.
func NewClassifier(s *Store, db *Database) *Classifier {
	return &Classifier{store: s, db: db}
}

// Classify implements the contract the detector expects: given a
// remote address, return (label, category, confidence, ok).
func (c *Classifier) Classify(remote string) (string, string, int, bool) {
	if c == nil || c.store == nil || c.db == nil {
		return "", "", 0, false
	}
	s, ok := c.store.Get(remote)
	if !ok {
		return "", "", 0, false
	}
	m, ok := c.db.Classify(s)
	if !ok {
		// No exact match — but if the SETTINGS frame is suspiciously
		// minimal (header_table_size 0, no SETTINGS apart from window
		// size, etc.) flag it as non-browser unknown.
		if looksMinimal(s) {
			return "minimal_h2", "unknown", 50, true
		}
		return "", "", 0, false
	}
	return m.Label, m.Category, m.Confidence, true
}

// looksMinimal returns true when the captured SETTINGS frame looks
// like a library default rather than a browser. Browsers consistently
// negotiate non-default values for header_table_size, max_concurrent_streams,
// and initial_window_size; libraries often leave them at protocol defaults.
func looksMinimal(s Settings) bool {
	if s.HeaderTableSize == 0 && s.MaxConcurrentStreams == 0 && s.InitialWindowSize == 0 {
		return true
	}
	return false
}

// SortedOrder returns the SETTINGS identifiers in their captured order,
// rendered as a comma-separated hex string. Useful when logging or
// emitting a metric.
func SortedOrder(s Settings) string {
	if len(s.Order) == 0 {
		return ""
	}
	parts := make([]string, len(s.Order))
	for i, o := range s.Order {
		parts[i] = fmt.Sprintf("%04x", o)
	}
	return strings.Join(parts, ",")
}

// stableJoin returns sort-stable join of a string slice — used by
// pseudo-header matching when an operator chooses to ignore order.
func stableJoin(in []string) string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return strings.Join(out, ",")
}
