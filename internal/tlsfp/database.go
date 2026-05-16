package tlsfp

import (
	"strings"
	"sync"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// Classification describes what we know about a fingerprint.
type Classification struct {
	Label      string // e.g. "python-requests", "chrome-120", "sqlmap"
	Category   string // "browser", "agent", "scanner", "bot", "unknown"
	Confidence int    // 0-100
}

// Database is a mutable set of known fingerprints.
type Database struct {
	mu        sync.RWMutex
	ja4Exact  map[string]Classification
	ja4Prefix map[string]Classification // match on first 10 chars
	ja3Exact  map[string]Classification
}

// NewDatabase returns an empty database. Use NewDatabaseFromDir to load rules.
func NewDatabase() *Database {
	return newEmptyDatabase()
}

// NewDatabaseFromDir returns a database populated from rulesDir (or embedded
// defaults when rulesDir is empty / the file is missing).
func NewDatabaseFromDir(rulesDir string) (*Database, error) {
	tls, err := rules.LoadTLS(rulesDir)
	if err != nil {
		return nil, err
	}
	d := newEmptyDatabase()
	d.Apply(tls)
	return d, nil
}

func newEmptyDatabase() *Database {
	return &Database{
		ja4Exact:  make(map[string]Classification),
		ja4Prefix: make(map[string]Classification),
		ja3Exact:  make(map[string]Classification),
	}
}

// Apply ingests a parsed rules.TLSFingerprints struct into the database.
func (d *Database) Apply(tls *rules.TLSFingerprints) {
	if tls == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, e := range tls.JA4Exact {
		d.ja4Exact[e.Hash] = Classification{Label: e.Label, Category: e.Category, Confidence: e.Confidence}
	}
	for _, e := range tls.JA4Prefix {
		d.ja4Prefix[e.Prefix] = Classification{Label: e.Label, Category: e.Category, Confidence: e.Confidence}
	}
	for _, e := range tls.JA3Exact {
		d.ja3Exact[e.Hash] = Classification{Label: e.Label, Category: e.Category, Confidence: e.Confidence}
	}
}

// Lookup tries exact JA4 match, then JA4 prefix, then JA3 exact.
// Returns zero Classification if unknown.
func (d *Database) Lookup(fp Fingerprint) Classification {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if c, ok := d.ja4Exact[fp.JA4]; ok {
		return c
	}
	if len(fp.JA4) >= 10 {
		if c, ok := d.ja4Prefix[fp.JA4[:10]]; ok {
			return c
		}
	}
	if c, ok := d.ja3Exact[fp.JA3]; ok {
		return c
	}
	return Classification{}
}

// LooksLikeBrowser returns true if the JA4 prefix matches any known browser
// family, used as a weaker signal when we don't have an exact hash match.
func (d *Database) LooksLikeBrowser(fp Fingerprint) bool {
	if len(fp.JA4) < 10 {
		return false
	}
	prefix := fp.JA4[:10]
	d.mu.RLock()
	defer d.mu.RUnlock()
	for p, c := range d.ja4Prefix {
		if strings.HasPrefix(prefix, p) && c.Category == "browser" {
			return true
		}
	}
	return false
}

// Add lets operators extend the database at runtime.
func (d *Database) Add(ja4 string, c Classification) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ja4Exact[ja4] = c
}
