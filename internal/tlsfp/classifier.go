package tlsfp

// Classifier is a thin adapter around a Store + Database that satisfies
// the detector.TLSLookup interface.
type Classifier struct {
	store *Store
	db    *Database
}

func NewClassifier(store *Store, db *Database) *Classifier {
	return &Classifier{store: store, db: db}
}

// Classify looks up the fingerprint for remoteAddr, then consults the database.
// If no fingerprint exists (plain HTTP or handshake not captured), returns ok=false.
// If fingerprint exists but is unknown AND doesn't look like a browser, returns
// category "unknown" so the scorer can still give partial points.
func (c *Classifier) Classify(remoteAddr string) (label, category string, confidence int, ok bool) {
	fp, found := c.store.Get(remoteAddr)
	if !found {
		return "", "", 0, false
	}
	cls := c.db.Lookup(fp)
	if cls.Label != "" {
		return cls.Label, cls.Category, cls.Confidence, true
	}
	// No match in DB. Use prefix heuristic.
	if c.db.LooksLikeBrowser(fp) {
		return "unknown-browser-like", "browser", 40, true
	}
	return "unknown", "unknown", 50, true
}
