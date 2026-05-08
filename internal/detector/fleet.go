package detector

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

// FleetTracker groups distinct client IPs by a behavioural fingerprint
// so the scorer can detect one attacker rotating through a pool of
// public IPs (Tor, VPN, residential-proxy, AWS spot fleet, etc).
//
// Fingerprint = sha1(ua_family | ja4_prefix | header_set_id | method).
// Each fingerprint keeps a rolling set of IPs seen inside the window.
// When the set grows past a threshold, the scorer attaches an
// ip_rotation_fleet signal to *every* member IP's subsequent requests.
//
// The tracker is intentionally separate from the per-client Tracker so
// it can be reset, GC'd, and queried independently without contending
// on the per-request hot path.
type FleetTracker struct {
	mu              sync.Mutex
	fingerprints    map[string]*fleetEntry
	window          time.Duration
	maxFingerprints int
}

type fleetEntry struct {
	FirstSeen time.Time
	LastSeen  time.Time
	// IPs maps client IP → last-seen time. Old IPs are evicted on
	// every access so the entry's len() reflects the *current*
	// rotation population, not all-time cumulative.
	IPs map[string]time.Time
}

// NewFleetTracker returns a tracker with the given rolling window
// (seconds). Pass 0 for a sane default of 10 minutes.
func NewFleetTracker(windowSeconds int, maxFingerprints int) *FleetTracker {
	if windowSeconds <= 0 {
		windowSeconds = 600
	}
	if maxFingerprints <= 0 {
		maxFingerprints = 20000
	}
	return &FleetTracker{
		fingerprints:    make(map[string]*fleetEntry),
		window:          time.Duration(windowSeconds) * time.Second,
		maxFingerprints: maxFingerprints,
	}
}

// Observe records that clientIP produced a request with the given
// fingerprint components, and returns the current distinct-IP count
// inside the window for that fingerprint.
//
// Callers build the fingerprint from whatever components discriminate
// one attacker-class from another while staying stable across IP
// rotation. UA family tokens + JA4 prefix + header-set id is a sweet
// spot: an attacker rotating IPs can't change those cheaply.
func (ft *FleetTracker) Observe(clientIP, uaFamily, ja4Prefix, headerSetID, method string, now time.Time) (fingerprint string, distinct int) {
	fp := fleetFingerprint(uaFamily, ja4Prefix, headerSetID, method)
	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Cheap eviction: when the map outgrows maxFingerprints, drop any
	// entry whose LastSeen is beyond the window. We avoid running a
	// full-table scan on every call; only pay the cost when pressured.
	if len(ft.fingerprints) >= ft.maxFingerprints {
		cutoff := now.Add(-ft.window)
		for k, e := range ft.fingerprints {
			if e.LastSeen.Before(cutoff) {
				delete(ft.fingerprints, k)
			}
		}
	}

	e, ok := ft.fingerprints[fp]
	if !ok {
		e = &fleetEntry{FirstSeen: now, IPs: make(map[string]time.Time)}
		ft.fingerprints[fp] = e
	}
	e.LastSeen = now
	e.IPs[clientIP] = now

	// Evict stale IPs within this entry.
	cutoff := now.Add(-ft.window)
	for ip, ts := range e.IPs {
		if ts.Before(cutoff) {
			delete(e.IPs, ip)
		}
	}
	return fp, len(e.IPs)
}

// GC removes fingerprint entries that have been idle longer than maxIdle.
// Call periodically from the same GC goroutine that prunes the per-client
// Tracker.
func (ft *FleetTracker) GC(maxIdle time.Duration) {
	cutoff := time.Now().Add(-maxIdle)
	ft.mu.Lock()
	defer ft.mu.Unlock()
	for k, e := range ft.fingerprints {
		if e.LastSeen.Before(cutoff) {
			delete(ft.fingerprints, k)
		}
	}
}

// Snapshot returns (fingerprint → distinct-IP count) for the current
// state. Exported for metrics + debugging; not used on the hot path.
func (ft *FleetTracker) Snapshot() map[string]int {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	out := make(map[string]int, len(ft.fingerprints))
	for k, e := range ft.fingerprints {
		out[k] = len(e.IPs)
	}
	return out
}

// fleetFingerprint is the stable hash used as the map key. Lowercases
// and trims each component so a trivial casing change in UA tokens
// doesn't split one attacker's traffic into two buckets.
func fleetFingerprint(uaFamily, ja4Prefix, headerSetID, method string) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(uaFamily)),
		strings.ToLower(strings.TrimSpace(ja4Prefix)),
		strings.ToLower(strings.TrimSpace(headerSetID)),
		strings.ToUpper(strings.TrimSpace(method)),
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:6]) // 12 hex chars — collision-safe enough for 20k fingerprints
}

// UAFamilyFromUA reduces a full User-Agent string to a stable family
// token set — "python-requests", "nikto", "chrome" — so that benign
// version drift across a proxy pool doesn't fragment the fingerprint.
// Empty input returns "<empty>".
func UAFamilyFromUA(ua string) string {
	ua = strings.ToLower(ua)
	if ua == "" {
		return "<empty>"
	}
	// Match the first recognised family token; fall back to the first
	// two alphabetic words.
	for _, fam := range uaFamilies {
		if strings.Contains(ua, fam) {
			return fam
		}
	}
	fields := strings.FieldsFunc(ua, func(r rune) bool {
		switch r {
		case ' ', '/', '(', ')', ',', ';', '.', '-':
			return true
		}
		return false
	})
	out := fields[:0]
	for _, f := range fields {
		if len(f) < 2 {
			continue
		}
		// Drop pure-digit tokens.
		allDigit := true
		for _, r := range f {
			if r < '0' || r > '9' {
				allDigit = false
				break
			}
		}
		if allDigit {
			continue
		}
		out = append(out, f)
		if len(out) == 2 {
			break
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return "<unknown>"
	}
	return strings.Join(out, "_")
}

var uaFamilies = []string{
	"python-requests", "python-urllib", "python-httpx", "aiohttp",
	"go-http-client", "okhttp", "reqwest", "libwww-perl",
	"curl/", "wget/", "httpie",
	"nikto", "nmap", "sqlmap", "nuclei", "wpscan", "wapiti",
	"ffuf", "gobuster", "dirsearch", "feroxbuster", "dirbuster",
	"subfinder", "amass", "httpx", "katana", "gospider",
	"arjun", "wafw00f", "trufflehog", "gitleaks",
	"zaproxy", "zap/", "burp", "caido", "xsstrike", "commix",
	"headlesschrome", "puppeteer", "playwright", "pentestgpt", "strix",
	"chrome", "firefox", "safari", "edg",
}
