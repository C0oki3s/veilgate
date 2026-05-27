// Package blueprint loads an operator-supplied API route map (OpenAPI 3.x,
// Swagger 2.0, or a simple custom YAML/JSON list) and exposes a fast in-memory
// Matcher used by the detector to fire the api_blueprint_miss signal.
package blueprint

import (
	"strings"
	"sync"
	"sync/atomic"
)

// maxCacheEntries caps the path result cache. Without a bound, an attacker
// sending requests with millions of unique path values (e.g. random UUIDs)
// would grow the sync.Map unboundedly and exhaust heap memory. At the cap the
// cache silently stops accepting new entries — lookups continue to work
// correctly, just without caching (graceful degradation, not a correctness
// failure).
const maxCacheEntries = 4096

// seg is one segment of a route path. isParam is true for {placeholder}
// segments, which match any non-empty value.
type seg struct {
	literal string
	isParam bool
}

type route struct {
	segs []seg
}

// pathEntry is the cached result of a single path lookup.
type pathEntry struct {
	inNamespace bool
	matched     bool
}

// Matcher holds a compiled set of API routes derived from a blueprint file.
// After the first request to a given path the result is memoized in cache,
// so subsequent requests pay only a sync.Map read — no string splitting or
// route scanning.
//
// The cache is bounded at maxCacheEntries to prevent memory exhaustion under
// path-flooding attacks. The cache is per-Matcher, so hot-reload (SetBlueprint
// installs a new *Matcher) starts with an empty cache automatically.
type Matcher struct {
	routes    []route
	namespace map[string]struct{} // set of known first-segment literals
	cache     sync.Map            // normalised path → pathEntry
	cacheLen  atomic.Int64        // count of entries stored; soft cap guard
}

// Lookup returns (inNamespace, matched) for path. Results are cached after
// the first evaluation. Call this instead of InNamespace + Matches separately
// to guarantee a single cache round-trip per request.
func (m *Matcher) Lookup(path string) (inNamespace, matched bool) {
	// Normalise the cache key so that "/api/users" and "/api/users/" share one
	// entry — splitPath strips trailing slashes so their match results are
	// identical anyway.
	key := strings.Trim(path, "/")

	if v, ok := m.cache.Load(key); ok {
		e := v.(pathEntry)
		return e.inNamespace, e.matched
	}

	inNamespace = m.inNamespace(path)
	if inNamespace {
		matched = m.matches(path)
	}
	entry := pathEntry{inNamespace: inNamespace, matched: matched}

	// Pre-claim a slot with an atomic increment. This eliminates the
	// check-then-store race: multiple goroutines each get a distinct Add
	// result, so only those whose result is ≤ maxCacheEntries proceed to
	// store. Goroutines over the cap release immediately with Add(-1).
	// If LoadOrStore finds the key already stored by a concurrent goroutine
	// that won the same slot race, we also release the pre-claimed slot so
	// cacheLen always equals the actual number of entries in cache.
	if m.cacheLen.Add(1) <= maxCacheEntries {
		if _, loaded := m.cache.LoadOrStore(key, entry); loaded {
			m.cacheLen.Add(-1) // concurrent store of same key; release slot
		}
	} else {
		m.cacheLen.Add(-1) // at cap; release slot
	}

	return inNamespace, matched
}

// Matches returns true if path matches any route in the blueprint.
// Prefer Lookup when you need both InNamespace and Matches in one call.
func (m *Matcher) Matches(path string) bool {
	_, matched := m.Lookup(path)
	return matched
}

// InNamespace returns true if the first path segment belongs to one of the
// namespaces derived from the blueprint (e.g. "api", "v1").
// Prefer Lookup when you need both InNamespace and Matches in one call.
func (m *Matcher) InNamespace(path string) bool {
	inNS, _ := m.Lookup(path)
	return inNS
}

// IsEmpty reports whether no routes were loaded.
func (m *Matcher) IsEmpty() bool { return len(m.routes) == 0 }

// RouteCount returns the total number of compiled routes.
func (m *Matcher) RouteCount() int { return len(m.routes) }

// CacheLen returns the number of entries currently in the path result cache.
// Exposed for testing; not part of the stable API.
func (m *Matcher) CacheLen() int { return int(m.cacheLen.Load()) }

// inNamespace is the uncached namespace check used by Lookup.
func (m *Matcher) inNamespace(path string) bool {
	parts := splitPath(path)
	if len(parts) == 0 {
		return false
	}
	_, ok := m.namespace[strings.ToLower(parts[0])]
	return ok
}

// matches is the uncached route scan used by Lookup.
func (m *Matcher) matches(path string) bool {
	parts := splitPath(path)
	for _, r := range m.routes {
		if len(r.segs) != len(parts) {
			continue
		}
		ok := true
		for i, s := range r.segs {
			if !s.isParam && s.literal != strings.ToLower(parts[i]) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// splitPath splits a URL path into non-empty segments, stripping leading and
// trailing slashes. Returns nil for paths that reduce to "".
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

func parseRoute(path string) route {
	parts := splitPath(path)
	segs := make([]seg, len(parts))
	for i, p := range parts {
		if len(p) > 2 && p[0] == '{' && p[len(p)-1] == '}' {
			segs[i] = seg{isParam: true}
		} else {
			segs[i] = seg{literal: strings.ToLower(p)}
		}
	}
	return route{segs: segs}
}

func buildMatcher(paths []string) *Matcher {
	m := &Matcher{namespace: make(map[string]struct{})}
	for _, p := range paths {
		r := parseRoute(p)
		if len(r.segs) == 0 {
			continue
		}
		m.routes = append(m.routes, r)
		if !r.segs[0].isParam {
			m.namespace[r.segs[0].literal] = struct{}{}
		}
	}
	return m
}
