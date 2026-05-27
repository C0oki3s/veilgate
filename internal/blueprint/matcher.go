// Package blueprint loads an operator-supplied API route map (OpenAPI 3.x,
// Swagger 2.0, or a simple custom YAML/JSON list) and exposes a fast in-memory
// Matcher used by the detector to fire the api_blueprint_miss signal.
package blueprint

import (
	"strings"
	"sync"
)

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
// so subsequent requests for the same path pay only a sync.Map read — no
// string splitting or route scanning.
//
// The cache is per-Matcher instance, so hot-reload (SetBlueprint installs a
// new *Matcher) automatically starts with an empty cache.
type Matcher struct {
	routes    []route
	namespace map[string]struct{} // set of known first-segment literals
	cache     sync.Map            // path string → pathEntry
}

// Lookup returns (inNamespace, matched) for path. Results are cached after
// the first evaluation; call this instead of InNamespace + Matches separately
// to guarantee a single cache round-trip per request.
func (m *Matcher) Lookup(path string) (inNamespace, matched bool) {
	if v, ok := m.cache.Load(path); ok {
		e := v.(pathEntry)
		return e.inNamespace, e.matched
	}
	inNamespace = m.inNamespace(path)
	if inNamespace {
		matched = m.matches(path)
	}
	m.cache.Store(path, pathEntry{inNamespace: inNamespace, matched: matched})
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
