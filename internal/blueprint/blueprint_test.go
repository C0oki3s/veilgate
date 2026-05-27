package blueprint

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ── Matcher correctness ───────────────────────────────────────────────────────

func TestMatcherExactRoute(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/posts"})
	if !m.Matches("/api/users") {
		t.Error("exact route /api/users should match")
	}
	if !m.Matches("/api/posts") {
		t.Error("exact route /api/posts should match")
	}
}

func TestMatcherPathParam(t *testing.T) {
	m := buildMatcher([]string{"/api/users/{id}", "/api/posts/{id}/comments"})
	if !m.Matches("/api/users/42") {
		t.Error("{id} segment should match numeric ID")
	}
	if !m.Matches("/api/users/abc-def-123") {
		t.Error("{id} segment should match string ID")
	}
	if !m.Matches("/api/posts/99/comments") {
		t.Error("nested path param should match")
	}
	if m.Matches("/api/users/42/extra") {
		t.Error("extra segment must not match")
	}
}

func TestMatcherCaseInsensitive(t *testing.T) {
	m := buildMatcher([]string{"/API/Users"})
	if !m.Matches("/api/users") {
		t.Error("matching should be case-insensitive")
	}
	if !m.Matches("/API/USERS") {
		t.Error("matching should be case-insensitive")
	}
}

func TestMatcherNoMatch(t *testing.T) {
	m := buildMatcher([]string{"/api/users"})
	if m.Matches("/api/unknown") {
		t.Error("/api/unknown must not match when not in blueprint")
	}
	if m.Matches("/other/path") {
		t.Error("/other/path must not match")
	}
}

func TestMatcherInNamespace(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/posts/{id}", "/v1/status"})
	if !m.InNamespace("/api/anything") {
		t.Error("/api/* should be in namespace")
	}
	if !m.InNamespace("/v1/anything") {
		t.Error("/v1/* should be in namespace")
	}
	if m.InNamespace("/other/path") {
		t.Error("/other is not a blueprint namespace")
	}
	if m.InNamespace("/") {
		t.Error("root path has no first segment")
	}
}

func TestMatcherIsEmpty(t *testing.T) {
	m := buildMatcher(nil)
	if !m.IsEmpty() {
		t.Error("empty routes should be IsEmpty")
	}
	m2 := buildMatcher([]string{"/api/users"})
	if m2.IsEmpty() {
		t.Error("non-empty routes should not be IsEmpty")
	}
}

func TestMatcherRouteCount(t *testing.T) {
	m := buildMatcher([]string{"/a", "/b", "/c"})
	if m.RouteCount() != 3 {
		t.Errorf("expected 3 routes, got %d", m.RouteCount())
	}
}

// ── Cache correctness ─────────────────────────────────────────────────────────

func TestCacheHitReturnsSameResult(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/users/{id}"})

	inNS1, matched1 := m.Lookup("/api/users")
	if !inNS1 || !matched1 {
		t.Fatalf("first lookup: inNS=%v matched=%v, want true/true", inNS1, matched1)
	}
	// Second call must return identical values from cache.
	inNS2, matched2 := m.Lookup("/api/users")
	if inNS1 != inNS2 || matched1 != matched2 {
		t.Error("cached lookup returned different result than first lookup")
	}
}

func TestCacheMissPath(t *testing.T) {
	m := buildMatcher([]string{"/api/users"})
	inNS, matched := m.Lookup("/api/unknown")
	if !inNS {
		t.Error("path in namespace should set inNS=true even on miss")
	}
	if matched {
		t.Error("unknown path should not be matched")
	}
}

func TestCacheOutOfNamespace(t *testing.T) {
	m := buildMatcher([]string{"/api/users"})
	inNS, matched := m.Lookup("/other/path")
	if inNS || matched {
		t.Errorf("out-of-namespace: got inNS=%v matched=%v, want false/false", inNS, matched)
	}
}

// TestCacheNormalisesTrailingSlash verifies that "/api/users" and
// "/api/users/" share a single cache entry — they have the same normalised key
// after Trim("/") so the route scan runs only once.
func TestCacheNormalisesTrailingSlash(t *testing.T) {
	m := buildMatcher([]string{"/api/users"})

	inNS1, matched1 := m.Lookup("/api/users")
	lenAfterFirst := m.CacheLen()

	inNS2, matched2 := m.Lookup("/api/users/")
	lenAfterSecond := m.CacheLen()

	if inNS1 != inNS2 || matched1 != matched2 {
		t.Errorf("trailing-slash variant gave different result: %v/%v vs %v/%v",
			inNS1, matched1, inNS2, matched2)
	}
	if lenAfterSecond != lenAfterFirst {
		t.Errorf("trailing-slash path should reuse the same cache entry (len %d → %d)",
			lenAfterFirst, lenAfterSecond)
	}
}

// ── Cache security / DoS ──────────────────────────────────────────────────────

// TestCacheBoundedUnderFlood verifies that an attacker sending requests with
// millions of unique path values cannot grow the cache past maxCacheEntries.
// After the cap, lookups must still return correct results (graceful
// degradation, not a panic or incorrect answer).
func TestCacheBoundedUnderFlood(t *testing.T) {
	m := buildMatcher([]string{"/api/users/{id}"})

	flood := maxCacheEntries * 3 // well past the cap
	for i := 0; i < flood; i++ {
		path := fmt.Sprintf("/api/users/%d", i)
		inNS, matched := m.Lookup(path)
		if !inNS {
			t.Fatalf("path %s should be in namespace", path)
		}
		if !matched {
			t.Fatalf("path %s should match /api/users/{id}", path)
		}
	}

	got := m.CacheLen()
	if got > maxCacheEntries {
		t.Errorf("cache grew to %d entries; must not exceed %d", got, maxCacheEntries)
	}
}

// TestCacheBoundedNonAPIFlood simulates an attacker flooding paths that are
// out of namespace — common in reconnaissance scans. The cache must cap and
// results must remain correct (always false/false for these paths).
func TestCacheBoundedNonAPIFlood(t *testing.T) {
	m := buildMatcher([]string{"/api/status"})

	for i := 0; i < maxCacheEntries*2; i++ {
		path := fmt.Sprintf("/scan/path%d", i)
		inNS, matched := m.Lookup(path)
		if inNS || matched {
			t.Fatalf("out-of-namespace path %s should return false/false", path)
		}
	}

	if got := m.CacheLen(); got > maxCacheEntries {
		t.Errorf("cache grew to %d entries under non-API flood; must not exceed %d", got, maxCacheEntries)
	}
}

// TestCacheConcurrentRace runs many goroutines calling Lookup on the same and
// on distinct paths simultaneously. The -race detector must find no data races,
// and every result must be correct.
func TestCacheConcurrentRace(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/users/{id}", "/api/posts"})

	paths := []string{
		"/api/users",
		"/api/users/42",
		"/api/posts",
		"/api/unknown",
		"/other",
	}
	expected := map[string][2]bool{
		"/api/users":    {true, true},
		"/api/users/42": {true, true},
		"/api/posts":    {true, true},
		"/api/unknown":  {true, false},
		"/other":        {false, false},
	}

	const workers = 50
	const iters = 200
	var wg sync.WaitGroup
	errs := make(chan string, workers*iters)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				p := paths[i%len(paths)]
				inNS, matched := m.Lookup(p)
				want := expected[p]
				if inNS != want[0] || matched != want[1] {
					errs <- fmt.Sprintf("path=%s: got inNS=%v matched=%v, want %v/%v",
						p, inNS, matched, want[0], want[1])
				}
			}
		}()
	}
	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
	}
}

// TestCacheConcurrentFloodAndRead simulates a mixed workload: half the
// goroutines flood with unique paths (attack traffic), half query known-good
// paths (legitimate traffic). Legitimate results must stay correct throughout.
func TestCacheConcurrentFloodAndRead(t *testing.T) {
	m := buildMatcher([]string{"/api/users", "/api/users/{id}"})

	var wg sync.WaitGroup
	errs := make(chan string, 1000)

	// Goroutines flooding unique paths to exhaust the cache.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		start := i * 500
		go func(base int) {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				m.Lookup(fmt.Sprintf("/scan/%d", base+j))
			}
		}(start)
	}

	// Goroutines reading legitimate paths concurrently with the flood.
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				inNS, matched := m.Lookup("/api/users")
				if !inNS || !matched {
					errs <- fmt.Sprintf("legitimate path corrupted: inNS=%v matched=%v", inNS, matched)
				}
				inNS2, matched2 := m.Lookup("/api/users/99")
				if !inNS2 || !matched2 {
					errs <- fmt.Sprintf("legitimate param path corrupted: inNS=%v matched=%v", inNS2, matched2)
				}
			}
		}()
	}

	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
	}
	if got := m.CacheLen(); got > maxCacheEntries {
		t.Errorf("cache exceeded cap during flood: %d > %d", got, maxCacheEntries)
	}
}

// TestCacheCounterAccuracy checks that CacheLen never over-counts when many
// goroutines race to store the same previously-unseen path. LoadOrStore
// guarantees only one goroutine wins the store, so the counter must end at 1
// for a single unique path regardless of concurrency.
func TestCacheCounterAccuracy(t *testing.T) {
	m := buildMatcher([]string{"/api/users"})

	const goroutines = 200
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Lookup("/api/users") // all racing on the same unseen path
		}()
	}
	wg.Wait()

	if got := m.CacheLen(); got != 1 {
		t.Errorf("cache counter = %d after %d concurrent stores of same path; want 1",
			got, goroutines)
	}
}

// ── Loader tests ──────────────────────────────────────────────────────────────

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("expected nil Matcher when no file present")
	}
}

func TestLoadCustomRoutesYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api_blueprint.yaml", `
routes:
  - /api/users
  - /api/users/{id}
  - /api/posts
`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if m.RouteCount() != 3 {
		t.Errorf("expected 3 routes, got %d", m.RouteCount())
	}
	if !m.Matches("/api/users") {
		t.Error("should match /api/users")
	}
	if !m.Matches("/api/users/123") {
		t.Error("should match /api/users/123 via path param")
	}
}

func TestLoadOpenAPI3YAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", `
openapi: "3.0.0"
info:
  title: Test API
  version: "1.0"
paths:
  /api/health: {}
  /api/users: {}
  /api/users/{id}: {}
`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if m.RouteCount() != 3 {
		t.Errorf("expected 3 routes, got %d", m.RouteCount())
	}
	if !m.Matches("/api/health") {
		t.Error("should match /api/health")
	}
}

func TestLoadSwagger2WithBasePath(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "openapi.yaml", `
swagger: "2.0"
basePath: /v1
paths:
  /users: {}
  /users/{id}: {}
  /status: {}
`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if !m.Matches("/v1/users") {
		t.Error("should match /v1/users with basePath prepended")
	}
	if !m.Matches("/v1/users/42") {
		t.Error("should match /v1/users/42 via path param")
	}
	if !m.InNamespace("/v1/anything") {
		t.Error("/v1 should be in namespace")
	}
}

func TestLoadCandidateFileOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api_blueprint.yaml", `routes: [/priority/route]`)
	writeFile(t, dir, "openapi.yaml", `paths: { /other/route: {} }`)

	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil Matcher")
	}
	if !m.Matches("/priority/route") {
		t.Error("api_blueprint.yaml should take priority over openapi.yaml")
	}
	if m.Matches("/other/route") {
		t.Error("openapi.yaml routes should be ignored when api_blueprint.yaml is present")
	}
}

func TestLoadEmptyDocReturnsNil(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "api_blueprint.yaml", `routes: []`)
	m, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Error("empty routes list should return nil Matcher")
	}
}
