package tarpit

import (
	"sync"
	"testing"
	"time"
)

func TestResponseCacheBasicHitMiss(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 1000)

	// Initial state: miss on anything
	if _, ok := c.Get("10.0.0.1", "/login"); ok {
		t.Fatal("expected cache miss on empty cache")
	}

	// Store a response and retrieve it
	want := Response{Status: 200, Body: "hello world", ContentType: "text/html"}
	c.Set("10.0.0.1", "/login", want)

	got, ok := c.Get("10.0.0.1", "/login")
	if !ok {
		t.Fatal("expected cache hit after Set")
	}
	if got.Status != want.Status || got.Body != want.Body || got.ContentType != want.ContentType {
		t.Fatalf("cached response mismatch: got %+v, want %+v", got, want)
	}
}

func TestResponseCacheDifferentClientsIsolated(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 1000)
	c.Set("ip1", "/api/data", Response{Body: "for-ip1"})
	c.Set("ip2", "/api/data", Response{Body: "for-ip2"})

	r1, ok1 := c.Get("ip1", "/api/data")
	r2, ok2 := c.Get("ip2", "/api/data")

	if !ok1 || !ok2 {
		t.Fatalf("expected hits for both clients: ip1=%v ip2=%v", ok1, ok2)
	}
	if r1.Body == r2.Body {
		t.Fatal("different clients should not share cached responses")
	}
	if r1.Body != "for-ip1" || r2.Body != "for-ip2" {
		t.Fatalf("client isolation broken: ip1=%q ip2=%q", r1.Body, r2.Body)
	}
}

func TestResponseCachePathCaseInsensitive(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 100)
	c.Set("10.0.0.1", "/Login", Response{Body: "login page"})

	// Lookup with lowercase path should hit
	got, ok := c.Get("10.0.0.1", "/login")
	if !ok {
		t.Fatal("cache should match paths case-insensitively")
	}
	if got.Body != "login page" {
		t.Fatalf("body mismatch: %q", got.Body)
	}

	// Mixed case also hits
	if _, ok := c.Get("10.0.0.1", "/LOGIN"); !ok {
		t.Fatal("cache should match paths case-insensitively (all caps)")
	}
}

func TestResponseCacheTTLExpiry(t *testing.T) {
	c := NewResponseCache(20*time.Millisecond, 1000)
	c.Set("10.0.0.1", "/path", Response{Status: 200, Body: "data"})

	// Verify stored before expiry
	if _, ok := c.Get("10.0.0.1", "/path"); !ok {
		t.Fatal("expected hit before TTL expiry")
	}

	time.Sleep(30 * time.Millisecond)

	// Should be expired now
	if _, ok := c.Get("10.0.0.1", "/path"); ok {
		t.Fatal("expected miss after TTL expiry")
	}
}

func TestResponseCacheCapacityDropWhenFull(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 2)
	c.Set("ip1", "/a", Response{Body: "a"})
	c.Set("ip2", "/b", Response{Body: "b"})

	// At capacity with no expired entries — new write should be silently dropped
	c.Set("ip3", "/c", Response{Body: "c"})

	if c.Len() != 2 {
		t.Fatalf("cache should stay at capacity=2, got %d", c.Len())
	}
	if _, ok := c.Get("ip3", "/c"); ok {
		t.Fatal("entry dropped due to full capacity should not be retrievable")
	}
}

func TestResponseCacheCapacityEvictsExpiredOnWrite(t *testing.T) {
	c := NewResponseCache(20*time.Millisecond, 2)
	c.Set("ip1", "/a", Response{Body: "a"})
	c.Set("ip2", "/b", Response{Body: "b"})

	// Wait for entries to expire
	time.Sleep(30 * time.Millisecond)

	// Now write a third entry — an expired slot should be evicted to make room
	c.Set("ip3", "/c", Response{Body: "c"})

	if _, ok := c.Get("ip3", "/c"); !ok {
		t.Fatal("new entry should succeed after evicting an expired slot")
	}
}

// TestResponseCacheSetOverwritesExistingEntry documents that Set always
// overwrites — the "serve identical bytes" invariant comes from handler.go's
// Get-before-Set pattern, not from Set refusing to overwrite.
// Concurrent same-path misses both render identical deterministic content,
// so last-writer-wins on the cache entry is safe.
func TestResponseCacheSetOverwritesExistingEntry(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 100)
	c.Set("10.0.0.1", "/api", Response{Body: "first"})
	c.Set("10.0.0.1", "/api", Response{Body: "second"}) // overwrites

	got, ok := c.Get("10.0.0.1", "/api")
	if !ok {
		t.Fatal("expected cache hit")
	}
	// Set overwrites — "second" is the current entry
	if got.Body != "second" {
		t.Fatalf("Set should overwrite existing entry: got %q, want %q", got.Body, "second")
	}
}

func TestResponseCacheGCRemovesExpiredEntries(t *testing.T) {
	c := NewResponseCache(20*time.Millisecond, 100)
	c.Set("ip1", "/p1", Response{Body: "a"})
	c.Set("ip2", "/p2", Response{Body: "b"})

	time.Sleep(30 * time.Millisecond)

	c.GC()

	if c.Len() != 0 {
		t.Fatalf("GC should have removed all expired entries, got Len=%d", c.Len())
	}
}

func TestResponseCacheGCPreservesUnexpiredEntries(t *testing.T) {
	c := NewResponseCache(10*time.Minute, 100)
	c.Set("ip1", "/keep", Response{Body: "keep"})
	c.Set("ip2", "/also-keep", Response{Body: "also"})

	c.GC()

	if c.Len() != 2 {
		t.Fatalf("GC should preserve unexpired entries, got Len=%d", c.Len())
	}
}

func TestResponseCacheLenAccurate(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 100)
	if c.Len() != 0 {
		t.Fatalf("empty cache Len = %d, want 0", c.Len())
	}
	c.Set("a", "/x", Response{})
	c.Set("b", "/y", Response{})
	if c.Len() != 2 {
		t.Fatalf("Len after 2 inserts = %d, want 2", c.Len())
	}
}

// TestResponseCacheConcurrent verifies the cache is safe under concurrent
// reads and writes — the lock discipline must not deadlock or race.
func TestResponseCacheConcurrent(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 500)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			id := rcItoa(n)
			c.Set(id, "/path", Response{Status: 200, Body: id})
		}(i)
		go func(n int) {
			defer wg.Done()
			c.Get(rcItoa(n), "/path")
		}(i)
	}
	wg.Wait()
	// GC should also be safe concurrently
	c.GC()
}

func rcItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestResponseCacheReturnsIdenticalBytes is the core invariant: an agent
// re-fetching the same path must see byte-identical responses so it cannot
// detect it is being observed. We test the struct fields match exactly.
func TestResponseCacheReturnsIdenticalBytes(t *testing.T) {
	c := NewResponseCache(30*time.Minute, 1000)

	original := Response{
		Status:      200,
		ContentType: "application/json",
		Body:        `{"id":1,"token":"canary-abc123","user":"admin@acme.internal"}`,
		Headers:     map[string]string{"X-Request-ID": "req-xyz", "Server": "nginx/1.22.1"},
	}
	c.Set("10.1.2.3", "/api/users/1", original)

	for i := 0; i < 5; i++ {
		got, ok := c.Get("10.1.2.3", "/api/users/1")
		if !ok {
			t.Fatalf("request %d: expected cache hit", i+1)
		}
		if got.Body != original.Body {
			t.Fatalf("request %d: body mismatch — agent can detect non-determinism", i+1)
		}
		if got.Status != original.Status {
			t.Fatalf("request %d: status mismatch", i+1)
		}
	}
}
