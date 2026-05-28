package tarpit

import (
	"strings"
	"sync"
	"time"
)

// ResponseCache stores fully-rendered tarpit responses keyed by (clientID, path).
// On first contact from a given IP to a given path, the rendered Response is
// stored. Every subsequent visit from that same IP sees identical bytes — so the
// deception stays coherent when agents re-check a "vulnerability" (which real
// agent logs confirm they always do: one agent fetched the same schema endpoint
// 5 times, another fetched the same login endpoint 9 times).
type ResponseCache struct {
	mu      sync.Mutex
	entries map[string]*rcEntry
	ttl     time.Duration
	maxSize int
}

type rcEntry struct {
	resp      Response
	expiresAt time.Time
}

// NewResponseCache creates a cache with the given TTL and max-entry cap.
func NewResponseCache(ttl time.Duration, maxSize int) *ResponseCache {
	return &ResponseCache{
		entries: make(map[string]*rcEntry, 256),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

func (c *ResponseCache) cacheKey(clientID, path string) string {
	return clientID + "|" + strings.ToLower(path)
}

// Get returns the cached Response for (clientID, path). Returns false when
// no entry exists or the entry has expired.
func (c *ResponseCache) Get(clientID, path string) (Response, bool) {
	k := c.cacheKey(clientID, path)
	c.mu.Lock()
	e, ok := c.entries[k]
	c.mu.Unlock()
	if !ok || time.Now().After(e.expiresAt) {
		return Response{}, false
	}
	return e.resp, true
}

// Set stores resp under (clientID, path). If the cache is at capacity and no
// expired entry can be evicted, the write is silently dropped — correctness
// (never panicking, never overwriting existing entries) matters more than
// guaranteeing every response is cached.
func (c *ResponseCache) Set(clientID, path string, resp Response) {
	k := c.cacheKey(clientID, path)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[k]; !exists && len(c.entries) >= c.maxSize {
		now := time.Now()
		evicted := false
		for key, e := range c.entries {
			if now.After(e.expiresAt) {
				delete(c.entries, key)
				evicted = true
				break
			}
		}
		if !evicted {
			return
		}
	}
	c.entries[k] = &rcEntry{resp: resp, expiresAt: time.Now().Add(c.ttl)}
}

// GC removes expired entries. Call periodically (e.g. every 10 minutes)
// from the same goroutine that runs tracker.GC.
func (c *ResponseCache) GC() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
}

// Len returns the number of cached entries. Used for metrics.
func (c *ResponseCache) Len() int {
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	return n
}
