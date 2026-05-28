package blueprint

import (
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestLoad6000RPM fires requests at 6000 RPM (100 RPS) for 12 seconds using
// 20 concurrent workers. Traffic is split across four categories:
//
//   - legitimate matched    40 % — always in-NS, always matched
//   - in-NS miss            20 % — in-NS, not a known route
//   - out-of-namespace      20 % — should never be in-NS
//   - unique flood paths    20 % — /api/probe/<N>, one new path per request,
//     designed to saturate the cache; cache must stay ≤ maxCacheEntries
//     and results must remain correct throughout.
//
// The test fails if any result is wrong, the cache exceeds its cap, or the
// race detector fires.
func TestLoad6000RPM(t *testing.T) {
	m := buildMatcher([]string{
		"/api/users",
		"/api/users/{id}",
		"/api/posts",
		"/api/posts/{id}",
		"/api/orders/{id}/items",
		"/api/status",
	})

	const (
		rpm         = 6000
		workers     = 20
		durationSec = 12
	)

	// Tick at exactly 6000 RPM.
	interval := time.Minute / time.Duration(rpm) // 10 ms

	// expected maps a path category to (inNS, matched) so each worker can
	// verify its own result without shared state.
	type pathKind struct {
		path        string
		wantInNS    bool
		wantMatched bool
	}

	// Pre-seeded legitimate paths (deterministic).
	legit := []pathKind{
		{"/api/users", true, true},
		{"/api/users/42", true, true},
		{"/api/users/abc-123", true, true},
		{"/api/posts", true, true},
		{"/api/posts/99", true, true},
		{"/api/orders/XYZ/items", true, true},
		{"/api/status", true, true},
	}
	misses := []pathKind{
		{"/api/unknown", true, false},
		{"/api/admin", true, false},
		{"/api/internal/config", true, false},
	}
	outOfNS := []pathKind{
		{"/health", false, false},
		{"/metrics", false, false},
		{"/", false, false},
		{"/static/main.js", false, false},
	}

	var (
		totalSent   atomic.Int64
		totalErrors atomic.Int64
		cacheExceed atomic.Int64
	)

	// Latency histogram buckets (µs).
	type latBucket struct {
		mu   sync.Mutex
		vals []int64
	}
	var lats latBucket

	recordLat := func(d time.Duration) {
		us := d.Microseconds()
		lats.mu.Lock()
		lats.vals = append(lats.vals, us)
		lats.mu.Unlock()
	}

	// Jobs channel: ticker feeds paths; workers drain it.
	jobs := make(chan pathKind, workers*4)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for pk := range jobs {
				t0 := time.Now()
				inNS, matched := m.Lookup(pk.path)
				recordLat(time.Since(t0))

				totalSent.Add(1)
				if inNS != pk.wantInNS || matched != pk.wantMatched {
					totalErrors.Add(1)
					t.Errorf("path=%q: got inNS=%v matched=%v, want inNS=%v matched=%v",
						pk.path, inNS, matched, pk.wantInNS, pk.wantMatched)
				}
				if cl := m.CacheLen(); cl > maxCacheEntries {
					if cacheExceed.Add(1) == 1 { // log once
						t.Errorf("cache exceeded cap: %d > %d", cl, maxCacheEntries)
					}
				}
			}
		}()
	}

	// Rate-limited feeder.
	ticker := time.NewTicker(interval)
	deadline := time.NewTimer(durationSec * time.Second)

	var seq int64 // monotonic counter for unique flood paths
	rng := rand.New(rand.NewSource(42))

	start := time.Now()
feed:
	for {
		select {
		case <-deadline.C:
			break feed
		case <-ticker.C:
			roll := rng.Intn(100)
			var pk pathKind
			switch {
			case roll < 40: // 40% legit
				pk = legit[rng.Intn(len(legit))]
			case roll < 60: // 20% in-NS miss
				pk = misses[rng.Intn(len(misses))]
			case roll < 80: // 20% out-of-namespace
				pk = outOfNS[rng.Intn(len(outOfNS))]
			default: // 20% unique flood paths
				n := atomic.AddInt64(&seq, 1)
				pk = pathKind{
					path:        fmt.Sprintf("/api/probe/%d", n),
					wantInNS:    true,
					wantMatched: false, // no blueprint route matches /api/probe/*
				}
			}
			jobs <- pk
		}
	}
	ticker.Stop()
	deadline.Stop()
	close(jobs)
	wg.Wait()

	elapsed := time.Since(start)
	sent := totalSent.Load()
	actualRPM := float64(sent) / elapsed.Minutes()

	// Latency percentiles.
	lats.mu.Lock()
	vals := lats.vals
	lats.mu.Unlock()
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	p50 := vals[len(vals)*50/100]
	p95 := vals[len(vals)*95/100]
	p99 := vals[len(vals)*99/100]
	pmax := vals[len(vals)-1]

	t.Logf("--- 6000 RPM load test ---")
	t.Logf("Duration:    %v", elapsed.Round(time.Millisecond))
	t.Logf("Requests:    %d  (target %.0f, actual %.0f RPM)", sent, float64(rpm), actualRPM)
	t.Logf("Errors:      %d", totalErrors.Load())
	t.Logf("Cache size:  %d / %d", m.CacheLen(), maxCacheEntries)
	t.Logf("Latency p50: %d µs  p95: %d µs  p99: %d µs  max: %d µs", p50, p95, p99, pmax)

	if totalErrors.Load() > 0 {
		t.Errorf("got %d incorrect results under load", totalErrors.Load())
	}
	if cl := m.CacheLen(); cl > maxCacheEntries {
		t.Errorf("cache exceeded cap at end: %d > %d", cl, maxCacheEntries)
	}

	// Actual rate must be within 10% of target.
	if actualRPM < float64(rpm)*0.90 || actualRPM > float64(rpm)*1.10 {
		t.Errorf("actual rate %.0f RPM is outside 10%% of target %d RPM", actualRPM, rpm)
	}
}
