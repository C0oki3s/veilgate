package detector

import (
	"sync"
	"time"
)

// ClientEvent is one observed request from a client.
type ClientEvent struct {
	Timestamp time.Time
	Path      string
	Query     string // raw URL query (without leading '?'), empty when none
	Method    string
	Status    int
	UserAgent string
	JA4       string // TLS fingerprint, optional
	// SecFetchDest mirrors the Sec-Fetch-Dest header value when present
	// ("document" / "image" / "script" / "empty" / …). Used by the
	// request-graph-topology signal to compute the ratio of subresource
	// fetches per HTML fetch.
	SecFetchDest string
	// HasCookie is true when the request carried any Cookie header.
	// Used by the cookie-ecology signal — clients that never send
	// cookies despite a Set-Cookie having gone out look library-shaped.
	HasCookie bool
	// ToolStage is "recon" | "probe" | "exploit" | "" — tagged by the
	// scorer using the same path patterns as the toolchain signal. We
	// cache it on the event so a follow-up cross-request signal (HMM
	// over the stage sequence) doesn't re-tokenize the path on every
	// request.
	ToolStage string
	// HeaderBitmap is a 32-bit presence mask of interesting request headers
	// (same set as the fleet-rotation signal uses). Stored per-event so the
	// header_mutation signal can detect mid-session header drops without
	// re-parsing the request.
	HeaderBitmap string
	// HasConditional is true when the request carried If-None-Match or
	// If-Modified-Since. Used by the cache_miss_anomaly signal to detect
	// agents that repeat-fetch the same path without cache discipline.
	HasConditional bool
	// HasOriginHeader is true when the request carried an Origin header,
	// indicating a cross-domain XHR/fetch (SPA calling a different-domain API).
	// Used by the no_cookie_return signal to avoid firing when the browser
	// legitimately cannot return a cookie without credentials:include + CORS.
	HasOriginHeader bool
}

// ClientState tracks rolling behavior for a single client (IP).
type ClientState struct {
	mu           sync.Mutex
	Events       []ClientEvent
	HoneypotHits int
	Score        int
	FirstSeen    time.Time
	LastSeen     time.Time
	// UniqueUAs is the set of distinct User-Agent strings seen from
	// this client inside the rolling window. Used for ua_rotation
	// detection — dirsearch -H / ffuf with a UA pool is the canonical
	// attacker that shuffles UAs while keeping IP stable.
	UniqueUAs map[string]time.Time

	// LastStatus is the response status code from the immediately-
	// preceding request, or 0 when none. Set by Tracker.RecordStatus
	// after the proxy finishes writing the response. The
	// failure-recovery signal compares this to the *next* request's
	// shape: a real user that hits a 401 retries the same shape with
	// credentials; an LLM agent often retries with a *different* path
	// or parameter set.
	LastStatus int
	// LastNon200Path is the path of the last request that returned a
	// 4xx/5xx response. Used together with LastStatus to detect
	// shape-change retries.
	LastNon200Path   string
	LastNon200Method string

	// CookiesSent / RequestsTotal track the cookie-ecology ratio.
	// Reset on the same window evictions as Events.
	CookiesSent   int
	RequestsTotal int

	// LastJSAssetAt is the timestamp of the most recent response that was a
	// JavaScript asset (path ends in .js, content-type javascript). Used by
	// scoreBundleMining to detect the "fetch JS bundle then immediately probe
	// API endpoints" pattern characteristic of LLM agents that grep source.
	LastJSAssetAt time.Time

	// SubresourceFetches / DocumentFetches feed the request-graph
	// topology signal. Real browsers post a tree-shaped pattern of
	// document followed by many subresource fetches; agents tend
	// toward a flat list of independent document fetches.
	DocumentFetches    int
	SubresourceFetches int

	// HeaderMutations counts how many times the header-presence bitmap
	// changed between consecutive requests. Agents often drop or add
	// headers mid-session as they switch between tool calls; real browsers
	// keep a stable header set throughout a session.
	HeaderMutations  int
	LastHeaderBitmap string

	// SetCookieReceived is set by the proxy when a tarpit response
	// included a Set-Cookie header. The no_cookie_return signal fires
	// when this is true and CookiesSent stays zero across subsequent
	// requests — a stateless HTTP client that ignores cookie jars.
	SetCookieReceived bool
	// HasCrossOriginRequests is set when any request from this client carried
	// an Origin header. A browser making cross-domain XHR/fetch calls may
	// legitimately not return cookies if the response lacked
	// Access-Control-Allow-Credentials or if the cookie was SameSite=Strict.
	// The no_cookie_return signal skips this client to avoid false positives.
	HasCrossOriginRequests bool
}

// Tracker holds per-client state across the process.
type Tracker struct {
	mu      sync.RWMutex
	clients map[string]*ClientState
	window  time.Duration
	maxHist int
}

func NewTracker(windowSeconds int) *Tracker {
	return &Tracker{
		clients: make(map[string]*ClientState),
		window:  time.Duration(windowSeconds) * time.Second,
		maxHist: 200,
	}
}

// Record adds an event for a client and returns the updated state.
func (t *Tracker) Record(clientID string, evt ClientEvent) *ClientState {
	t.mu.Lock()
	st, ok := t.clients[clientID]
	if !ok {
		st = &ClientState{
			FirstSeen: evt.Timestamp,
			UniqueUAs: make(map[string]time.Time),
		}
		t.clients[clientID] = st
	}
	t.mu.Unlock()

	st.mu.Lock()
	defer st.mu.Unlock()

	st.LastSeen = evt.Timestamp
	st.Events = append(st.Events, evt)
	st.RequestsTotal++
	if evt.HasCookie {
		st.CookiesSent++
	}
	switch evt.SecFetchDest {
	case "document":
		st.DocumentFetches++
	case "":
		// no info — typical for libraries; ignore for the topology ratio.
	default:
		st.SubresourceFetches++
	}

	// Detect header-presence mutations between consecutive requests.
	// An empty bitmap on the very first request initialises the baseline
	// without counting as a mutation.
	if evt.HeaderBitmap != "" {
		if st.LastHeaderBitmap != "" && evt.HeaderBitmap != st.LastHeaderBitmap {
			st.HeaderMutations++
		}
		st.LastHeaderBitmap = evt.HeaderBitmap
	}
	// Mark cross-origin requests; once set it is never cleared because the
	// no_cookie_return signal should stay suppressed for the whole session.
	if evt.HasOriginHeader {
		st.HasCrossOriginRequests = true
	}

	if st.UniqueUAs == nil {
		st.UniqueUAs = make(map[string]time.Time)
	}
	// Record the UA fingerprint for this request (empty UA counts as
	// its own distinct bucket — rotators often mix real UAs with gaps).
	st.UniqueUAs[evt.UserAgent] = evt.Timestamp

	// Evict events outside the rolling window.
	cutoff := evt.Timestamp.Add(-t.window)
	i := 0
	for ; i < len(st.Events); i++ {
		if st.Events[i].Timestamp.After(cutoff) {
			break
		}
	}
	if i > 0 {
		st.Events = st.Events[i:]
	}
	if len(st.Events) > t.maxHist {
		st.Events = st.Events[len(st.Events)-t.maxHist:]
	}
	// Evict stale UA entries on the same window cutoff so the set
	// reflects *current* rotation, not all-time distinct UAs.
	for ua, ts := range st.UniqueUAs {
		if ts.Before(cutoff) {
			delete(st.UniqueUAs, ua)
		}
	}
	return st
}

// Get returns the state for a client without modifying it.
func (t *Tracker) Get(clientID string) *ClientState {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.clients[clientID]
}

// RecordJSAsset marks that the client just fetched a JavaScript bundle
// asset. Called from the proxy when the upstream response has a JS
// content-type. This arms the scoreBundleMining signal for the next 60s.
func (t *Tracker) RecordJSAsset(clientID string) {
	if t == nil {
		return
	}
	t.mu.RLock()
	st := t.clients[clientID]
	t.mu.RUnlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	st.LastJSAssetAt = time.Now()
	st.mu.Unlock()
}

// RecordSetCookie marks that the tarpit served a Set-Cookie to this client.
// Called from the proxy after writing a tarpit response that included a
// Set-Cookie header. Arms the no_cookie_return signal.
func (t *Tracker) RecordSetCookie(clientID string) {
	if t == nil {
		return
	}
	t.mu.RLock()
	st := t.clients[clientID]
	t.mu.RUnlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	st.SetCookieReceived = true
	st.mu.Unlock()
}

// RecordStatus annotates the previous request's response status. Called
// from the proxy after WriteHeader. Lets the failure-recovery signal
// compare a 401/403/404 response with the next request's shape.
func (t *Tracker) RecordStatus(clientID string, status int, path, method string) {
	if t == nil {
		return
	}
	t.mu.RLock()
	st := t.clients[clientID]
	t.mu.RUnlock()
	if st == nil {
		return
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	st.LastStatus = status
	if status >= 400 {
		st.LastNon200Path = path
		st.LastNon200Method = method
	}
	if len(st.Events) > 0 {
		st.Events[len(st.Events)-1].Status = status
	}
}

// Len returns the number of client IPs currently tracked. Used by the
// periodic metrics publisher to feed the client-cardinality gauge.
func (t *Tracker) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.clients)
}

// GC removes stale clients. Call periodically.
func (t *Tracker) GC(maxIdle time.Duration) {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, st := range t.clients {
		st.mu.Lock()
		idle := now.Sub(st.LastSeen)
		st.mu.Unlock()
		if idle > maxIdle {
			delete(t.clients, id)
		}
	}
}
