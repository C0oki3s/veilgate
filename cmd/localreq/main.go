package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type browserProfile struct {
	userAgent       string
	secCHUA         string
	secCHUAPlatform string
	acceptLanguage  string
	headerStyle     string
}

type endpoint struct {
	method string
	path   string
	weight int
}

type requestResult struct {
	statusCode int
	err        error
	latency    time.Duration
}

var profiles = []browserProfile{
	{
		userAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36",
		secCHUA:         "\"Google Chrome\";v=\"147\", \"Chromium\";v=\"147\", \"Not.A/Brand\";v=\"8\"",
		secCHUAPlatform: "\"Windows\"",
		acceptLanguage:  "en-US,en;q=0.9",
		headerStyle:     "browser",
	},
	{
		userAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
		secCHUA:         "\"Google Chrome\";v=\"146\", \"Chromium\";v=\"146\", \"Not.A/Brand\";v=\"8\"",
		secCHUAPlatform: "\"macOS\"",
		acceptLanguage:  "en-US,en;q=0.8",
		headerStyle:     "browser",
	},
	{
		userAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
		secCHUA:         "\"Google Chrome\";v=\"145\", \"Chromium\";v=\"145\", \"Not.A/Brand\";v=\"8\"",
		secCHUAPlatform: "\"Linux\"",
		acceptLanguage:  "en-US,en;q=0.7",
		headerStyle:     "browser",
	},
}

var challengeProfiles = []browserProfile{
	{
		userAgent:      "python-requests/2.32.3",
		acceptLanguage: "",
		headerStyle:    "sparse",
	},
	{
		userAgent:      "curl/8.7.1",
		acceptLanguage: "",
		headerStyle:    "sparse",
	},
	{
		userAgent:      "Go-http-client/2.0",
		acceptLanguage: "",
		headerStyle:    "sparse",
	},
}

var maliciousProfiles = []browserProfile{
	{
		userAgent:   "sqlmap/1.8.7#stable (https://sqlmap.org)",
		headerStyle: "sparse",
	},
	{
		userAgent:   "Nikto/2.5.0",
		headerStyle: "sparse",
	},
	{
		userAgent:   "nuclei/v3.2.9",
		headerStyle: "sparse",
	},
}

var normalEndpoints = []endpoint{
	{method: http.MethodGet, path: "/", weight: 35},
	{method: http.MethodGet, path: "/api/health", weight: 25},
	{method: http.MethodGet, path: "/api/content", weight: 20},
	{method: http.MethodGet, path: "/api/timeline", weight: 15},
	{method: http.MethodPost, path: "/api/visits", weight: 5},
}

var challengeEndpoints = []endpoint{
	{method: http.MethodGet, path: "/", weight: 20},
	{method: http.MethodGet, path: "/api/products", weight: 35},
	{method: http.MethodGet, path: "/api/stats", weight: 25},
	{method: http.MethodGet, path: "/api/veilgate/config", weight: 20},
}

var maliciousEndpoints = []endpoint{
	{method: http.MethodGet, path: "/wp-login.php", weight: 20},
	{method: http.MethodGet, path: "/.env", weight: 20},
	{method: http.MethodGet, path: "/admin-panel-v2", weight: 20},
	{method: http.MethodGet, path: "/.git/config", weight: 15},
	{method: http.MethodGet, path: "/api/products?q=../etc/passwd", weight: 15},
	{method: http.MethodGet, path: "/api/search?q=' OR '1'='1", weight: 10},
}

func main() {
	positionalCount, parseArgs := extractPositionalCount(os.Args[1:])
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	baseURL := fs.String("base", "http://localhost", "base URL to target")
	totalRequests := fs.Int("n", 0, "number of requests to send (or pass as positional arg)")
	concurrency := fs.Int("concurrency", 1, "number of concurrent workers")
	trafficMode := fs.String("traffic", "normal", "traffic profile: normal, challenge, malicious, mixed")
	inspect := fs.Bool("inspect", false, "print Set-Cookie and challenge-like responses")
	tlsMode := fs.String("tls", "auto", "TLS verification: auto, strict, skip-verify")
	insecure := fs.Bool("insecure", false, "alias for -tls=skip-verify")
	ipFamily := fs.String("ip-family", "auto", "IP family: auto, 4, 6")
	minDelay := fs.Duration("min-delay", 250*time.Millisecond, "minimum delay between requests per worker")
	maxDelay := fs.Duration("max-delay", 1500*time.Millisecond, "maximum delay between requests per worker")
	timeout := fs.Duration("timeout", 10*time.Second, "HTTP request timeout")
	seed := fs.Int64("seed", time.Now().UnixNano(), "random seed")
	if err := fs.Parse(parseArgs); err != nil {
		fail("parse args: %v", err)
	}

	if *totalRequests <= 0 && positionalCount > 0 {
		*totalRequests = positionalCount
	}
	if *totalRequests <= 0 {
		*totalRequests = 25
	}
	if *concurrency <= 0 {
		fail("concurrency must be >= 1")
	}
	if *minDelay < 0 || *maxDelay < 0 {
		fail("min-delay and max-delay must be >= 0")
	}
	if *maxDelay < *minDelay {
		fail("max-delay must be >= min-delay")
	}
	if !validTrafficMode(*trafficMode) {
		fail("traffic must be one of: normal, challenge, malicious, mixed")
	}
	if !validIPFamily(*ipFamily) {
		fail("ip-family must be one of: auto, 4, 6")
	}
	if !validTLSMode(*tlsMode) {
		fail("tls must be one of: auto, strict, skip-verify")
	}
	if *insecure {
		*tlsMode = "skip-verify"
	}

	base := strings.TrimRight(*baseURL, "/")
	skipTLSVerify := shouldSkipTLSVerify(base, *tlsMode)
	if skipTLSVerify && strings.HasPrefix(strings.ToLower(base), "https://") {
		fmt.Fprintf(os.Stderr, "warning: TLS certificate verification disabled for %s; use -tls=strict to require a trusted certificate\n", base)
	}
	client := newHTTPClient(*timeout, *ipFamily, skipTLSVerify)
	rng := rand.New(rand.NewSource(*seed))

	fmt.Printf("target=%s requests=%d concurrency=%d traffic=%s tls=%s delay=%s..%s seed=%d\n",
		base, *totalRequests, *concurrency, *trafficMode, *tlsMode, minDelay.String(), maxDelay.String(), *seed)

	jobs := make(chan int)
	results := make(chan requestResult, *totalRequests)

	var sent int64
	var wg sync.WaitGroup
	for workerID := 0; workerID < *concurrency; workerID++ {
		wg.Add(1)
		workerSeed := rng.Int63()
		go func(id int, s int64) {
			defer wg.Done()
			workerRNG := rand.New(rand.NewSource(s))
			profileSet := profilesForMode(*trafficMode)
			profile := profileSet[id%len(profileSet)]
			for range jobs {
				ep := chooseEndpoint(workerRNG, endpointsForMode(*trafficMode, workerRNG))
				res := performRequest(client, base, ep, profile, workerRNG, *inspect)
				results <- res
				atomic.AddInt64(&sent, 1)
				sleepJitter(workerRNG, *minDelay, *maxDelay)
			}
		}(workerID, workerSeed)
	}

	go func() {
		for i := 0; i < *totalRequests; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var ok2xx int
	var ok3xx int
	var clientErr int
	var serverErr int
	var failed int
	var totalLatency time.Duration
	var countLatency int

	for res := range results {
		if res.err != nil {
			failed++
			fmt.Printf("error: %v\n", res.err)
			continue
		}
		switch {
		case res.statusCode >= 200 && res.statusCode < 300:
			ok2xx++
		case res.statusCode >= 300 && res.statusCode < 400:
			ok3xx++
		case res.statusCode >= 400 && res.statusCode < 500:
			clientErr++
		case res.statusCode >= 500:
			serverErr++
		}
		totalLatency += res.latency
		countLatency++
	}

	avgLatency := time.Duration(0)
	if countLatency > 0 {
		avgLatency = totalLatency / time.Duration(countLatency)
	}
	fmt.Printf("done sent=%d 2xx=%d 3xx=%d 4xx=%d 5xx=%d failed=%d avg_latency=%s\n",
		sent, ok2xx, ok3xx, clientErr, serverErr, failed, avgLatency)
}

func newHTTPClient(timeout time.Duration, ipFamily string, insecure bool) *http.Client {
	jar, _ := cookiejar.New(nil)
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}
	network := "tcp"
	if ipFamily == "4" {
		network = "tcp4"
	}
	if ipFamily == "6" {
		network = "tcp6"
	}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _ string, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure,
		},
	}
	return &http.Client{
		Timeout:   timeout,
		Jar:       jar,
		Transport: transport,
	}
}

func chooseEndpoint(rng *rand.Rand, endpoints []endpoint) endpoint {
	totalWeight := 0
	for _, ep := range endpoints {
		totalWeight += ep.weight
	}
	pick := rng.Intn(totalWeight)
	for _, ep := range endpoints {
		pick -= ep.weight
		if pick < 0 {
			return ep
		}
	}
	return endpoints[0]
}

func performRequest(client *http.Client, base string, ep endpoint, p browserProfile, rng *rand.Rand, inspect bool) requestResult {
	if ep.method == http.MethodGet && ep.path == "/" {
		return performDocumentFlow(client, base, p, rng, inspect)
	}

	url := base + ep.path
	var body io.Reader
	if ep.method == http.MethodPost && ep.path == "/api/visits" {
		payload := map[string]any{
			"visitorId":         fmt.Sprintf("sess-%08x", rng.Uint32()),
			"path":              pickPath(rng),
			"userAgent":         p.userAgent,
			"referrer":          base + "/",
			"screen":            pickScreen(rng),
			"ja3":               "771,4865-4866-4867,0-11-10-35-16-5-13,29-23-24,0",
			"ja4":               "t13d1516h2_8daaf6152771_b0da82dd1658",
			"missingSecFetch":   false,
			"requestIntervalMs": 300 + rng.Intn(2500),
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return requestResult{err: fmt.Errorf("marshal payload: %w", err)}
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequest(ep.method, url, body)
	if err != nil {
		return requestResult{err: fmt.Errorf("new request %s %s: %w", ep.method, ep.path, err)}
	}
	applyHeaders(req, ep, p, base)
	if ep.method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return requestResult{err: fmt.Errorf("%s %s failed: %w", ep.method, ep.path, err), latency: latency}
	}
	defer resp.Body.Close()
	if inspect {
		// readResponseBody handles gzip/deflate; the proxy may compress
		// even small JSON, and printing raw gzip bytes is useless.
		decoded, derr := readResponseBody(resp)
		if derr != nil {
			fmt.Printf("inspect %s %s decode body: %v\n", ep.method, ep.path, derr)
		} else {
			inspectResponse(ep, resp, decoded)
		}
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	}

	return requestResult{statusCode: resp.StatusCode, latency: latency}
}

func performDocumentFlow(client *http.Client, base string, p browserProfile, rng *rand.Rand, inspect bool) requestResult {
	rootReq, err := http.NewRequest(http.MethodGet, base+"/", nil)
	if err != nil {
		return requestResult{err: fmt.Errorf("new request GET /: %w", err)}
	}
	applyHeaders(rootReq, endpoint{method: http.MethodGet, path: "/"}, p, base)

	start := time.Now()
	rootResp, err := client.Do(rootReq)
	latency := time.Since(start)
	if err != nil {
		return requestResult{err: fmt.Errorf("GET / failed: %w", err), latency: latency}
	}
	rootBody, bodyErr := readResponseBody(rootResp)
	rootResp.Body.Close()
	if bodyErr != nil {
		return requestResult{err: fmt.Errorf("read GET / response: %w", bodyErr), latency: latency}
	}
	if inspect {
		inspectResponse(endpoint{method: http.MethodGet, path: "/"}, rootResp, rootBody)
	}

	assets := extractAssetPaths(rootBody)
	if len(assets) > 0 {
		// Load a few static assets right after document fetch so request topology
		// looks more browser-like and less like a headless crawler.
		maxAssets := 3
		if len(assets) < maxAssets {
			maxAssets = len(assets)
		}
		for i := 0; i < maxAssets; i++ {
			assetPath := assets[i]
			assetReq, reqErr := http.NewRequest(http.MethodGet, base+assetPath, nil)
			if reqErr != nil {
				continue
			}
			assetEP := endpoint{method: http.MethodGet, path: assetPath}
			applyHeaders(assetReq, assetEP, p, base)
			_, _ = client.Do(assetReq)
		}
	}

	return requestResult{statusCode: rootResp.StatusCode, latency: latency}
}

func applyHeaders(req *http.Request, ep endpoint, p browserProfile, base string) {
	if p.headerStyle == "sparse" {
		req.Header.Set("Accept", "*/*")
		req.Header.Set("User-Agent", p.userAgent)
		return
	}
	req.Header.Set("Accept", acceptedType(ep.path))
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Accept-Language", p.acceptLanguage)
	req.Header.Set("Sec-CH-UA", p.secCHUA)
	req.Header.Set("Sec-CH-UA-Mobile", "?0")
	req.Header.Set("Sec-CH-UA-Platform", p.secCHUAPlatform)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", base+"/")
	req.Header.Set("User-Agent", p.userAgent)
	if ep.path == "/" {
		req.Header.Set("Upgrade-Insecure-Requests", "1")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-User", "?1")
	}
	if strings.HasPrefix(ep.path, "/assets/") {
		req.Header.Set("Sec-Fetch-Mode", "no-cors")
		req.Header.Set("Sec-Fetch-Dest", fetchDestForAsset(ep.path))
	}
}

func validTrafficMode(mode string) bool {
	switch mode {
	case "normal", "challenge", "malicious", "mixed":
		return true
	default:
		return false
	}
}

func validIPFamily(family string) bool {
	switch family {
	case "auto", "4", "6":
		return true
	default:
		return false
	}
}

func validTLSMode(mode string) bool {
	switch mode {
	case "auto", "strict", "skip-verify":
		return true
	default:
		return false
	}
}

func shouldSkipTLSVerify(base string, mode string) bool {
	switch mode {
	case "skip-verify":
		return true
	case "strict":
		return false
	default:
		return strings.HasPrefix(strings.ToLower(base), "https://")
	}
}

func profilesForMode(mode string) []browserProfile {
	switch mode {
	case "challenge":
		return challengeProfiles
	case "malicious":
		return maliciousProfiles
	default:
		return profiles
	}
}

func endpointsForMode(mode string, rng *rand.Rand) []endpoint {
	switch mode {
	case "challenge":
		return challengeEndpoints
	case "malicious":
		return maliciousEndpoints
	case "mixed":
		if rng.Intn(100) < 35 {
			return maliciousEndpoints
		}
		return normalEndpoints
	default:
		return normalEndpoints
	}
}

func inspectResponse(ep endpoint, resp *http.Response, body string) {
	fmt.Printf("\n--- inspect %s %s HTTP/%d.%d %d %s\n",
		ep.method, ep.path, resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, http.StatusText(resp.StatusCode))

	names := make([]string, 0, len(resp.Header))
	for k := range resp.Header {
		names = append(names, k)
	}
	sortStrings(names)
	for _, name := range names {
		for _, v := range resp.Header.Values(name) {
			fmt.Printf("    %s: %s\n", name, v)
		}
	}

	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "challenge_required") ||
		strings.Contains(lowerBody, "proof-of-work") ||
		strings.Contains(lowerBody, "__veilgate") {
		fmt.Println("    [hint] challenge-like body detected")
	}

	const maxBody = 4096
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		fmt.Println("    body: <empty>")
		return
	}
	if len(trimmed) > maxBody {
		fmt.Printf("    body (%d bytes, truncated to %d):\n%s\n    ...[%d more bytes]\n",
			len(trimmed), maxBody, indentLines(trimmed[:maxBody]), len(trimmed)-maxBody)
		return
	}
	fmt.Printf("    body (%d bytes):\n%s\n", len(trimmed), indentLines(trimmed))
}

func indentLines(s string) string {
	if s == "" {
		return ""
	}
	return "      " + strings.ReplaceAll(s, "\n", "\n      ")
}

// sortStrings is a tiny shim to avoid pulling in "sort" just for one
// call. Bubble sort is fine — header lists are tens of entries at most.
func sortStrings(xs []string) {
	for i := 1; i < len(xs); i++ {
		for j := i; j > 0 && strings.ToLower(xs[j-1]) > strings.ToLower(xs[j]); j-- {
			xs[j-1], xs[j] = xs[j], xs[j-1]
		}
	}
}

func acceptedType(path string) string {
	if path == "/" {
		return "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	}
	return "application/json, text/plain, */*"
}

func pickPath(rng *rand.Rand) string {
	paths := []string{
		"/",
		"/products",
		"/pricing",
		"/checkout",
		"/cart",
	}
	return paths[rng.Intn(len(paths))]
}

func pickScreen(rng *rand.Rand) string {
	screens := []string{
		"1920x1080",
		"1536x864",
		"1440x900",
		"1366x768",
		"2560x1440",
	}
	return screens[rng.Intn(len(screens))]
}

func sleepJitter(rng *rand.Rand, minDelay, maxDelay time.Duration) {
	if maxDelay == 0 {
		return
	}
	if maxDelay == minDelay {
		time.Sleep(minDelay)
		return
	}
	delta := maxDelay - minDelay
	time.Sleep(minDelay + time.Duration(rng.Int63n(int64(delta))))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func readResponseBody(resp *http.Response) (string, error) {
	var reader io.ReadCloser = resp.Body
	var err error

	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return "", err
		}
		defer reader.Close()
	case "deflate":
		reader, err = zlib.NewReader(resp.Body)
		if err != nil {
			return "", err
		}
		defer reader.Close()
	}

	b, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func extractAssetPaths(html string) []string {
	re := regexp.MustCompile(`(?:src|href)="(/assets/[^"]+)"`)
	matches := re.FindAllStringSubmatch(html, -1)
	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		p := m[1]
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func fetchDestForAsset(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".js", ".mjs":
		return "script"
	case ".css":
		return "style"
	case ".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico":
		return "image"
	default:
		return "empty"
	}
}

func extractPositionalCount(args []string) (int, []string) {
	filtered := make([]string, 0, len(args))
	positionalCount := 0
	for _, arg := range args {
		if positionalCount == 0 && !strings.HasPrefix(arg, "-") {
			n, err := strconv.Atoi(arg)
			if err == nil && n > 0 {
				positionalCount = n
				continue
			}
		}
		filtered = append(filtered, arg)
	}
	return positionalCount, filtered
}
