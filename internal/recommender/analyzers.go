package recommender

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// ── path helpers ─────────────────────────────────────────────────────────────

// pathExt returns the lowercased file extension including the dot (e.g. ".php"),
// or "" if the last path segment has no extension or the extension is trivially
// short. Only looks at the last path segment; query strings are stripped.
func pathExt(p string) string {
	// Strip query string that may have been stored with the path.
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	base := filepath.Base(p) // last segment
	ext := strings.ToLower(filepath.Ext(base))
	if len(ext) <= 1 { // "." alone or empty
		return ""
	}
	return ext
}

// pathPrefixDepth returns the path prefix up to depth segments.
// pathPrefixDepth("/api/v1/users/42", 2) → "/api/v1/"
// Returns the full path (with trailing slash) when depth >= segment count.
func pathPrefixDepth(p string, depth int) string {
	p = strings.TrimRight(p, "/")
	parts := strings.SplitN(p, "/", depth+2) // parts[0] is "" before leading /
	if len(parts) <= depth+1 {
		return p + "/"
	}
	return strings.Join(parts[:depth+1], "/") + "/"
}

// sanitizeName converts an arbitrary string to a safe signal name fragment:
// lowercase, non-alnum chars become underscores, leading/trailing underscores
// stripped, max 32 chars.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	name := strings.Trim(b.String(), "_")
	if len(name) > 32 {
		name = name[:32]
	}
	if name == "" {
		name = "custom"
	}
	return name
}

// benignExtensions lists file extensions that commonly appear in clean browser
// traffic; the PathExtensionAnalyzer skips them to suppress noise.
var benignExtensions = map[string]bool{
	".html": true, ".htm": true, ".js": true, ".mjs": true,
	".css": true, ".json": true, ".xml": true, ".txt": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".svg": true, ".ico": true, ".webp": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".map": true, ".ts": true,
}

// ── isTarpitted helper ────────────────────────────────────────────────────────

func isTarpitted(s persist.PathSample, threshold int) bool {
	return s.Decision == "tarpit" || s.Score >= threshold
}

func isClean(s persist.PathSample) bool {
	return s.Score == 0
}

// ── PathExtensionAnalyzer ────────────────────────────────────────────────────

// PathExtensionAnalyzer finds file extensions that appear almost exclusively
// in tarpitted requests and rarely in clean traffic. Produces path_suffix
// custom signals.
type PathExtensionAnalyzer struct{}

func NewPathExtensionAnalyzer() *PathExtensionAnalyzer { return &PathExtensionAnalyzer{} }
func (a *PathExtensionAnalyzer) Name() string          { return "path_extension" }

func (a *PathExtensionAnalyzer) Analyze(cfg AnalysisConfig, samples []persist.PathSample, totalTarpit, totalClean int) ([]SignalRecommendation, error) {
	type stat struct{ tarpit, clean int }
	counts := map[string]*stat{}

	for _, s := range samples {
		ext := pathExt(s.Path)
		if ext == "" || benignExtensions[ext] {
			continue
		}
		if _, ok := counts[ext]; !ok {
			counts[ext] = &stat{}
		}
		if isTarpitted(s, cfg.TarpitThreshold) {
			counts[ext].tarpit++
		} else if isClean(s) {
			counts[ext].clean++
		}
	}

	safeClean := max1(totalClean)
	var recs []SignalRecommendation
	for ext, st := range counts {
		total := st.tarpit + st.clean
		if total == 0 {
			continue
		}
		confidence := float64(st.tarpit) / float64(total)
		fpRate := float64(st.clean) / float64(safeClean)
		name := "auto_ext_" + sanitizeName(ext[1:]) // strip leading dot
		recs = append(recs, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("Requests with path extension %s", ext),
			Confidence:        confidence,
			Support:           st.tarpit,
			FalsePositiveRate: fpRate,
			Rationale: fmt.Sprintf(
				"Extension %s found in %d tarpitted requests vs %d clean (%.0f%% precision).",
				ext, st.tarpit, st.clean, confidence*100,
			),
			Source: a.Name(),
			Signal: rules.CustomSignal{
				Name:        name,
				Description: fmt.Sprintf("%s extension probe (auto-suggested)", ext),
				Enabled:     false,
				Points:      15,
				Conditions: []rules.CustomSignalCondition{
					{Type: "path_suffix", Value: ext},
				},
			},
		})
	}
	return recs, nil
}

// ── PathPrefixAnalyzer ───────────────────────────────────────────────────────

// PathPrefixAnalyzer clusters tarpitted request paths by depth-2 prefix and
// finds prefixes that appear only (or mostly) in attack traffic. Produces
// path_prefix custom signals.
type PathPrefixAnalyzer struct{}

func NewPathPrefixAnalyzer() *PathPrefixAnalyzer { return &PathPrefixAnalyzer{} }
func (a *PathPrefixAnalyzer) Name() string        { return "path_prefix" }

func (a *PathPrefixAnalyzer) Analyze(cfg AnalysisConfig, samples []persist.PathSample, totalTarpit, totalClean int) ([]SignalRecommendation, error) {
	type stat struct{ tarpit, clean int }
	counts := map[string]*stat{}

	for _, s := range samples {
		prefix := pathPrefixDepth(s.Path, 2)
		if len(prefix) <= 2 || prefix == "/" { // skip root
			continue
		}
		if _, ok := counts[prefix]; !ok {
			counts[prefix] = &stat{}
		}
		if isTarpitted(s, cfg.TarpitThreshold) {
			counts[prefix].tarpit++
		} else if isClean(s) {
			counts[prefix].clean++
		}
	}

	safeClean := max1(totalClean)
	var recs []SignalRecommendation
	for prefix, st := range counts {
		total := st.tarpit + st.clean
		if total == 0 {
			continue
		}
		confidence := float64(st.tarpit) / float64(total)
		fpRate := float64(st.clean) / float64(safeClean)
		name := "auto_pfx_" + sanitizeName(prefix)
		recs = append(recs, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("Requests to path prefix %s", prefix),
			Confidence:        confidence,
			Support:           st.tarpit,
			FalsePositiveRate: fpRate,
			Rationale: fmt.Sprintf(
				"Path prefix %s seen in %d tarpitted vs %d clean requests (%.0f%% precision).",
				prefix, st.tarpit, st.clean, confidence*100,
			),
			Source: a.Name(),
			Signal: rules.CustomSignal{
				Name:        name,
				Description: fmt.Sprintf("Requests under %s (auto-suggested)", prefix),
				Enabled:     false,
				Points:      20,
				Conditions: []rules.CustomSignalCondition{
					{Type: "path_prefix", Value: prefix},
				},
			},
		})
	}
	return recs, nil
}

// ── UASubstringAnalyzer ──────────────────────────────────────────────────────

// UASubstringAnalyzer reads the features_rollup table for ua_token entries with
// a high agent-posterior and maps them to ua_contains custom signals. This
// complements the ML miner: the miner activates a Bayes rule; this analyzer
// produces a deterministic signal that fires without needing ML to be warm.
type UASubstringAnalyzer struct {
	store *persist.Store
}

func NewUASubstringAnalyzer(store *persist.Store) *UASubstringAnalyzer {
	return &UASubstringAnalyzer{store: store}
}
func (a *UASubstringAnalyzer) Name() string { return "ua_substring" }

func (a *UASubstringAnalyzer) Analyze(cfg AnalysisConfig, _ []persist.PathSample, totalTarpit, totalClean int) ([]SignalRecommendation, error) {
	rows, err := a.store.QueryRollup()
	if err != nil {
		return nil, err
	}

	safeClean := max1(totalClean)
	var recs []SignalRecommendation
	for _, row := range rows {
		if row.Feature != "ua_token" {
			continue
		}
		token := row.Bucket
		if len(token) < 3 || looksLikeVersion(token) {
			continue
		}
		support := row.AgentCount + row.HumanCount
		// Beta(1,1) posterior — same formula as the miner.
		confidence := float64(row.AgentCount+1) / float64(support+2)
		fpRate := float64(row.HumanCount) / float64(safeClean)
		name := "auto_ua_" + sanitizeName(token)
		recs = append(recs, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("User-Agent containing '%s'", token),
			Confidence:        confidence,
			Support:           row.AgentCount,
			FalsePositiveRate: fpRate,
			Rationale: fmt.Sprintf(
				"UA token '%s' has %d agent-labeled vs %d human-labeled observations (%.0f%% posterior).",
				token, row.AgentCount, row.HumanCount, confidence*100,
			),
			Source: a.Name(),
			Signal: rules.CustomSignal{
				Name:        name,
				Description: fmt.Sprintf("User-Agent containing '%s' (auto-suggested)", token),
				Enabled:     false,
				Points:      20,
				Conditions: []rules.CustomSignalCondition{
					{Type: "ua_contains", Value: token},
				},
			},
		})
	}
	return recs, nil
}

// looksLikeVersion returns true for tokens that are version strings, short
// numerics, or single characters — these make poor UA substrings for matching.
func looksLikeVersion(s string) bool {
	if len(s) <= 2 {
		return true
	}
	// Purely numeric or version-shaped "1.2.3"
	allNumDot := true
	for _, r := range s {
		if !(r >= '0' && r <= '9') && r != '.' {
			allNumDot = false
			break
		}
	}
	return allNumDot
}

// ── MethodComboAnalyzer ──────────────────────────────────────────────────────

// MethodComboAnalyzer finds (HTTP method, path prefix) pairs that appear
// almost exclusively in tarpitted requests. Produces two-condition custom
// signals combining method and path_prefix.
type MethodComboAnalyzer struct{}

func NewMethodComboAnalyzer() *MethodComboAnalyzer { return &MethodComboAnalyzer{} }
func (a *MethodComboAnalyzer) Name() string         { return "method_combo" }

func (a *MethodComboAnalyzer) Analyze(cfg AnalysisConfig, samples []persist.PathSample, totalTarpit, totalClean int) ([]SignalRecommendation, error) {
	type key struct{ method, prefix string }
	type stat struct{ tarpit, clean int }
	counts := map[key]*stat{}

	for _, s := range samples {
		m := strings.ToUpper(s.Method)
		if m == "GET" || m == "HEAD" || m == "OPTIONS" { // these alone are rarely suspicious
			continue
		}
		prefix := pathPrefixDepth(s.Path, 1)
		if prefix == "/" {
			continue
		}
		k := key{m, prefix}
		if _, ok := counts[k]; !ok {
			counts[k] = &stat{}
		}
		if isTarpitted(s, cfg.TarpitThreshold) {
			counts[k].tarpit++
		} else if isClean(s) {
			counts[k].clean++
		}
	}

	safeClean := max1(totalClean)
	var recs []SignalRecommendation
	for k, st := range counts {
		total := st.tarpit + st.clean
		if total == 0 {
			continue
		}
		confidence := float64(st.tarpit) / float64(total)
		fpRate := float64(st.clean) / float64(safeClean)
		name := "auto_combo_" + sanitizeName(k.method) + "_" + sanitizeName(k.prefix)
		recs = append(recs, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("%s requests to %s", k.method, k.prefix),
			Confidence:        confidence,
			Support:           st.tarpit,
			FalsePositiveRate: fpRate,
			Rationale: fmt.Sprintf(
				"%s %s seen in %d tarpitted vs %d clean requests (%.0f%% precision).",
				k.method, k.prefix, st.tarpit, st.clean, confidence*100,
			),
			Source: a.Name(),
			Signal: rules.CustomSignal{
				Name:        name,
				Description: fmt.Sprintf("%s to %s (auto-suggested)", k.method, k.prefix),
				Enabled:     false,
				Points:      25,
				Conditions: []rules.CustomSignalCondition{
					{Type: "method", Value: k.method},
					{Type: "path_prefix", Value: k.prefix},
				},
			},
		})
	}
	return recs, nil
}

// ── UAPathComboAnalyzer ──────────────────────────────────────────────────────

// UAPathComboAnalyzer finds (UA leading token, path prefix) pairs that are
// strongly predictive of attack traffic and unlikely in clean traffic. Produces
// two-condition signals combining ua_contains and path_prefix.
type UAPathComboAnalyzer struct{}

func NewUAPathComboAnalyzer() *UAPathComboAnalyzer { return &UAPathComboAnalyzer{} }
func (a *UAPathComboAnalyzer) Name() string         { return "ua_path_combo" }

func (a *UAPathComboAnalyzer) Analyze(cfg AnalysisConfig, samples []persist.PathSample, totalTarpit, totalClean int) ([]SignalRecommendation, error) {
	type key struct{ uaToken, prefix string }
	type stat struct{ tarpit, clean int }
	counts := map[key]*stat{}

	for _, s := range samples {
		if s.UserAgent == "" {
			continue
		}
		tok := uaLeadingToken(s.UserAgent)
		if len(tok) < 3 || looksLikeVersion(tok) {
			continue
		}
		prefix := pathPrefixDepth(s.Path, 1)
		if prefix == "/" {
			continue
		}
		k := key{tok, prefix}
		if _, ok := counts[k]; !ok {
			counts[k] = &stat{}
		}
		if isTarpitted(s, cfg.TarpitThreshold) {
			counts[k].tarpit++
		} else if isClean(s) {
			counts[k].clean++
		}
	}

	safeClean := max1(totalClean)
	var recs []SignalRecommendation
	for k, st := range counts {
		total := st.tarpit + st.clean
		if total == 0 {
			continue
		}
		confidence := float64(st.tarpit) / float64(total)
		fpRate := float64(st.clean) / float64(safeClean)
		name := "auto_ua_path_" + sanitizeName(k.uaToken) + "_" + sanitizeName(k.prefix)
		recs = append(recs, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("UA containing '%s' accessing %s", k.uaToken, k.prefix),
			Confidence:        confidence,
			Support:           st.tarpit,
			FalsePositiveRate: fpRate,
			Rationale: fmt.Sprintf(
				"UA token '%s' + path prefix '%s': %d tarpitted vs %d clean (%.0f%% precision).",
				k.uaToken, k.prefix, st.tarpit, st.clean, confidence*100,
			),
			Source: a.Name(),
			Signal: rules.CustomSignal{
				Name:        name,
				Description: fmt.Sprintf("UA '%s' accessing %s (auto-suggested)", k.uaToken, k.prefix),
				Enabled:     false,
				Points:      25,
				Conditions: []rules.CustomSignalCondition{
					{Type: "ua_contains", Value: k.uaToken},
					{Type: "path_prefix", Value: k.prefix},
				},
			},
		})
	}
	return recs, nil
}

// uaLeadingToken extracts the first meaningful word from a User-Agent string:
// the text before the first "/" or space, lowercased. This catches "python-requests",
// "curl", "sqlmap", "nuclei", etc. without matching overly generic tokens.
func uaLeadingToken(ua string) string {
	ua = strings.TrimSpace(strings.ToLower(ua))
	if i := strings.IndexAny(ua, "/ "); i > 0 {
		return ua[:i]
	}
	if len(ua) > 30 {
		return ua[:30]
	}
	return ua
}

// max1 returns n if n > 0, else 1. Prevents division-by-zero in rate calculations.
func max1(n int) int {
	if n > 0 {
		return n
	}
	return 1
}
