// Package telemetry — endpoint correlation helpers.
//
// # What this file tracks
//
// Every scored request contributes to four Prometheus counter vectors that let
// operators answer attack-investigation questions without grepping logs:
//
//  1. veilgate_endpoint_signal_total{path_bucket, signal, method, decision}
//     Which exact signals fire on which endpoints, and what VeilGate did.
//     Example: injection_marker fires on POST /api/users/{id} → tarpit.
//
//  2. veilgate_endpoint_attack_family_total{path_bucket, family, method, decision}
//     Same data grouped into 9 attack families (recon, auth, injection, evasion,
//     fingerprint, behavioral, fleet, toolchain, ml). One request can emit
//     multiple families. Use for a heat-map of "what attack type is hitting which
//     endpoint" without knowing all 40+ signal names.
//
//  3. veilgate_endpoint_score_tier_total{path_bucket, tier, decision}
//     Attack severity per endpoint: critical(≥80), high(60-79), medium(40-59),
//     low(<40). Use to rank which endpoints deserve the most attention.
//
//  4. veilgate_endpoint_request_total{path_bucket, method, decision}
//     Total requests per endpoint/method/decision. The denominator for
//     rate(veilgate_endpoint_signal_total[5m]) / rate(veilgate_endpoint_request_total[5m])
//     which gives signal hit-rate per endpoint — a normalised attack pressure metric.
//
// # Node correlation model
//
// A "node" in the correlation graph is a (path_bucket, attack_family) pair.
// Edges are implicit through shared {path_bucket} labels: any two signals
// (or families) with the same path_bucket fired on the same endpoint pattern
// and can be joined in Grafana/Prometheus with:
//
//   sum by (signal) (rate(veilgate_endpoint_signal_total{path_bucket="/api/auth/{id}"}[5m]))
//
// This shows every signal type hitting the auth endpoint — a full "node neighbourhood".
//
// # Path normalisation
//
// To prevent cardinality explosion while keeping endpoints meaningful:
//   - UUID segments  (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) → {id}
//   - Pure numeric   (12345)                                → {id}
//   - Long hex token (20+ hex chars)                       → {id}
//   - Depth capped at 4 segments                           → prevents /a/b/c/d/e/f proliferation
//
// Examples:
//   /api/users/550e8400-e29b-41d4-a716-446655440000/profile → /api/users/{id}/profile
//   /v1/orders/99182                                        → /v1/orders/{id}
//   /api/internal/session/abc123def456789012               → /api/internal/session/{id}
package telemetry

import (
	"regexp"
	"strings"
)

// ── Path normalisation ────────────────────────────────────────────────────────

var (
	uuidSegRE    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	numericSegRE = regexp.MustCompile(`^\d+$`)
	hexIDSegRE   = regexp.MustCompile(`^[0-9a-f]{20,}$`)
)

const maxPathBucketSegments = 4

// NormalizePath collapses high-cardinality path segments and caps depth.
// See package doc for examples.
func NormalizePath(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > maxPathBucketSegments {
		parts = parts[:maxPathBucketSegments]
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		if p == "" {
			out[i] = p
			continue
		}
		if uuidSegRE.MatchString(p) || numericSegRE.MatchString(p) || hexIDSegRE.MatchString(p) {
			out[i] = "{id}"
		} else {
			out[i] = p
		}
	}
	return "/" + strings.Join(out, "/")
}

// ── Attack family classification ─────────────────────────────────────────────

// SignalFamily maps every VeilGate signal name to one of nine attack family
// labels used in veilgate_endpoint_attack_family_total. Unknown signal names
// fall through to "other".
//
// Family definitions:
//
//	recon       — API schema discovery, path enumeration, directory bruteforce
//	auth        — auth endpoint probing, cookie/session attacks, credential replay
//	injection   — SQLi/XSS/SSTI markers, OOB interaction payloads, encoding tricks
//	evasion     — TLS/H2 fingerprint spoofing, header manipulation, encoding obfuscation
//	fingerprint — non-browser TLS/H2/UA/header patterns (passive, not attack intent)
//	behavioral  — anomalous session patterns, timing, cache abuse
//	fleet       — IP rotation, proxy pools, IP reputation list hits
//	toolchain   — recognised pentest tool sequences (sqlmap, nikto, nuclei …)
//	ml          — Isolation Forest + Bayes composite score
func SignalFamily(name string) string {
	switch name {
	// recon — active API discovery, path enumeration
	case "schema_first",
		"api_blueprint_miss",
		"path_bruteforce",
		"wordlist_path",
		"fanout_extreme",
		"fanout_high",
		"graph_flat":
		return "recon"

	// auth — credential and session attacks
	case "auth_probe_sequence",
		"no_cookie_return",
		"cookie_stateless",
		"canary_replay":
		return "auth"

	// injection — payload-based attacks
	case "injection_marker",
		"oob_interaction",
		"encoding_chain":
		return "injection"

	// evasion — active techniques to hide from detection
	case "header_mutation",
		"ua_rotation",
		"tls_agent",
		"h2_agent":
		return "evasion"

	// fingerprint — passive non-browser signatures (not necessarily malicious)
	case "sparse_headers",
		"empty_ua",
		"suspicious_ua",
		"sec_fetch_absent",
		"sec_fetch_partial",
		"ae_browser_empty",
		"ae_browser_no_br",
		"h3_mismatch",
		"tls_bot",
		"tls_non_browser",
		"h2_bot",
		"h2_non_browser":
		return "fingerprint"

	// behavioral — session-level anomalies
	case "cache_miss_anomaly",
		"regular_timing",
		"bundle_mining",
		"recovery_pivot",
		"graph_doc_heavy":
		return "behavioral"

	// fleet — distributed attack infrastructure
	case "ip_rotation_fleet",
		"ip_reputation":
		return "fleet"

	// toolchain — recognised attack tool sequences
	case "toolchain_full",
		"toolchain_partial",
		"toolchain_hmm",
		"toolchain_hmm_partial":
		return "toolchain"

	// ml — composite ML score
	case "ml_agent_score":
		return "ml"
	}
	return "other"
}

// ── Score tier ────────────────────────────────────────────────────────────────

// ScoreTier maps a numeric total score (0-100) to a human-readable severity
// tier used in veilgate_endpoint_score_tier_total.
//
//	critical — ≥ 80: almost certainly an automated attacker; tarpitted or challenged
//	high     — 60-79: strong bot signals; usually challenged or tarpitted
//	medium   — 40-59: suspicious but ambiguous; reviewed or observed
//	low      — < 40: minor signals only; typically passed to upstream
func ScoreTier(total int) string {
	switch {
	case total >= 80:
		return "critical"
	case total >= 60:
		return "high"
	case total >= 40:
		return "medium"
	default:
		return "low"
	}
}

// ── Unified observation call ──────────────────────────────────────────────────

// ObserveEndpoint is the single call site for all endpoint correlation metrics.
// Call it once per scored request that has at least one fired signal OR that
// has a non-zero score (so score-tier counts are always populated).
//
// It emits:
//   - EndpointRequestTotal once (always)
//   - EndpointScoreTierTotal once (always)
//   - EndpointSignalTotal once per signal in signalNames
//   - EndpointAttackFamilyTotal once per distinct attack family fired
func ObserveEndpoint(path, method, decision string, score int, signalNames []string) {
	bucket := NormalizePath(path)

	// Normalise method — cap to 10 chars to prevent label abuse from
	// malformed HTTP methods sent by scanners.
	m := method
	if len(m) > 10 {
		m = m[:10]
	}

	EndpointRequestTotal.WithLabelValues(bucket, m, decision).Inc()
	EndpointScoreTierTotal.WithLabelValues(bucket, ScoreTier(score), decision).Inc()

	if len(signalNames) == 0 {
		return
	}

	// Emit per-signal counts and collect distinct families in one pass.
	families := make(map[string]struct{}, 4)
	for _, name := range signalNames {
		EndpointSignalTotal.WithLabelValues(bucket, name, m, decision).Inc()
		families[SignalFamily(name)] = struct{}{}
	}
	for fam := range families {
		EndpointAttackFamilyTotal.WithLabelValues(bucket, fam, m, decision).Inc()
	}
}

// ── Content-type category (used by tarpit) ────────────────────────────────────

// ContentTypeCategory maps a Content-Type header value to the short label
// used in TarpitTemplateTypeTotal.
func ContentTypeCategory(ct string) string {
	ct = toLower(ct)
	switch {
	case containsStr(ct, "graphql"):
		return "graphql"
	case containsStr(ct, "json"):
		return "json"
	case containsStr(ct, "html"):
		return "html"
	case containsStr(ct, "text/"):
		return "text"
	default:
		return "other"
	}
}

// ObserveEndpointSignals is a backwards-compatible shim for callers that only
// have signal names (no method/decision/score). Prefer ObserveEndpoint.
func ObserveEndpointSignals(path string, signalNames []string) {
	ObserveEndpoint(path, "unknown", "unknown", 0, signalNames)
}
