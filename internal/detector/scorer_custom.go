package detector

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// applySignalConfig filters out disabled signals and applies points overrides
// from the signals.yaml registry.
func (s *Scorer) applySignalConfig(signals []Signal) []Signal {
	out := make([]Signal, 0, len(signals))
	for _, sig := range signals {
		entry, ok := s.signals.Signals[sig.Name]
		if ok && !entry.Enabled {
			continue
		}
		if ok && entry.Points > 0 {
			sig.Points = entry.Points
		}
		out = append(out, sig)
	}
	return out
}

// scoreCustomSignals evaluates all operator-defined custom signals from
// signals.yaml against the current request.
func (s *Scorer) scoreCustomSignals(r *http.Request) []Signal {
	if s.signals == nil || len(s.signals.CustomSignals) == 0 {
		return nil
	}
	path := strings.ToLower(r.URL.Path)
	ua := strings.ToLower(r.UserAgent())
	query := strings.ToLower(r.URL.RawQuery)

	var out []Signal
	for _, cs := range s.signals.CustomSignals {
		if !cs.Enabled || cs.Points == 0 || len(cs.Conditions) == 0 {
			continue
		}
		matched := true
		for _, cond := range cs.Conditions {
			if !s.matchCondition(r, cond, path, ua, query) {
				matched = false
				break
			}
		}
		if matched {
			out = append(out, Signal{
				Name:   cs.Name,
				Points: cs.Points,
				Reason: cs.Description,
			})
		}
	}
	return out
}

// matchCondition tests one condition from a custom signal against the request.
func (s *Scorer) matchCondition(r *http.Request, cond rules.CustomSignalCondition, path, ua, query string) bool {
	val := strings.ToLower(cond.Value)
	switch cond.Type {
	case "path_prefix":
		return strings.HasPrefix(path, val)
	case "path_contains":
		return strings.Contains(path, val)
	case "path_suffix":
		return strings.HasSuffix(path, val)
	case "path_regex":
		if re, ok := s.customRegexes[cond.Value]; ok {
			return re.MatchString(r.URL.Path)
		}
		if re, err := regexp.Compile(cond.Value); err == nil {
			return re.MatchString(r.URL.Path)
		}
		return false
	case "ua_contains":
		return strings.Contains(ua, val)
	case "header_present":
		return r.Header.Get(cond.Name) != ""
	case "header_value":
		return strings.Contains(strings.ToLower(r.Header.Get(cond.Name)), val)
	case "query_contains":
		return strings.Contains(query, val)
	case "method":
		return strings.EqualFold(r.Method, cond.Value)
	}
	return false
}

// scoreAPIBlueprintMiss fires when a request targets the operator's documented
// API namespace but the path is not present in the blueprint.
func (s *Scorer) scoreAPIBlueprintMiss(r *http.Request) Signal {
	if s.bp == nil || s.bp.IsEmpty() {
		return Signal{}
	}
	inNS, matched := s.bp.Lookup(r.URL.Path)
	if !inNS || matched {
		return Signal{}
	}
	return Signal{
		Name:   "api_blueprint_miss",
		Points: 15,
		Reason: "path is in the API namespace but not in the blueprint",
	}
}

