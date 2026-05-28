package detector

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// scoreToolchain flags classic scanner sequences: recon → probe → exploit.
func (s *Scorer) scoreToolchain(events []ClientEvent) Signal {
	tc := s.rules.Toolchain
	if len(events) < 4 {
		return Signal{}
	}
	sawRecon, sawProbe, sawExploit := false, false, false
	for _, e := range events {
		p := strings.ToLower(e.Path + "?" + e.Query)
		for _, r := range tc.ReconPaths {
			if strings.Contains(p, r) {
				sawRecon = true
			}
		}
		for _, pr := range tc.ProbePaths {
			if strings.Contains(p, pr) {
				sawProbe = true
			}
		}
		for _, ex := range tc.ExploitMarkers {
			if strings.Contains(p, ex) {
				sawExploit = true
			}
		}
	}
	stages := 0
	for _, b := range []bool{sawRecon, sawProbe, sawExploit} {
		if b {
			stages++
		}
	}
	switch stages {
	case 3:
		return Signal{Name: "toolchain_full", Points: tc.Points.Full,
			Reason: "observed recon + probe + exploit sequence"}
	case 2:
		return Signal{Name: "toolchain_partial", Points: tc.Points.Partial,
			Reason: "observed two pentest stages"}
	}
	return Signal{}
}

// scoreToolchainHMM scores the ordered sequence of (recon, probe, exploit)
// labels across the rolling event history.
func (s *Scorer) scoreToolchainHMM(events []ClientEvent) Signal {
	if len(events) < 5 {
		return Signal{}
	}
	var seq []string
	for _, e := range events {
		if e.ToolStage == "" {
			continue
		}
		if len(seq) > 0 && seq[len(seq)-1] == e.ToolStage {
			continue
		}
		seq = append(seq, e.ToolStage)
	}
	if len(seq) < 2 {
		return Signal{}
	}
	idx := 0
	want := []string{"recon", "probe", "exploit"}
	for _, st := range seq {
		if st == want[idx] {
			idx++
			if idx == len(want) {
				return Signal{Name: "toolchain_hmm", Points: 20,
					Reason: "observed ordered recon→probe→exploit pattern across visits"}
			}
		}
	}
	for i := 0; i+1 < len(seq); i++ {
		if seq[i] == "recon" && seq[i+1] == "probe" {
			return Signal{Name: "toolchain_hmm_partial", Points: 8,
				Reason: "observed ordered recon→probe pattern"}
		}
		if seq[i] == "probe" && seq[i+1] == "exploit" {
			return Signal{Name: "toolchain_hmm_partial", Points: 12,
				Reason: "observed ordered probe→exploit pattern"}
		}
	}
	return Signal{}
}

// scorePathBruteforce detects one client rapidly walking a wordlist.
func (s *Scorer) scorePathBruteforce(events []ClientEvent) Signal {
	tiers := s.rules.PathBruteforce.Tiers
	if len(tiers) == 0 || len(events) < 2 {
		return Signal{}
	}
	seen := make(map[string]struct{}, len(events))
	for _, e := range events {
		seen[e.Path] = struct{}{}
	}
	distinct := len(seen)
	for _, tier := range tiers {
		if distinct >= tier.DistinctPaths {
			return Signal{
				Name:   "path_bruteforce",
				Points: tier.Points,
				Reason: fmt.Sprintf("client hit %d distinct paths inside the window (wordlist bruteforce)", distinct),
			}
		}
	}
	return Signal{}
}

// scoreWordlistPath matches the request path against known dirsearch/nikto
// wordlist markers.
func (s *Scorer) scoreWordlistPath(r *http.Request) Signal {
	cfg := s.rules.WordlistPaths
	if cfg.Points == 0 || len(cfg.Substrings) == 0 {
		return Signal{}
	}
	path := strings.ToLower(r.URL.Path)
	for _, sub := range cfg.Substrings {
		if strings.Contains(path, strings.ToLower(sub)) {
			return Signal{
				Name:   "wordlist_path",
				Points: cfg.Points,
				Reason: "path matches known scanner wordlist entry: " + sub,
			}
		}
	}
	return Signal{}
}

// scoreInjection looks for attack payload markers in the URL and headers.
func (s *Scorer) scoreInjection(r *http.Request) Signal {
	cfg := s.rules.InjectionMarkers
	if cfg.Points == 0 || len(cfg.Substrings) == 0 {
		return Signal{}
	}
	haystacks := []string{
		strings.ToLower(r.URL.Path),
		strings.ToLower(r.URL.RawQuery),
	}
	if r.Body != nil && (r.ContentLength >= 0 && r.ContentLength <= 64*1024) {
		body, err := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err == nil && len(body) > 0 {
			haystacks = append(haystacks, strings.ToLower(string(body)))
		}
	}
	if len(cfg.Headers) == 0 {
		for _, vs := range r.Header {
			for _, v := range vs {
				haystacks = append(haystacks, strings.ToLower(v))
			}
		}
	} else {
		for _, h := range cfg.Headers {
			if v := r.Header.Get(h); v != "" {
				haystacks = append(haystacks, strings.ToLower(v))
			}
		}
		for _, h := range cfg.Headers {
			if strings.EqualFold(h, "Host") && r.Host != "" {
				haystacks = append(haystacks, strings.ToLower(r.Host))
			}
		}
	}
	for _, sub := range cfg.Substrings {
		needle := strings.ToLower(sub)
		for _, h := range haystacks {
			if strings.Contains(h, needle) {
				return Signal{
					Name:   "injection_marker",
					Points: cfg.Points,
					Reason: "request contains attack payload marker: " + sub,
				}
			}
		}
	}
	return Signal{}
}

// scoreOOB flags out-of-band callback hosts used by Burp Collaborator,
// interactsh, webhook.site, etc.
func (s *Scorer) scoreOOB(r *http.Request) Signal {
	cfg := s.rules.OOBInteraction
	if cfg.Points == 0 || len(cfg.Substrings) == 0 {
		return Signal{}
	}
	candidates := []string{
		strings.ToLower(r.URL.Path),
		strings.ToLower(r.URL.RawQuery),
		strings.ToLower(r.Host),
	}
	for _, vs := range r.Header {
		for _, v := range vs {
			candidates = append(candidates, strings.ToLower(v))
		}
	}
	for _, sub := range cfg.Substrings {
		needle := strings.ToLower(sub)
		for _, h := range candidates {
			if strings.Contains(h, needle) {
				return Signal{
					Name:   "oob_interaction",
					Points: cfg.Points,
					Reason: "request references OOB callback host: " + sub,
				}
			}
		}
	}
	return Signal{}
}

// classifyToolStage tags one request as belonging to the recon/probe/exploit
// phase of a pentest pipeline, or "" when no marker matches.
func classifyToolStage(r *http.Request, d *rules.Detector) string {
	if d == nil {
		return ""
	}
	hay := strings.ToLower(r.URL.Path + "?" + r.URL.RawQuery)
	for _, ex := range d.Toolchain.ExploitMarkers {
		if strings.Contains(hay, strings.ToLower(ex)) {
			return "exploit"
		}
	}
	for _, p := range d.Toolchain.ProbePaths {
		if strings.Contains(hay, strings.ToLower(p)) {
			return "probe"
		}
	}
	for _, p := range d.Toolchain.ReconPaths {
		if strings.Contains(hay, strings.ToLower(p)) {
			return "recon"
		}
	}
	return ""
}
