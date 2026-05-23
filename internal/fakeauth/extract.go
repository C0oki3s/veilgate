package fakeauth

import "regexp"

// jwtPattern matches a complete 3-part JWT in any response body.
// Conservative: requires eyJ prefix on header and payload to avoid
// matching short base64 strings that happen to contain dots.
var jwtPattern = regexp.MustCompile(
	`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
)

// apiKeyPattern matches Stripe-style sk_live_ keys.
var apiKeyPattern = regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`)

// awsKeyPattern matches AWS access key IDs.
var awsKeyPattern = regexp.MustCompile(`AKIA[A-Z0-9]{16}`)

// sessionPattern matches Express connect.sid signed session cookies.
var sessionPattern = regexp.MustCompile(`s%3A[0-9a-f]{32}\.[A-Za-z0-9_-]{20,}`)

// ExtractCanaries returns all token strings found in body that should be
// registered in the canary table. Each returned string is one distinct token
// that, if replayed by a client, should fire the canary_replay signal.
func ExtractCanaries(body string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(tok string) {
		if _, dup := seen[tok]; !dup && tok != "" {
			seen[tok] = struct{}{}
			out = append(out, tok)
		}
	}
	for _, m := range jwtPattern.FindAllString(body, -1) {
		add(m)
	}
	for _, m := range apiKeyPattern.FindAllString(body, -1) {
		add(m)
	}
	for _, m := range awsKeyPattern.FindAllString(body, -1) {
		add(m)
	}
	for _, m := range sessionPattern.FindAllString(body, -1) {
		add(m)
	}
	return out
}
