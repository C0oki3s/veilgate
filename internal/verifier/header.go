package verifier

import (
	"net/http"
	"strings"
)

// HeaderVerifier accepts a request when a named request header
// carries a value the configured Validator approves. It is the
// header-shaped sibling of CookieVerifier and shares the validator
// surface — switching from a cookie to a header (or vice-versa) is
// a yaml change, not a code change.
//
// Use cases:
//
//   - Cloudflare Access JWT pass-through (CF-Access-Jwt-Assertion)
//   - Internal service tokens on a custom header
//   - API gateway-injected identity headers
//
// For the `Authorization: Bearer …` shape with opaque tokens, prefer
// the dedicated BearerVerifier — it knows how to strip the scheme.
// HeaderVerifier treats the entire header value as the credential.
type HeaderVerifier struct {
	hdrName    string
	hdrDisplay string // original casing for audit + Name()
	validator  Validator
}

// NewHeaderVerifier wires a header name to a validator.
func NewHeaderVerifier(headerName string, v Validator) (*HeaderVerifier, error) {
	if headerName == "" {
		return nil, &configError{"header verifier: name is required"}
	}
	if v == nil {
		return nil, &configError{"header verifier: validator is required"}
	}
	return &HeaderVerifier{
		hdrName:    http.CanonicalHeaderKey(headerName),
		hdrDisplay: headerName,
		validator:  v,
	}, nil
}

// Name implements Verifier. Disambiguated by header name so multiple
// header verifiers in the chain produce distinct audit lines.
func (h *HeaderVerifier) Name() string {
	return "header:" + h.hdrDisplay
}

// HeaderName exposes the configured header for the /_g/config
// discovery endpoint.
func (h *HeaderVerifier) HeaderName() string { return h.hdrDisplay }

// ValidatorType exposes the underlying validator type for discovery
// and audit.
func (h *HeaderVerifier) ValidatorType() string { return h.validator.Type() }

// Describe implements Discoverable.
func (h *HeaderVerifier) Describe() CredentialDescriptor {
	return CredentialDescriptor{
		Type:      "header",
		Name:      h.hdrDisplay,
		Validator: h.validator.Type(),
	}
}

// Verify implements Verifier. Header absence is a zero Result;
// presence with a bad value produces a non-empty reason for audit.
func (h *HeaderVerifier) Verify(r *http.Request) Result {
	raw := strings.TrimSpace(r.Header.Get(h.hdrName))
	if raw == "" {
		return Result{}
	}
	client, ok, reason := h.validator.Validate(raw)
	if !ok {
		return rejected(h.Name(), reason)
	}
	return Result{
		Accepted: true,
		Name:     h.Name(),
		Client:   client,
		Reason:   "valid " + h.validator.Type() + " header",
	}
}
