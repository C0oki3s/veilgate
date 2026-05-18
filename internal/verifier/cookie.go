package verifier

import (
	"net/http"
)

// CookieVerifier accepts a request when a named cookie carries a
// value the configured Validator approves. The cookie + validator
// design lets operators bridge their existing session systems into
// VeilGate's bypass surface without writing Go code:
//
//	verifiers:
//	  cookies:
//	    - name: MY_AUTH_SESSION
//	      validator: opaque
//	      tokens_dir: /etc/veilgate/sessions
//	    - name: ACCESS_JWT
//	      validator: jwt           # ships in #4
//	      jwks_url: https://…/jwks
//
// Each entry produces one CookieVerifier in the chain; the chain
// short-circuits on the first acceptance.
type CookieVerifier struct {
	cookieName string
	validator  Validator
}

// NewCookieVerifier wires a cookie name to a validator. The caller
// constructs the validator (OpaqueValidator, JWTValidator, …) so
// validator-specific config validation happens once at startup.
func NewCookieVerifier(cookieName string, v Validator) (*CookieVerifier, error) {
	if cookieName == "" {
		return nil, &configError{"cookie verifier: name is required"}
	}
	if v == nil {
		return nil, &configError{"cookie verifier: validator is required"}
	}
	return &CookieVerifier{cookieName: cookieName, validator: v}, nil
}

// Name implements Verifier. The audit name disambiguates multiple
// cookie verifiers — useful when an operator runs both a session
// cookie and a CDN-set JWT cookie through the chain.
func (c *CookieVerifier) Name() string {
	return "cookie:" + c.cookieName
}

// CookieName exposes the configured cookie name for the audit log
// and the /__veilgate/.well-known discovery endpoint.
func (c *CookieVerifier) CookieName() string { return c.cookieName }

// ValidatorType exposes the underlying validator type for discovery
// and audit ("opaque", "jwt", …).
func (c *CookieVerifier) ValidatorType() string { return c.validator.Type() }

// Describe implements Discoverable.
func (c *CookieVerifier) Describe() CredentialDescriptor {
	return CredentialDescriptor{
		Type:      "cookie",
		Name:      c.cookieName,
		Validator: c.validator.Type(),
	}
}

// Verify implements Verifier.
//
// Cookie absence returns a zero Result so the chain continues
// quietly. Only an explicit reject (cookie present but value bad)
// produces an audit-worthy reason.
func (c *CookieVerifier) Verify(r *http.Request) Result {
	ck, err := r.Cookie(c.cookieName)
	if err != nil || ck == nil || ck.Value == "" {
		return Result{}
	}
	client, ok, reason := c.validator.Validate(ck.Value)
	if !ok {
		return rejected(c.Name(), reason)
	}
	return Result{
		Accepted: true,
		Name:     c.Name(),
		Client:   client,
		Reason:   "valid " + c.validator.Type() + " cookie",
	}
}
