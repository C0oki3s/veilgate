// Package verifier exposes a short-circuit chain of authenticators
// the proxy consults before falling back to the score system.
//
// Each Verifier implementation answers "is this request from a client
// I should trust?" for one specific class of credential: an HMAC
// signature header, a JWT bearer token, a TLS-terminator-set client
// cert fingerprint, etc. The chain is ordered; the first verifier
// that accepts wins.
//
// Verifier acceptance does NOT bypass the score system — a request
// can be accepted here and still be tarpitted if its behavioural
// score is ≥ tarpit_threshold. That same "cookie can't whitewash
// attack behaviour" rule that keeps the PoW cookie honest applies
// uniformly across every verifier.
package verifier

import (
	"net/http"
)

// Result is what a Verifier returns.
//
// Accepted=true means "I recognise this credential and the caller
// should be treated as legitimate." Reason is logged for audit and
// debugging; it MUST NOT include secret material.
type Result struct {
	Accepted bool
	Name     string // verifier name (e.g. "hmac", "mtls"); empty when Accepted is false
	Client   string // operator-supplied client ID this credential maps to; empty when not applicable
	Reason   string // short, redacted description for audit
}

// A Verifier accepts or rejects one request based on a specific
// credential shape. Verifiers must be safe for concurrent use.
type Verifier interface {
	// Name is the verifier's stable identifier, used for config keys
	// and audit log entries.
	Name() string
	// Verify inspects the request and returns a Result. A nil-Verifier
	// is never installed; the chain skips disabled verifiers via
	// configuration rather than nil checks.
	Verify(r *http.Request) Result
}

// Discoverable is implemented by verifiers that want to advertise
// the credential shape they accept on the /_g/config
// discovery endpoint. Implementing it is optional: a verifier that
// does not advertise (e.g. HMAC, where the client-secret pairing is
// out-of-band) simply omits Describe.
type Discoverable interface {
	Describe() CredentialDescriptor
}

// CredentialDescriptor is the JSON shape exposed by the discovery
// endpoint so a client SDK can auto-attach the right credential
// without hardcoding cookie/header names. Each field is optional —
// only the fields meaningful for the credential type are populated.
type CredentialDescriptor struct {
	// Type is one of "bearer", "cookie", "header". Required.
	Type string `json:"type"`
	// Name is the cookie or header name (for cookie / header types).
	Name string `json:"name,omitempty"`
	// Header is the request header (for bearer type).
	Header string `json:"header,omitempty"`
	// Scheme is the prefix the bearer header expects (e.g. "Bearer").
	// Empty when the bearer is configured in raw-token mode.
	Scheme string `json:"scheme,omitempty"`
	// Validator names the validator implementation behind a cookie or
	// header verifier ("opaque", "jwt", "callout"). Clients can use
	// this to know whether the credential is short-lived (so they
	// shouldn't aggressively cache it).
	Validator string `json:"validator,omitempty"`
}

// Chain is a short-circuit list of verifiers. Verify returns the
// first Accepted result, or a zero-value Result if no verifier
// accepted.
type Chain struct {
	verifiers []Verifier
}

// NewChain builds a chain. Verifiers are consulted in argument order.
// A nil entry is dropped — caller's responsibility to enable/disable
// via config before passing in.
func NewChain(vs ...Verifier) *Chain {
	out := make([]Verifier, 0, len(vs))
	for _, v := range vs {
		if v != nil {
			out = append(out, v)
		}
	}
	return &Chain{verifiers: out}
}

// Verify walks the chain. Returns the first acceptance, or a zero
// Result when none accept.
func (c *Chain) Verify(r *http.Request) Result {
	if c == nil {
		return Result{}
	}
	for _, v := range c.verifiers {
		if res := v.Verify(r); res.Accepted {
			return res
		}
	}
	return Result{}
}

// VerifyExcept walks the chain while skipping verifiers named in skip.
// It is used by upload policies that must avoid body-sensitive
// verifiers such as HMAC on large streaming request bodies.
func (c *Chain) VerifyExcept(r *http.Request, skip map[string]struct{}) Result {
	if c == nil {
		return Result{}
	}
	for _, v := range c.verifiers {
		if _, ok := skip[v.Name()]; ok {
			continue
		}
		if res := v.Verify(r); res.Accepted {
			return res
		}
	}
	return Result{}
}

// Len returns the number of installed verifiers. Useful for tests and
// for the audit log so we can emit "chain has N verifiers configured"
// at startup.
func (c *Chain) Len() int {
	if c == nil {
		return 0
	}
	return len(c.verifiers)
}

// Describe returns one CredentialDescriptor per Discoverable
// verifier in the chain, in chain order. Verifiers that do not
// implement Discoverable (e.g. HMAC) are omitted — the discovery
// surface is for what a client SDK can attach, not a full audit of
// what is installed.
func (c *Chain) Describe() []CredentialDescriptor {
	if c == nil {
		return nil
	}
	out := make([]CredentialDescriptor, 0, len(c.verifiers))
	for _, v := range c.verifiers {
		if d, ok := v.(Discoverable); ok {
			out = append(out, d.Describe())
		}
	}
	return out
}
