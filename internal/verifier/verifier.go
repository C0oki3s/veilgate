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

// Len returns the number of installed verifiers. Useful for tests and
// for the audit log so we can emit "chain has N verifiers configured"
// at startup.
func (c *Chain) Len() int {
	if c == nil {
		return 0
	}
	return len(c.verifiers)
}
