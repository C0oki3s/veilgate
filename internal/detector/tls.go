package detector

// TLSLookup is the interface the scorer uses to ask for a TLS fingerprint
// classification for a given remote address. Implemented by the tlsfp package.
type TLSLookup interface {
	// Classify returns a label, category, and confidence for the client.
	// Returns ok=false if no fingerprint is available (e.g. plain HTTP).
	Classify(remoteAddr string) (label, category string, confidence int, ok bool)
}

// SetTLSLookup wires a TLS fingerprint source into the scorer.
func (s *Scorer) SetTLSLookup(l TLSLookup) { s.tls = l }
