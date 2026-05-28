package detector

import (
	"fmt"
	"net/http"
	"time"
)

// scoreTLS consults the TLS fingerprint database.
func (s *Scorer) scoreTLS(remoteAddr string) Signal {
	if s.tls == nil {
		return Signal{}
	}
	label, category, conf, ok := s.tls.Classify(remoteAddr)
	if !ok {
		return Signal{}
	}
	switch category {
	case "agent", "scanner":
		points := 45
		if conf < 80 {
			points = 30
		}
		return Signal{Name: "tls_agent", Points: points,
			Reason: "TLS fingerprint matches known agent library: " + label}
	case "bot":
		return Signal{Name: "tls_bot", Points: 25,
			Reason: "TLS fingerprint matches known bot: " + label}
	case "unknown":
		return Signal{Name: "tls_non_browser", Points: 20,
			Reason: "TLS fingerprint does not match any known browser"}
	}
	return Signal{}
}

// scoreIPReputation tags the client IP against the operator-editable CIDR list.
func (s *Scorer) scoreIPReputation(clientID string) (Signal, string) {
	if s.ipRep == nil {
		return Signal{}, ""
	}
	cat, pts, ok := s.ipRep.Classify(clientID)
	if !ok || pts <= 0 {
		return Signal{}, ""
	}
	return Signal{
		Name:   "ip_reputation",
		Points: pts,
		Reason: "client IP matches " + cat + " CIDR list",
	}, cat
}

// scoreFleetRotation observes the current request's behavioural fingerprint
// and returns a signal when N distinct IPs have shared that fingerprint inside
// the rolling window.
func (s *Scorer) scoreFleetRotation(clientID string, r *http.Request, ja4 string) (Signal, string, int) {
	if s.fleet == nil || s.ipRep == nil || !s.ipRep.FleetRotation.Enabled {
		return Signal{}, "", 0
	}
	tiers := s.ipRep.FleetRotation.Tiers
	if len(tiers) == 0 {
		return Signal{}, "", 0
	}
	uaFam := UAFamilyFromUA(r.UserAgent())
	ja4p := ja4
	if len(ja4p) > 10 {
		ja4p = ja4p[:10]
	}
	hdr := headerBitmap(r)
	fp, distinct := s.fleet.Observe(clientID, uaFam, ja4p, hdr, r.Method, time.Now())
	for _, tier := range tiers {
		if distinct >= tier.DistinctIPs {
			return Signal{
				Name:   "ip_rotation_fleet",
				Points: tier.Points,
				Reason: fmt.Sprintf("%d distinct client IPs share fingerprint %s (ua=%s ja4=%s) — proxy/VPN rotation", distinct, fp, uaFam, ja4p),
			}, fp, distinct
		}
	}
	return Signal{}, fp, distinct
}

// scoreUARotation fires when one client IP has sent requests under N+
// distinct User-Agent strings inside the tracker's window.
func (s *Scorer) scoreUARotation(state *ClientState) Signal {
	if s.ipRep == nil || !s.ipRep.UARotation.Enabled {
		return Signal{}
	}
	threshold := s.ipRep.UARotation.DistinctUAsForFire
	if threshold < 2 {
		return Signal{}
	}
	state.mu.Lock()
	distinct := len(state.UniqueUAs)
	state.mu.Unlock()
	if distinct < threshold {
		return Signal{}
	}
	return Signal{
		Name:   "ua_rotation",
		Points: s.ipRep.UARotation.Points,
		Reason: fmt.Sprintf("client sent %d distinct User-Agents inside the window — UA pool rotation", distinct),
	}
}
