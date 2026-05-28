package detector

import "math"

// scoreTiming detects suspiciously regular inter-request intervals.
// LLM agents tend to produce 2-8 second gaps with low variance.
func (s *Scorer) scoreTiming(events []ClientEvent) Signal {
	t := s.rules.Timing
	if len(events) < t.MinEvents {
		return Signal{}
	}
	gaps := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		d := events[i].Timestamp.Sub(events[i-1].Timestamp).Seconds()
		if d > 0 && d < 60 {
			gaps = append(gaps, d)
		}
	}
	if len(gaps) < t.MinEvents-1 {
		return Signal{}
	}

	mean := 0.0
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))

	variance := 0.0
	for _, g := range gaps {
		variance += (g - mean) * (g - mean)
	}
	variance /= float64(len(gaps))
	cv := math.Sqrt(variance) / mean

	if mean >= t.MinMeanSeconds && mean <= t.MaxMeanSeconds && cv < t.StrictCVMax {
		return Signal{Name: "regular_timing", Points: t.StrictPoints,
			Reason: "request gaps are suspiciously regular (LLM-paced)"}
	}
	if mean >= t.MinMeanSeconds && mean <= t.MaxMeanSeconds && cv < t.LooseCVMax {
		return Signal{Name: "regular_timing", Points: t.LoosePoints,
			Reason: "request gaps show moderate regularity"}
	}
	return Signal{}
}
