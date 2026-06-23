package admin

// Server-side SVG chart rendering for the dashboard analytics.
//
// Everything here emits plain inline <svg> as a template.HTML string. There is
// no client-side charting library and no JavaScript: this keeps us fully inside
// the admin's strict Content-Security-Policy (no 'unsafe-eval', no external
// origins) and works with JS disabled. Hover tooltips come for free from native
// <title> elements. Colours reference the CSS design tokens via fill="var(--…)"
// so charts track the light/dark theme automatically.

import (
	"fmt"
	"html"
	"html/template"
	"math"
	"strings"

	"github.com/C0oki3s/veilgate/internal/persist"
)

// Decision colour tokens, shared across every chart so a class always reads the
// same colour (tarpit=red, challenge=amber, observe=accent, clean=green).
const (
	colObserve   = "var(--accent-base)"
	colChallenge = "var(--color-warn)"
	colTarpit    = "var(--color-danger)"
	colClean     = "var(--color-success)"
	colOther     = "var(--color-neutral)"
	colGrid      = "var(--surface-3)"
	colAxis      = "var(--text-tertiary)"
)

// f trims a float to a compact SVG coordinate.
func f(v float64) string { return strings.TrimSuffix(fmt.Sprintf("%.2f", v), ".00") }

// ── Requests-over-time: stacked bars ────────────────────────────────────────

// timelineSVG renders the requests-over-time chart as stacked vertical bars,
// one bar per time bucket, segmented by decision class. Each segment carries a
// native <title> tooltip. Returns "" when there is nothing to draw.
func timelineSVG(buckets []persist.TimeBucket) template.HTML {
	if len(buckets) == 0 {
		return ""
	}
	const (
		w        = 720.0
		h        = 220.0
		padL     = 34.0
		padR     = 8.0
		padT     = 12.0
		padB     = 26.0
	)
	plotW := w - padL - padR
	plotH := h - padT - padB

	maxTotal := 1
	for _, b := range buckets {
		if b.Total > maxTotal {
			maxTotal = b.Total
		}
	}
	// "Nice" y-axis ceiling so gridlines land on round numbers.
	ceil := niceCeil(maxTotal)

	n := len(buckets)
	slot := plotW / float64(n)
	barW := slot * 0.62
	if barW > 26 {
		barW = 26
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %s %s" class="chart-svg" role="img" preserveAspectRatio="none">`, f(w), f(h))

	// Horizontal gridlines + y labels (0, ¼, ½, ¾, max).
	for i := 0; i <= 4; i++ {
		val := ceil * i / 4
		y := padT + plotH*(1-float64(i)/4)
		fmt.Fprintf(&b, `<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1"/>`,
			f(padL), f(y), f(w-padR), f(y), colGrid)
		fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-axis" text-anchor="end" dominant-baseline="middle">%d</text>`,
			f(padL-5), f(y), val)
	}

	yFor := func(cum int) float64 { return padT + plotH*(1-float64(cum)/float64(ceil)) }

	// Stack order from the bottom up.
	type seg struct {
		val   int
		color string
		label string
	}
	for i, bk := range buckets {
		cx := padL + slot*float64(i) + slot/2
		x := cx - barW/2
		segs := []seg{
			{bk.Clean, colClean, "clean"},
			{bk.Observe, colObserve, "observe"},
			{bk.Challenge, colChallenge, "challenge"},
			{bk.Tarpit, colTarpit, "tarpit"},
			{bk.Other, colOther, "other"},
		}
		cum := 0
		tip := fmt.Sprintf("%s — %d req (obs %d, chal %d, tar %d, clean %d)",
			bk.Start.Local().Format("Jan 2 15:04"), bk.Total,
			bk.Observe, bk.Challenge, bk.Tarpit, bk.Clean)
		for _, sg := range segs {
			if sg.val == 0 {
				continue
			}
			y0 := yFor(cum)
			y1 := yFor(cum + sg.val)
			fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s"><title>%s</title></rect>`,
				f(x), f(y1), f(barW), f(y0-y1), sg.color, html.EscapeString(tip))
			cum += sg.val
		}
		// Sparse x labels: first, last, and a couple in between.
		if n <= 12 || i == 0 || i == n-1 || i%(n/6+1) == 0 {
			fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-axis" text-anchor="middle">%s</text>`,
				f(cx), f(h-8), bk.Start.Local().Format("15:04"))
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec // all dynamic values escaped or numeric
}

// ── Decision mix: donut ──────────────────────────────────────────────────────

type donutSeg struct {
	Value int
	Color string
	Label string
}

// donutSVG renders a decision-mix donut. Each arc has a <title> tooltip and the
// total sits in the centre. Returns "" when there are no events.
func donutSVG(segs []donutSeg, total int) template.HTML {
	if total <= 0 {
		return ""
	}
	const (
		size = 180.0
		cx   = size / 2
		cy   = size / 2
		rOut = 78.0
		rIn  = 50.0
	)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %s %s" class="chart-donut" role="img">`, f(size), f(size))

	angle := -math.Pi / 2 // start at 12 o'clock
	for _, sg := range segs {
		if sg.Value <= 0 {
			continue
		}
		frac := float64(sg.Value) / float64(total)
		sweep := frac * 2 * math.Pi
		end := angle + sweep
		large := 0
		if sweep > math.Pi {
			large = 1
		}
		x0o, y0o := cx+rOut*math.Cos(angle), cy+rOut*math.Sin(angle)
		x1o, y1o := cx+rOut*math.Cos(end), cy+rOut*math.Sin(end)
		x0i, y0i := cx+rIn*math.Cos(end), cy+rIn*math.Sin(end)
		x1i, y1i := cx+rIn*math.Cos(angle), cy+rIn*math.Sin(angle)
		d := fmt.Sprintf("M%s,%s A%s,%s 0 %d,1 %s,%s L%s,%s A%s,%s 0 %d,0 %s,%s Z",
			f(x0o), f(y0o), f(rOut), f(rOut), large, f(x1o), f(y1o),
			f(x0i), f(y0i), f(rIn), f(rIn), large, f(x1i), f(y1i))
		tip := fmt.Sprintf("%s: %d (%.0f%%)", sg.Label, sg.Value, frac*100)
		fmt.Fprintf(&b, `<path d="%s" fill="%s"><title>%s</title></path>`, d, sg.Color, html.EscapeString(tip))
		angle = end
	}
	// Centre total.
	fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-donut-num" text-anchor="middle">%d</text>`,
		f(cx), f(cy-2), total)
	fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-donut-cap" text-anchor="middle">requests</text>`,
		f(cx), f(cy+16))
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec
}

// ── Score distribution: histogram ────────────────────────────────────────────

// histogramSVG renders the score distribution. Bars are coloured by the zone
// each bin falls into relative to the challenge/tarpit thresholds.
func histogramSVG(bins []persist.HistBin, challenge, tarpit int) template.HTML {
	if len(bins) == 0 {
		return ""
	}
	const (
		w    = 720.0
		h    = 180.0
		padL = 34.0
		padR = 8.0
		padT = 10.0
		padB = 26.0
	)
	plotW := w - padL - padR
	plotH := h - padT - padB

	maxCount := 1
	for _, bn := range bins {
		if bn.Count > maxCount {
			maxCount = bn.Count
		}
	}
	ceil := niceCeil(maxCount)
	slot := plotW / float64(len(bins))
	barW := slot * 0.78

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %s %s" class="chart-svg" role="img" preserveAspectRatio="none">`, f(w), f(h))
	for i := 0; i <= 4; i++ {
		val := ceil * i / 4
		y := padT + plotH*(1-float64(i)/4)
		fmt.Fprintf(&b, `<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="1"/>`,
			f(padL), f(y), f(w-padR), f(y), colGrid)
		fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-axis" text-anchor="end" dominant-baseline="middle">%d</text>`,
			f(padL-5), f(y), val)
	}
	for i, bn := range bins {
		color := colClean
		switch {
		case bn.Lo >= tarpit:
			color = colTarpit
		case bn.Lo >= challenge:
			color = colChallenge
		case bn.Lo > 0:
			color = colObserve
		}
		bh := plotH * float64(bn.Count) / float64(ceil)
		x := padL + slot*float64(i) + (slot-barW)/2
		y := padT + plotH - bh
		tip := fmt.Sprintf("score %d–%d: %d req", bn.Lo, bn.Hi, bn.Count)
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s" rx="2"><title>%s</title></rect>`,
			f(x), f(y), f(barW), f(bh), color, html.EscapeString(tip))
		fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-axis" text-anchor="middle">%d</text>`,
			f(padL+slot*float64(i)+slot/2), f(h-8), bn.Lo)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec
}

// ── Horizontal-bar breakdowns (paths, clients, user-agents, signals) ─────────

// hbarRow is one row of a horizontal-bar chart. Tarpit (when > 0) is drawn as a
// danger-red overlay covering its share of the total bar. Color overrides the
// default accent fill of the base bar.
type hbarRow struct {
	Label  string // display label (long values are truncated for the axis)
	Full   string // untruncated text for the hover tooltip
	Count  int
	Tarpit int    // 0 = no overlay
	Color  string // "" = accent
}

// hbarSVG renders a labelled horizontal-bar chart. Shared by every "top N"
// breakdown so a bar always reads the same across charts.
func hbarSVG(rows []hbarRow, labelW float64) template.HTML {
	if len(rows) == 0 {
		return ""
	}
	const (
		w    = 720.0
		rowH = 30.0
		padT = 6.0
		barH = 16.0
		numW = 46.0
	)
	h := padT*2 + rowH*float64(len(rows))
	barMaxW := w - labelW - numW - 12

	maxCount := 1
	for _, r := range rows {
		if r.Count > maxCount {
			maxCount = r.Count
		}
	}
	// One label char is ~6.2px at the axis font size; cap so text never spills
	// into the bar track.
	maxChars := int((labelW - 6) / 6.2)

	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %s %s" class="chart-hbar" role="img">`, f(w), f(h))
	for i, r := range rows {
		y := padT + rowH*float64(i)
		cy := y + rowH/2
		label := r.Label
		if maxChars > 1 && len(label) > maxChars {
			label = label[:maxChars-1] + "…"
		}
		full := r.Full
		if full == "" {
			full = r.Label
		}
		fmt.Fprintf(&b, `<text x="0" y="%s" class="chart-hbar-label" dominant-baseline="middle">%s<title>%s</title></text>`,
			f(cy), html.EscapeString(label), html.EscapeString(full))
		barLen := barMaxW * float64(r.Count) / float64(maxCount)
		by := cy - barH/2
		base := r.Color
		if base == "" {
			base = colObserve
		}
		fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s" rx="3"/>`,
			f(labelW), f(by), f(barLen), f(barH), base)
		if r.Tarpit > 0 {
			tw := barLen * float64(r.Tarpit) / float64(r.Count)
			fmt.Fprintf(&b, `<rect x="%s" y="%s" width="%s" height="%s" fill="%s" rx="3"><title>%d tarpitted</title></rect>`,
				f(labelW), f(by), f(tw), f(barH), colTarpit, r.Tarpit)
		}
		fmt.Fprintf(&b, `<text x="%s" y="%s" class="chart-hbar-num" text-anchor="end" dominant-baseline="middle">%d</text>`,
			f(w), f(cy), r.Count)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String()) //nolint:gosec
}

// topPathsSVG renders the most-requested paths as horizontal bars, with the
// tarpitted share drawn in danger-red on top of the total.
func topPathsSVG(rows []persist.PathCount) template.HTML {
	out := make([]hbarRow, len(rows))
	for i, r := range rows {
		out[i] = hbarRow{Label: r.Path, Full: r.Path, Count: r.Count, Tarpit: r.Tarpit}
	}
	return hbarSVG(out, 300)
}

// topClientsSVG renders the busiest clients, tarpit share overlaid. The tooltip
// surfaces the client's peak score.
func topClientsSVG(rows []persist.ClientStat) template.HTML {
	out := make([]hbarRow, len(rows))
	for i, r := range rows {
		out[i] = hbarRow{
			Label:  r.ClientID,
			Full:   fmt.Sprintf("%s — %d req, peak score %d, %d tarpitted", r.ClientID, r.Count, r.MaxScore, r.Tarpit),
			Count:  r.Count,
			Tarpit: r.Tarpit,
		}
	}
	return hbarSVG(out, 280)
}

// topUserAgentsSVG renders the most common user-agents, tarpit share overlaid.
func topUserAgentsSVG(rows []persist.LabelCount) template.HTML {
	out := make([]hbarRow, len(rows))
	for i, r := range rows {
		out[i] = hbarRow{Label: r.Label, Full: r.Label, Count: r.Count, Tarpit: r.Tarpit}
	}
	return hbarSVG(out, 360)
}

// topSignalsSVG renders the most frequently fired detection signals. No tarpit
// overlay — a fired signal is a detector hit, not a decision — so bars use the
// challenge/amber colour to read as "detection activity".
func topSignalsSVG(rows []persist.LabelCount) template.HTML {
	out := make([]hbarRow, len(rows))
	for i, r := range rows {
		out[i] = hbarRow{Label: r.Label, Full: r.Label, Count: r.Count, Color: colChallenge}
	}
	return hbarSVG(out, 300)
}

// niceCeil rounds n up to a friendly axis maximum (1, 2, 5 × 10ⁿ).
func niceCeil(n int) int {
	if n <= 5 {
		return 5
	}
	mag := math.Pow(10, math.Floor(math.Log10(float64(n))))
	norm := float64(n) / mag
	switch {
	case norm <= 1:
		return int(1 * mag)
	case norm <= 2:
		return int(2 * mag)
	case norm <= 5:
		return int(5 * mag)
	default:
		return int(10 * mag)
	}
}
