package telemetry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// Dashboard serves a rich HTML live view of what VeilGate is doing,
// with Prometheus-backed graphs, PromQL search, and IP rotation panels.
// All layout, colours, metric names, graph definitions, and search tags
// are driven by rules/dashboard.yaml -- no hardcoded content.
type Dashboard struct {
	mu           sync.Mutex
	recentEvents []Event
	cfgHolder    *rules.Holder[rules.Dashboard]
}

type Event struct {
	Time     time.Time
	Client   string
	Path     string
	Score    int
	Decision string
}

func NewDashboard(holder *rules.Holder[rules.Dashboard]) *Dashboard {
	return &Dashboard{cfgHolder: holder}
}

func (d *Dashboard) cfg() *rules.Dashboard {
	if d.cfgHolder != nil {
		if c := d.cfgHolder.Load(); c != nil {
			return c
		}
	}
	// No rules holder set; return a zero-value config.
	return new(rules.Dashboard)
}

func (d *Dashboard) Record(e Event) {
	c := d.cfg()
	max := c.MaxEvents
	d.mu.Lock()
	defer d.mu.Unlock()
	d.recentEvents = append(d.recentEvents, e)
	if len(d.recentEvents) > max {
		d.recentEvents = d.recentEvents[len(d.recentEvents)-max:]
	}
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := d.cfg()

	d.mu.Lock()
	events := append([]Event(nil), d.recentEvents...)
	d.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Serialize YAML-driven config to JSON for the JS runtime.
	cfgJSON, _ := json.Marshal(c)

	fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><title>VeilGate -- Prometheus Console</title>
<meta charset="utf-8">
<style>
:root {
  --bg: %s; --bg2: %s; --bg3: %s;
  --fg: %s; --muted: %s; --accent: %s;
  --red: %s; --yellow: %s; --green: %s;
  --border: %s;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--fg); padding: 20px; }
h1 { font-weight: 500; letter-spacing: -0.01em; margin-bottom: 4px; }
.subtitle { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
.subtitle a { color: var(--accent); text-decoration: none; }
.grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px; }
.grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 20px; }
.full { grid-column: 1 / -1; }
.card { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
.card h2 { font-size: 14px; font-weight: 500; color: var(--muted); margin-bottom: 12px; text-transform: uppercase; letter-spacing: 0.05em; }
.stat { font-size: 32px; font-weight: 600; }
.stat-label { font-size: 12px; color: var(--muted); margin-top: 2px; }
.stat-row { display: flex; gap: 24px; }
.stat-item { flex: 1; }
canvas { width: 100%%%% !important; height: 200px !important; }
.search-box { background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 20px; }
.search-box h2 { font-size: 14px; font-weight: 500; color: var(--muted); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.05em; }
.search-row { display: flex; gap: 8px; }
.search-row input { flex: 1; background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; color: var(--fg); font-family: 'Consolas','Monaco',monospace; font-size: 14px; }
.search-row input:focus { outline: none; border-color: var(--accent); }
.search-row button { background: var(--accent); color: #000; border: none; border-radius: 4px; padding: 8px 16px; cursor: pointer; font-weight: 600; font-size: 13px; }
.search-row button:hover { opacity: 0.9; }
.search-results { margin-top: 12px; font-family: monospace; font-size: 13px; max-height: 300px; overflow-y: auto; background: var(--bg); border-radius: 4px; padding: 12px; display: none; }
.search-results pre { white-space: pre-wrap; word-break: break-all; }
.search-hint { color: var(--muted); font-size: 12px; margin-top: 6px; }
.metric-tag { display: inline-block; background: var(--bg3); border: 1px solid var(--border); border-radius: 3px; padding: 2px 6px; font-size: 11px; font-family: monospace; margin: 2px; cursor: pointer; color: var(--accent); }
.metric-tag:hover { background: var(--border); }
table { border-collapse: collapse; width: 100%%%%; font-size: 13px; }
th, td { text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }
th { color: var(--muted); font-weight: 500; position: sticky; top: 0; background: var(--bg2); }
.d-real { color: var(--muted); }
.d-observe { color: var(--accent); }
.d-challenge { color: var(--yellow); }
.d-tarpit { color: var(--red); font-weight: 600; }
.score-high { color: var(--red); }
.score-med { color: var(--yellow); }
.score-low { color: var(--muted); }
.table-wrap { max-height: 400px; overflow-y: auto; }
.filter-row { display: flex; gap: 8px; margin-bottom: 12px; }
.filter-row input { flex: 1; background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 6px 10px; color: var(--fg); font-size: 13px; }
.filter-row input:focus { outline: none; border-color: var(--accent); }
</style>
</head>
<body>
<h1>VeilGate</h1>
<p class="subtitle">Live Prometheus Console -- auto-refresh every %ds -- <a href="/metrics">Raw /metrics</a></p>
`,
		c.Colours.BG, c.Colours.BG2, c.Colours.BG3,
		c.Colours.FG, c.Colours.Muted, c.Colours.Accent,
		c.Colours.Red, c.Colours.Yellow, c.Colours.Green,
		c.Colours.Border,
		c.RefreshSeconds)

	// ---- PromQL search bar (tags from YAML) ----
	fmt.Fprint(w, `<div class="search-box">
<h2>Prometheus Metric Search</h2>
<div class="search-row">
<input type="text" id="promql-input" placeholder="Search metric name or paste PromQL...">
<button onclick="searchMetrics()">Search</button>
</div>
<div class="search-hint">Quick: `)
	for _, tag := range c.SearchTags {
		fmt.Fprintf(w, `<span class="metric-tag" onclick="fillSearch('%s')">%s</span> `,
			htmlEscape(tag.Query), htmlEscape(tag.Label))
	}
	fmt.Fprint(w, `</div>
<div class="search-results" id="search-results"><pre id="search-output"></pre></div>
</div>`)

	// ---- Summary stat cards (from YAML) ----
	fmt.Fprint(w, `<div class="grid-3">`)
	for _, sc := range c.StatCards {
		colStyle := ""
		if sc.Colour != "" {
			colStyle = fmt.Sprintf(` style="color:var(--%s)"`, htmlEscape(sc.Colour))
		}
		fmt.Fprintf(w, `<div class="card"><h2>%s</h2><div class="stat"%s id="%s">--</div><div class="stat-label">%s</div></div>`,
			htmlEscape(sc.Title), colStyle, htmlEscape(sc.ID), htmlEscape(sc.Label))
	}
	fmt.Fprint(w, `</div>`)

	// ---- IP Rotation + Public IP panels ----
	fmt.Fprint(w, `<div class="grid">`)
	// IP rotation
	fmt.Fprintf(w, `<div class="card"><h2>%s</h2><div class="stat-row">`, htmlEscape(c.IPRotation.Title))
	for _, t := range c.IPRotation.Tiers {
		colStyle := ""
		if t.Colour != "" {
			colStyle = fmt.Sprintf(` style="color:var(--%s)"`, htmlEscape(t.Colour))
		}
		fmt.Fprintf(w, `<div class="stat-item"><div class="stat"%s id="%s">--</div><div class="stat-label">%s</div></div>`,
			colStyle, htmlEscape(t.ID), htmlEscape(t.Display))
	}
	fmt.Fprint(w, `</div><canvas id="chart-fleet" style="margin-top:12px"></canvas></div>`)

	// Public IP
	fmt.Fprintf(w, `<div class="card"><h2>%s</h2><div class="stat-row">`, htmlEscape(c.PublicIPRotation.Title))
	for _, item := range c.PublicIPRotation.Items {
		colStyle := ""
		if item.Colour != "" {
			colStyle = fmt.Sprintf(` style="color:var(--%s)"`, htmlEscape(item.Colour))
		}
		fmt.Fprintf(w, `<div class="stat-item"><div class="stat"%s id="%s">--</div><div class="stat-label">%s</div></div>`,
			colStyle, htmlEscape(item.ID), htmlEscape(item.Display))
	}
	fmt.Fprint(w, `</div><canvas id="chart-public-ip" style="margin-top:12px"></canvas></div>`)
	fmt.Fprint(w, `</div>`)

	// ---- Graph panels (from YAML, rendered as canvas placeholders) ----
	graphs := c.Graphs
	for i := 0; i < len(graphs); i += 2 {
		fmt.Fprint(w, `<div class="grid">`)
		for j := i; j < i+2 && j < len(graphs); j++ {
			g := graphs[j]
			fmt.Fprintf(w, `<div class="card"><h2>%s</h2>`, htmlEscape(g.Title))
			if g.ID == "chart-cardinality" {
				fmt.Fprint(w, `<div class="stat-row" style="margin-bottom:12px"><div class="stat-item"><div class="stat" id="stat-clients">--</div><div class="stat-label">tracked clients</div></div><div class="stat-item"><div class="stat" id="stat-fingerprints">--</div><div class="stat-label">fleet fingerprints</div></div></div>`)
			}
			fmt.Fprintf(w, `<canvas id="%s"></canvas></div>`, htmlEscape(g.ID))
		}
		fmt.Fprint(w, `</div>`)
	}

	// ---- Events table ----
	fmt.Fprint(w, `<div class="card full" style="margin-top:16px">
<h2>Recent Events</h2>
<div class="filter-row">
<input type="text" id="event-filter" placeholder="Filter by IP, path, or decision..." oninput="filterEvents()">
</div>
<div class="table-wrap"><table>
<thead><tr><th>Time</th><th>Client</th><th>Path</th><th>Score</th><th>Decision</th></tr></thead>
<tbody id="events-body">`)

	scoreHigh := c.ScoreThresholds.High
	scoreMed := c.ScoreThresholds.Medium

	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		scoreClass := "score-low"
		switch {
		case e.Score >= scoreHigh:
			scoreClass = "score-high"
		case e.Score >= scoreMed:
			scoreClass = "score-med"
		}
		fmt.Fprintf(w, `<tr class="event-row" data-client="%s" data-path="%s" data-decision="%s">
<td class="muted">%s</td><td>%s</td><td>%s</td><td class="%s">%d</td><td class="d-%s">%s</td></tr>`,
			htmlEscape(e.Client), htmlEscape(e.Path), e.Decision,
			e.Time.Format("15:04:05"), htmlEscape(e.Client), htmlEscape(e.Path),
			scoreClass, e.Score, e.Decision, e.Decision)
	}

	fmt.Fprint(w, `</tbody></table></div></div>`)

	// ---- JS: inject YAML config as JSON, build everything from it ----
	fmt.Fprintf(w, `
<script src="%s"></script>
<script>
const CFG = %s;

// ---- Metric parsing & fetching ----
let metricsCache = {};
let historyData = {};
const maxHistory = CFG.max_history_points || 60;

async function fetchMetrics() {
  try {
    const resp = await fetch('/metrics');
    const text = await resp.text();
    metricsCache = parsePrometheus(text);
    updateStats();
    updateCharts();
  } catch(e) { console.error('fetch /metrics:', e); }
}

function parsePrometheus(text) {
  const result = {};
  for (const line of text.split('\n')) {
    if (line.startsWith('#') || line.trim() === '') continue;
    const match = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\{?(.*?)\}?\s+([\d.eE+\-]+|NaN|Inf|\+Inf|-Inf)$/);
    if (match) {
      const name = match[1], labels = match[2], value = parseFloat(match[3]);
      if (!result[name]) result[name] = [];
      const labelMap = {};
      if (labels) { for (const pair of labels.split(',')) { const eq = pair.indexOf('='); if (eq > 0) labelMap[pair.slice(0,eq).trim()] = pair.slice(eq+1).trim().replace(/^"|"$/g, ''); } }
      result[name].push({ labels: labelMap, value });
    } else {
      const simple = line.match(/^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+([\d.eE+\-]+|NaN|Inf|\+Inf|-Inf)$/);
      if (simple) { if (!result[simple[1]]) result[simple[1]] = []; result[simple[1]].push({ labels: {}, value: parseFloat(simple[2]) }); }
    }
  }
  return result;
}

function getMetricValue(name, labelFilter) {
  const entries = metricsCache[name];
  if (!entries) return 0;
  for (const e of entries) {
    if (!labelFilter) return e.value;
    let match = true;
    for (const [k,v] of Object.entries(labelFilter)) { if (e.labels[k] !== v) { match = false; break; } }
    if (match) return e.value;
  }
  return 0;
}

function sumAllLabels(name) {
  const entries = metricsCache[name];
  if (!entries) return 0;
  return entries.reduce((s,e) => s + e.value, 0);
}

function getMetricsByLabel(name, labelKey) {
  const entries = metricsCache[name];
  if (!entries) return {};
  const out = {};
  for (const e of entries) { const key = e.labels[labelKey] || 'unknown'; out[key] = (out[key] || 0) + e.value; }
  return out;
}

function fmtNum(n) { if (n >= 1e6) return (n/1e6).toFixed(1)+'M'; if (n >= 1e3) return (n/1e3).toFixed(1)+'K'; return Math.round(n).toString(); }

// ---- Stats updates (driven by YAML stat_cards) ----
function updateStats() {
  for (const sc of (CFG.stat_cards || [])) {
    const el = document.getElementById(sc.id);
    if (!el) continue;
    let val;
    if (sc.aggregate === 'sum_all_labels') { val = sumAllLabels(sc.metric); }
    else if (sc.filter) { val = getMetricValue(sc.metric, sc.filter); }
    else { val = getMetricValue(sc.metric); }
    el.textContent = sc.format === 'usd' ? ('$' + val.toFixed(4)) : fmtNum(val);
  }
  // IP rotation tiers
  for (const t of (CFG.ip_rotation && CFG.ip_rotation.tiers || [])) {
    const el = document.getElementById(t.id);
    if (el) el.textContent = fmtNum(getMetricValue(CFG.ip_rotation.metric, {[t.label_key]: t.label_value}));
  }
  // Public IP items
  for (const item of (CFG.public_ip_rotation && CFG.public_ip_rotation.items || [])) {
    const el = document.getElementById(item.id);
    if (el) el.textContent = fmtNum(getMetricValue(CFG.public_ip_rotation.metric, {[item.label_key]: item.label_value}));
  }
  // Cardinality
  if (CFG.cardinality) {
    const ce = document.getElementById('stat-clients');
    const fe = document.getElementById('stat-fingerprints');
    if (ce) ce.textContent = fmtNum(getMetricValue(CFG.cardinality.clients_metric));
    if (fe) fe.textContent = fmtNum(getMetricValue(CFG.cardinality.fingerprints_metric));
  }
}

// ---- Charts (driven by YAML graphs) ----
const chartOpts = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { labels: { color: '#888', font: { size: 11 } } } },
  scales: { x: { ticks: { color: '#666', font: { size: 10 } }, grid: { color: '#222' } }, y: { ticks: { color: '#666', font: { size: 10 } }, grid: { color: '#222' }, beginAtZero: true } }
};
let charts = {};

function initCharts() {
  for (const g of (CFG.graphs || [])) {
    const canvas = document.getElementById(g.id);
    if (!canvas) continue;
    switch (g.type) {
      case 'bar':
        charts[g.id] = new Chart(canvas, { type: 'bar', data: { labels: g.bucket_labels || [], datasets: [{ label: 'Requests', data: (g.bucket_labels||[]).map(()=>0), backgroundColor: g.colours || g.colour || '#7db8ff' }] }, options: { ...chartOpts, plugins: { ...chartOpts.plugins, legend: { display: false } } } });
        break;
      case 'doughnut':
        charts[g.id] = new Chart(canvas, { type: 'doughnut', data: { labels: (g.series||[]).map(s=>s.value), datasets: [{ data: (g.series||[]).map(()=>0), backgroundColor: g.colours || (g.series||[]).map(s=>s.colour) }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: '#888' } } } } });
        break;
      case 'horizontal_bar':
        charts[g.id] = new Chart(canvas, { type: 'bar', data: { labels: [], datasets: [{ label: 'Hits', data: [], backgroundColor: g.colour || '#7db8ff' }] }, options: { ...chartOpts, indexAxis: 'y', plugins: { ...chartOpts.plugins, legend: { display: false } } } });
        break;
      case 'line':
        const datasets = (g.series||[]).map(s => ({ label: s.label || s.value, data: [], borderColor: s.colour, backgroundColor: s.fill_colour || 'transparent', fill: !!s.fill_colour, tension: 0.3 }));
        charts[g.id] = new Chart(canvas, { type: 'line', data: { labels: [], datasets }, options: chartOpts });
        historyData[g.id] = { labels: [], series: datasets.map(()=>[]) };
        break;
    }
  }
}

function updateCharts() {
  const now = new Date().toLocaleTimeString();
  for (const g of (CFG.graphs || [])) {
    const chart = charts[g.id];
    if (!chart) continue;
    switch (g.type) {
      case 'bar': {
        const buckets = metricsCache[g.metric+'_bucket'] || metricsCache[g.metric] || [];
        const cumulative = (g.bucket_labels||[]).map(b => { const e = buckets.find(e => e.labels.le === b); return e ? e.value : 0; });
        chart.data.datasets[0].data = cumulative.map((v,i) => i === 0 ? v : v - cumulative[i-1]);
        chart.update('none');
        break;
      }
      case 'doughnut': {
        if (g.series && g.series.length > 0) {
          chart.data.datasets[0].data = g.series.map(s => getMetricValue(g.metric, {[g.label_key]: s.value}));
        } else {
          const d = getMetricsByLabel(g.metric, g.label_key);
          chart.data.labels = Object.keys(d);
          chart.data.datasets[0].data = Object.values(d);
        }
        chart.update('none');
        break;
      }
      case 'horizontal_bar': {
        const d = getMetricsByLabel(g.metric, g.label_key);
        const sorted = Object.entries(d).sort((a,b) => b[1]-a[1]).slice(0, g.max_items || 15);
        chart.data.labels = sorted.map(s=>s[0]);
        chart.data.datasets[0].data = sorted.map(s=>s[1]);
        chart.update('none');
        break;
      }
      case 'line': {
        const hd = historyData[g.id];
        if (!hd) break;
        hd.labels.push(now);
        (g.series||[]).forEach((s,i) => {
          const metric = s.metric || g.metric;
          const filter = s.value ? {[g.label_key]: s.value} : {};
          hd.series[i].push(Object.keys(filter).length ? getMetricValue(metric, filter) : getMetricValue(metric));
        });
        if (hd.labels.length > maxHistory) { hd.labels.shift(); hd.series.forEach(s => s.shift()); }
        chart.data.labels = hd.labels;
        (g.series||[]).forEach((_,i) => { chart.data.datasets[i].data = hd.series[i]; });
        chart.update('none');
        break;
      }
    }
  }
}

// ---- PromQL search ----
function fillSearch(q) { document.getElementById('promql-input').value = q; searchMetrics(); }

function searchMetrics() {
  const query = document.getElementById('promql-input').value.trim().toLowerCase();
  const resultsDiv = document.getElementById('search-results');
  const output = document.getElementById('search-output');
  if (!query) { resultsDiv.style.display = 'none'; return; }
  resultsDiv.style.display = 'block';
  let lines = [];
  // Exact and substring match
  for (const [name, entries] of Object.entries(metricsCache)) {
    if (name.toLowerCase().includes(query) || query.includes(name.toLowerCase())) {
      for (const e of entries) {
        const ls = Object.entries(e.labels).map(([k,v])=>k+'="'+v+'"').join(', ');
        lines.push((ls ? name+'{'+ls+'}' : name) + ' ' + e.value);
      }
    }
  }
  // Fuzzy fallback: split on _ and space, match any word
  if (lines.length === 0) {
    const words = query.split(/[_\s]+/).filter(w => w.length > 2);
    for (const [name, entries] of Object.entries(metricsCache)) {
      if (words.some(w => name.toLowerCase().includes(w))) {
        for (const e of entries) {
          const ls = Object.entries(e.labels).map(([k,v])=>k+'="'+v+'"').join(', ');
          lines.push((ls ? name+'{'+ls+'}' : name) + ' ' + e.value);
        }
      }
    }
  }
  if (lines.length > 0) {
    output.textContent = lines.join('\n');
  } else {
    const available = Object.keys(metricsCache).filter(k => k.startsWith('veilgate_')).sort().join('\n  ');
    output.textContent = 'No metrics matching "' + query + '".\n\nAvailable veilgate_* metrics:\n  ' + (available || '(none yet -- wait for first request)');
  }
}
document.getElementById('promql-input').addEventListener('keydown', function(e) { if (e.key === 'Enter') searchMetrics(); });

// ---- Event filter ----
function filterEvents() {
  const q = document.getElementById('event-filter').value.toLowerCase();
  for (const row of document.querySelectorAll('.event-row')) {
    const match = !q || (row.dataset.client||'').toLowerCase().includes(q) || (row.dataset.path||'').toLowerCase().includes(q) || (row.dataset.decision||'').toLowerCase().includes(q);
    row.style.display = match ? '' : 'none';
  }
}

// ---- Init ----
initCharts();
fetchMetrics();
setInterval(fetchMetrics, (CFG.refresh_seconds||10)*1000);
setInterval(function(){ location.reload(); }, (CFG.page_reload_seconds||60)*1000);
</script>
</body></html>`,
		htmlEscape(c.ChartJSCDN), string(cfgJSON))
}

func htmlEscape(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '<':
			out = append(out, '&', 'l', 't', ';')
		case '>':
			out = append(out, '&', 'g', 't', ';')
		case '&':
			out = append(out, '&', 'a', 'm', 'p', ';')
		case '"':
			out = append(out, '&', 'q', 'u', 'o', 't', ';')
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
