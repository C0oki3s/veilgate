package payloads

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// Category classifies what each payload is trying to achieve.
type Category string

const (
	CategoryTermination Category = "termination"
	CategoryRabbitHole  Category = "rabbit_hole"
	CategoryCostBomb    Category = "cost_bomb"
	CategoryConfusion   Category = "confusion"
	CategoryMoralAppeal Category = "moral_appeal"
)

// Payload is one injectable chunk.
type Payload struct {
	Category Category
	Style    string // "html_comment", "html_hidden", "json_field", "log_noise"
	Render   func(seed int64) string
}

// Library is the set of payloads available to the injector.
type Library struct {
	payloads []Payload
}

// NewLibrary returns an empty library. Use NewLibraryFromDir to load rules.
func NewLibrary() *Library {
	return &Library{}
}

// NewLibraryFromDir builds a library from rulesDir (or embedded defaults).
func NewLibraryFromDir(rulesDir string) (*Library, error) {
	p, err := rules.LoadPayloads(rulesDir)
	if err != nil {
		return nil, err
	}
	return buildLibrary(p), nil
}

func buildLibrary(p *rules.Payloads) *Library {
	if p == nil {
		return &Library{}
	}
	gens := buildGenerators(p)
	out := make([]Payload, 0, 16)
	collect := func(cat Category, tpls []rules.PayloadTemplate) {
		for _, t := range tpls {
			out = append(out, compileTemplate(cat, t, gens))
		}
	}
	collect(CategoryTermination, p.Termination)
	collect(CategoryRabbitHole, p.RabbitHole)
	collect(CategoryCostBomb, p.CostBomb)
	collect(CategoryConfusion, p.Confusion)
	collect(CategoryMoralAppeal, p.MoralAppeal)
	return &Library{payloads: out}
}

// Pick returns n payloads chosen pseudo-randomly based on the salt.
// Using a deterministic seed means the same attacker sees coherent payloads
// across requests rather than noticing sudden shifts in tone.
func (l *Library) Pick(salt string, n int) []Payload {
	h := sha256.Sum256([]byte(salt))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	r := rand.New(rand.NewSource(seed))
	perm := r.Perm(len(l.payloads))
	if n > len(perm) {
		n = len(perm)
	}
	out := make([]Payload, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, l.payloads[perm[i]])
	}
	return out
}

// compileTemplate turns a YAML template into a Payload with a Render closure.
// Supports placeholder substitution and generator-ref for programmatic payloads.
func compileTemplate(cat Category, t rules.PayloadTemplate, gens map[string]func(int64) string) Payload {
	if gen := gens[t.Generator]; gen != nil {
		return Payload{Category: cat, Style: t.Style, Render: gen}
	}
	text := strings.TrimRight(t.Text, "\n")
	return Payload{
		Category: cat,
		Style:    t.Style,
		Render: func(seed int64) string {
			return renderPlaceholders(text, seed)
		},
	}
}

// renderPlaceholders supports:
//   {seed}         -> int64 seed
//   {seed_mod:N}   -> seed % N, zero-padded to width of N
//   {ticket_id}    -> 1000 + seed%9000 (rabbit-hole SEC tickets)
func renderPlaceholders(text string, seed int64) string {
	if !strings.Contains(text, "{") {
		return text
	}
	out := text
	out = strings.ReplaceAll(out, "{seed}", strconv.FormatInt(seed, 10))
	out = strings.ReplaceAll(out, "{ticket_id}", strconv.FormatInt(1000+seed%9000, 10))
	// {seed_mod:N} — find all occurrences
	for {
		start := strings.Index(out, "{seed_mod:")
		if start < 0 {
			break
		}
		end := strings.Index(out[start:], "}")
		if end < 0 {
			break
		}
		expr := out[start+len("{seed_mod:") : start+end]
		n, err := strconv.ParseInt(expr, 10, 64)
		if err != nil || n == 0 {
			out = out[:start] + out[start+end+1:]
			continue
		}
		v := seed % n
		if v < 0 {
			v = -v
		}
		width := len(strconv.FormatInt(n-1, 10))
		rep := fmt.Sprintf("%0*d", width, v)
		out = out[:start] + rep + out[start+end+1:]
	}
	return out
}

// buildGenerators returns the map of programmatic renderers keyed by the
// `generator:` field in payloads.yaml. Each renderer closes over config
// loaded from YAML so the Go side contains only the rand-loop mechanics.
func buildGenerators(p *rules.Payloads) map[string]func(int64) string {
	return map[string]func(int64) string{
		"log_burst": newLogBurst(p.Generators.LogBurst),
	}
}

func newLogBurst(cfg rules.LogBurstConfig) func(int64) string {
	// Defensive defaults so a partially-populated YAML doesn't panic.
	if cfg.Count <= 0 {
		cfg.Count = 120
	}
	if cfg.LineFormat == "" {
		cfg.LineFormat = "[2026-01-%02d %02d:%02d:%02d] INFO req=%x path=/api/v%d/resource/%d status=%d dur=%dms\n"
	}
	if len(cfg.StatusCodes) == 0 {
		cfg.StatusCodes = []int{200, 200, 200, 201, 304, 404, 500}
	}
	if cfg.APIVersions <= 0 {
		cfg.APIVersions = 3
	}
	if cfg.MaxResource <= 0 {
		cfg.MaxResource = 100000
	}
	if cfg.MaxDurMs <= 0 {
		cfg.MaxDurMs = 500
	}
	if cfg.DayOfMonth <= 0 {
		cfg.DayOfMonth = 30
	}
	return func(seed int64) string {
		var b strings.Builder
		b.WriteString(cfg.WrapperOpen)
		r := rand.New(rand.NewSource(seed))
		for i := 0; i < cfg.Count; i++ {
			b.WriteString(fmt.Sprintf(cfg.LineFormat,
				1+r.Intn(cfg.DayOfMonth),
				r.Intn(24), r.Intn(60), r.Intn(60),
				r.Uint64(),
				1+r.Intn(cfg.APIVersions),
				r.Intn(cfg.MaxResource),
				cfg.StatusCodes[r.Intn(len(cfg.StatusCodes))],
				r.Intn(cfg.MaxDurMs),
			))
		}
		b.WriteString(cfg.WrapperClose)
		return b.String()
	}
}
