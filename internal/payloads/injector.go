package payloads

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"

	"github.com/C0oki3s/veilgate/internal/tarpit"
)

// Injector implements tarpit.PayloadInjector.
// It picks N payloads per request and splices them into the body in
// appropriate places for the response's content type.
type Injector struct {
	lib         *Library
	perResponse int
	diversify   bool // alternate categories so repeated scans see variety
}

func NewInjector(lib *Library, perResponse int, diversify bool) *Injector {
	if lib == nil {
		lib = NewLibrary()
	}
	if perResponse <= 0 {
		perResponse = 3
	}
	return &Injector{lib: lib, perResponse: perResponse, diversify: diversify}
}

// Inject implements tarpit.PayloadInjector.
func (i *Injector) Inject(contentType, body string, ctx tarpit.InjectionContext) string {
	// Vary salt per-visit so the same client gets rotating payloads.
	salt := ctx.ClientID + ":" + ctx.Path
	if i.diversify {
		// Bucket visits so payloads rotate every few requests instead of every one.
		bucket := ctx.Visits / 3
		salt = salt + ":" + itoa(bucket)
	}
	seed := seedFromSalt(salt)

	picked := i.lib.Pick(salt, i.perResponse*2) // overpick, then filter by style
	if len(picked) == 0 {
		return body
	}

	switch {
	case strings.Contains(contentType, "html"):
		return injectHTML(body, picked, i.perResponse, seed)
	case strings.Contains(contentType, "json"):
		return injectJSON(body, picked, i.perResponse, seed)
	case strings.Contains(contentType, "javascript"):
		return injectJS(body, picked, i.perResponse, seed)
	case strings.Contains(contentType, "text/plain"):
		return injectPlain(body, picked, i.perResponse, seed)
	default:
		return body
	}
}

// injectHTML splices comment-style and hidden-div payloads into HTML.
func injectHTML(body string, candidates []Payload, n int, seed int64) string {
	var chosen []Payload
	for _, p := range candidates {
		if p.Style == "html_comment" || p.Style == "html_hidden" || p.Style == "log_noise" {
			chosen = append(chosen, p)
			if len(chosen) >= n {
				break
			}
		}
	}
	if len(chosen) == 0 {
		return body
	}

	// Inject near the top of <body> or after <html> if no body tag.
	var top, bottom strings.Builder
	for idx, p := range chosen {
		rendered := p.Render(seed + int64(idx))
		if idx%2 == 0 {
			top.WriteString(rendered)
			top.WriteString("\n")
		} else {
			bottom.WriteString(rendered)
			bottom.WriteString("\n")
		}
	}

	// Try to place after <body ...> tag; else prepend.
	if idx := strings.Index(strings.ToLower(body), "<body"); idx >= 0 {
		end := strings.Index(body[idx:], ">")
		if end >= 0 {
			insertAt := idx + end + 1
			body = body[:insertAt] + "\n" + top.String() + body[insertAt:]
		}
	} else {
		body = top.String() + body
	}

	// Append the "bottom" payloads before </body> or at the end.
	if idx := strings.LastIndex(strings.ToLower(body), "</body>"); idx >= 0 {
		body = body[:idx] + bottom.String() + body[idx:]
	} else {
		body = body + "\n" + bottom.String()
	}

	return body
}

// injectJSON adds payload fields to the top-level JSON object. Assumes the body
// ends with a closing `}`. If it doesn't parse as object, leaves it alone.
func injectJSON(body string, candidates []Payload, n int, seed int64) string {
	body = strings.TrimSpace(body)
	if len(body) == 0 || body[len(body)-1] != '}' {
		return body
	}

	var chosen []Payload
	for _, p := range candidates {
		if p.Style == "json_field" {
			chosen = append(chosen, p)
			if len(chosen) >= n {
				break
			}
		}
	}
	if len(chosen) == 0 {
		return body
	}

	var inject strings.Builder
	for idx, p := range chosen {
		inject.WriteString(p.Render(seed + int64(idx)))
	}
	return body[:len(body)-1] + inject.String() + "}"
}

// injectJS splices canary and rabbit-hole payloads into a JavaScript body.
// js_comment payloads are wrapped in /* ... */; js_string_literal payloads
// are embedded inside an IIFE comment block that appears to be dead config.
// Both are placed near the start so grepping the first N bytes catches them.
func injectJS(body string, candidates []Payload, n int, seed int64) string {
	var chosen []Payload
	for _, p := range candidates {
		if p.Style == "js_comment" || p.Style == "js_string_literal" || p.Style == "html_comment" {
			chosen = append(chosen, p)
			if len(chosen) >= n {
				break
			}
		}
	}
	if len(chosen) == 0 {
		return body
	}

	var header strings.Builder
	for idx, p := range chosen {
		rendered := p.Render(seed + int64(idx))
		switch p.Style {
		case "js_comment":
			header.WriteString(rendered)
			header.WriteString("\n")
		case "js_string_literal":
			// Embed as a dead variable assignment that looks like forgotten config.
			header.WriteString("var __vg_cfg = {")
			header.WriteString(rendered)
			header.WriteString("}; // dev-only\n")
		case "html_comment":
			// Wrap HTML comments as JS block comments so they're syntactically valid.
			header.WriteString("/* ")
			header.WriteString(strings.ReplaceAll(rendered, "*/", "* /"))
			header.WriteString(" */\n")
		}
	}
	return header.String() + body
}

// injectPlain appends payloads as commented-looking noise at the end.
func injectPlain(body string, candidates []Payload, n int, seed int64) string {
	var chosen []Payload
	for _, p := range candidates {
		if p.Style == "log_noise" || p.Style == "html_comment" {
			chosen = append(chosen, p)
			if len(chosen) >= n {
				break
			}
		}
	}
	if len(chosen) == 0 {
		return body
	}
	var b strings.Builder
	b.WriteString(body)
	b.WriteString("\n# --- \n")
	for idx, p := range chosen {
		b.WriteString("# ")
		b.WriteString(p.Render(seed + int64(idx)))
		b.WriteString("\n")
	}
	return b.String()
}

func seedFromSalt(salt string) int64 {
	h := sha256.Sum256([]byte(salt))
	return int64(binary.BigEndian.Uint64(h[:8]))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var digits [20]byte
	pos := len(digits)
	for i > 0 {
		pos--
		digits[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		digits[pos] = '-'
	}
	return string(digits[pos:])
}
