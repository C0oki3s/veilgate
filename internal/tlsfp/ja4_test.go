package tlsfp

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

const testRulesDir = "../../rules"

func mustDatabase(t *testing.T) *Database {
	t.Helper()
	db, err := NewDatabaseFromDir(testRulesDir)
	if err != nil {
		t.Fatalf("NewDatabaseFromDir: %v", err)
	}
	return db
}

func TestJA4BasicShape(t *testing.T) {
	ch := &ClientHello{
		Version:        0x0303,
		SupportedVers:  []uint16{0x0304, 0x0303}, // TLS 1.3, 1.2
		CipherSuites:   []uint16{0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f},
		Extensions:     []uint16{0x0000, 0x0017, 0x000b, 0x000a, 0x0023, 0x0010, 0x0005, 0x0012, 0x002b},
		EllipticCurves: []uint16{0x001d, 0x0017, 0x0018},
		SignatureAlgos: []uint16{0x0403, 0x0804, 0x0401},
		ALPNProtocols:  []string{"h2", "http/1.1"},
		SNI:            "example.com",
	}
	j4 := JA4(ch)
	// Expect shape: t<ver=13><sni=d><cc=05><ec=09><alpn=h2>_<12hex>_<12hex>
	if len(j4) < 20 {
		t.Fatalf("JA4 too short: %q", j4)
	}
	if j4[0] != 't' {
		t.Errorf("JA4 should start with 't' for TCP, got %q", j4[:1])
	}
	if j4[1:3] != "13" {
		t.Errorf("expected version 13 for TLS 1.3, got %q", j4[1:3])
	}
	if j4[3] != 'd' {
		t.Errorf("expected SNI flag 'd', got %q", j4[3:4])
	}
}

func TestJA4NoSNI(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301},
		Extensions:   []uint16{0x0017},
	}
	j4 := JA4(ch)
	if j4[3] != 'i' {
		t.Errorf("no SNI should yield 'i', got %q in %q", j4[3:4], j4)
	}
}

func TestJA4FiltersGREASE(t *testing.T) {
	ch := &ClientHello{
		Version:      0x0303,
		CipherSuites: []uint16{0x0a0a, 0x1301, 0x1302, 0xdada}, // two GREASE
		Extensions:   []uint16{0x4a4a, 0x0017, 0x000b},         // one GREASE
	}
	j4 := JA4(ch)
	// cipher count should be 02, extension count 02
	if j4[4:6] != "02" {
		t.Errorf("cipher count after GREASE filter should be 02, got %q in %q", j4[4:6], j4)
	}
	if j4[6:8] != "02" {
		t.Errorf("extension count after GREASE filter should be 02, got %q in %q", j4[6:8], j4)
	}
}

func TestJA4Deterministic(t *testing.T) {
	ch := &ClientHello{
		Version:        0x0303,
		CipherSuites:   []uint16{0x1301, 0x1302},
		Extensions:     []uint16{0x0000, 0x0017},
		EllipticCurves: []uint16{0x001d},
		SignatureAlgos: []uint16{0x0403},
		SNI:            "a.test",
	}
	a := JA4(ch)
	b := JA4(ch)
	if a != b {
		t.Errorf("JA4 must be deterministic: %q vs %q", a, b)
	}
}

func TestJA3FiltersGREASEAndHashesCanonicalString(t *testing.T) {
	ch := &ClientHello{
		Version:        0x0303,
		CipherSuites:   []uint16{0x0a0a, 0x1301, 0x1302, 0x1303},
		Extensions:     []uint16{0x0000, 0x1a1a, 0x000a, 0x000b},
		EllipticCurves: []uint16{0x001d, 0x002a, 0x0017},
		ECPointFormats: []uint8{0x00},
	}
	got := JA3(ch)
	sum := sha256.Sum256([]byte("771,4865-4866-4867,0-10-11,29-42-23,0"))
	want := hex.EncodeToString(sum[:16])
	if got != want {
		t.Fatalf("JA3 hash = %q, want %q", got, want)
	}
}

func TestJA4VersionALPNAndClamp(t *testing.T) {
	ciphers := make([]uint16, 105)
	for i := range ciphers {
		ciphers[i] = uint16(0x1301 + i)
	}
	ch := &ClientHello{
		Version:       0x0301,
		SupportedVers: []uint16{0x0a0a, 0x0303},
		CipherSuites:  ciphers,
		Extensions:    []uint16{0x0000},
		ALPNProtocols: []string{"h3"},
		SNI:           "example.test",
	}
	j4 := JA4(ch)
	if j4[:10] != "t12d9901h3" {
		t.Fatalf("unexpected JA4 prefix %q in %q", j4[:10], j4)
	}
}

func TestParseClientHello_MinimalTLS13(t *testing.T) {
	// Hand-crafted minimal ClientHello record:
	// Record header (5): 16 03 03 00 XX
	// Handshake header (4): 01 00 00 YY
	// Version (2): 03 03
	// Random (32): zero bytes
	// SID (1+0): 00
	// Cipher suites (2 + N): 0004 1301 1302
	// Compression (1 + 1): 01 00
	// Extensions length (2): 0000 (no extensions) — still valid
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})                         // version
	body.Write(make([]byte, 32))                           // random
	body.WriteByte(0x00)                                   // sid len
	body.Write([]byte{0x00, 0x04, 0x13, 0x01, 0x13, 0x02}) // ciphers
	body.Write([]byte{0x01, 0x00})                         // compression
	body.Write([]byte{0x00, 0x00})                         // extensions length = 0

	// Handshake envelope
	var hs bytes.Buffer
	hs.WriteByte(0x01) // type: ClientHello
	bodyLen := body.Len()
	hs.Write([]byte{byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen)}) // 3-byte len
	hs.Write(body.Bytes())

	// Record envelope
	var rec bytes.Buffer
	rec.WriteByte(0x16)           // handshake
	rec.Write([]byte{0x03, 0x03}) // record version
	hsLen := hs.Len()
	rec.Write([]byte{byte(hsLen >> 8), byte(hsLen)}) // 2-byte len
	rec.Write(hs.Bytes())

	ch, raw, err := ParseClientHello(&rec)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if ch.Version != 0x0303 {
		t.Errorf("version = 0x%04x, want 0x0303", ch.Version)
	}
	if len(ch.CipherSuites) != 2 || ch.CipherSuites[0] != 0x1301 || ch.CipherSuites[1] != 0x1302 {
		t.Errorf("ciphers = %v", ch.CipherSuites)
	}
	if len(raw) == 0 {
		t.Error("raw bytes should be captured for replay")
	}
}

func TestParseClientHelloExtractsExtensions(t *testing.T) {
	rec := clientHelloRecord(t, []uint16{0x1301}, []tlsExtension{
		{typ: 0x0000, data: sniData("api.example.test")},
		{typ: 0x000a, data: vector16([]byte{0x00, 0x1d, 0x00, 0x17})},
		{typ: 0x000b, data: []byte{0x01, 0x00}},
		{typ: 0x000d, data: vector16([]byte{0x04, 0x03, 0x08, 0x04})},
		{typ: 0x0010, data: alpnData("h2", "http/1.1")},
		{typ: 0x002b, data: []byte{0x04, 0x03, 0x04, 0x03, 0x03}},
	})
	ch, _, err := ParseClientHello(bytes.NewReader(rec))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if ch.SNI != "api.example.test" {
		t.Fatalf("SNI = %q", ch.SNI)
	}
	if len(ch.EllipticCurves) != 2 || ch.EllipticCurves[0] != 0x001d {
		t.Fatalf("curves = %v", ch.EllipticCurves)
	}
	if len(ch.ECPointFormats) != 1 || ch.ECPointFormats[0] != 0x00 {
		t.Fatalf("point formats = %v", ch.ECPointFormats)
	}
	if len(ch.SignatureAlgos) != 2 || ch.SignatureAlgos[0] != 0x0403 {
		t.Fatalf("signature algos = %v", ch.SignatureAlgos)
	}
	if len(ch.ALPNProtocols) != 2 || ch.ALPNProtocols[0] != "h2" {
		t.Fatalf("ALPN = %v", ch.ALPNProtocols)
	}
	if len(ch.SupportedVers) != 2 || ch.SupportedVers[0] != 0x0304 {
		t.Fatalf("supported versions = %v", ch.SupportedVers)
	}
}

func TestParseClientHelloRejectsBadRecords(t *testing.T) {
	if _, _, err := ParseClientHello(bytes.NewReader([]byte{0x15, 0x03, 0x03, 0x00, 0x04, 0, 0, 0, 0})); err == nil {
		t.Fatal("expected non-handshake record to fail")
	}
	if _, _, err := ParseClientHello(bytes.NewReader([]byte{0x16, 0x03, 0x03, 0x00, 0x03, 0x01, 0, 0})); err == nil {
		t.Fatal("expected short handshake record to fail")
	}
}

func TestDatabaseLookup(t *testing.T) {
	db := mustDatabase(t)
	fp := Fingerprint{JA4: "t13d1715h2_5b57614c22b0_3d5424432f57"}
	c := db.Lookup(fp)
	if c.Label != "python-httpx" {
		t.Errorf("expected python-httpx match, got %+v", c)
	}
}

func TestDatabaseLookupPrefersJA4ThenPrefixThenJA3(t *testing.T) {
	db := newEmptyDatabase()
	db.Apply(&rules.TLSFingerprints{
		JA4Exact: []struct {
			Hash       string "yaml:\"hash\""
			Label      string "yaml:\"label\""
			Category   string "yaml:\"category\""
			Confidence int    "yaml:\"confidence\""
		}{{Hash: "exact", Label: "exact-lib", Category: "agent", Confidence: 99}},
		JA4Prefix: []struct {
			Prefix     string "yaml:\"prefix\""
			Label      string "yaml:\"label\""
			Category   string "yaml:\"category\""
			Confidence int    "yaml:\"confidence\""
		}{{Prefix: "prefix1234", Label: "prefix-browser", Category: "browser", Confidence: 60}},
		JA3Exact: []struct {
			Hash       string "yaml:\"hash\""
			Label      string "yaml:\"label\""
			Category   string "yaml:\"category\""
			Confidence int    "yaml:\"confidence\""
		}{{Hash: "ja3hash", Label: "ja3-scanner", Category: "scanner", Confidence: 88}},
	})
	if got := db.Lookup(Fingerprint{JA4: "exact", JA3: "ja3hash"}); got.Label != "exact-lib" {
		t.Fatalf("exact JA4 should win, got %+v", got)
	}
	if got := db.Lookup(Fingerprint{JA4: "prefix1234_suffix"}); got.Label != "prefix-browser" {
		t.Fatalf("JA4 prefix should match, got %+v", got)
	}
	if got := db.Lookup(Fingerprint{JA3: "ja3hash"}); got.Label != "ja3-scanner" {
		t.Fatalf("JA3 exact should match, got %+v", got)
	}
}

func TestClassifierFallbacks(t *testing.T) {
	store := NewStore(time.Minute)
	db := newEmptyDatabase()
	db.Apply(&rules.TLSFingerprints{
		JA4Prefix: []struct {
			Prefix     string "yaml:\"prefix\""
			Label      string "yaml:\"label\""
			Category   string "yaml:\"category\""
			Confidence int    "yaml:\"confidence\""
		}{{Prefix: "t13d1517", Label: "chrome", Category: "browser", Confidence: 80}},
	})
	c := NewClassifier(store, db)
	if _, _, _, ok := c.Classify("missing"); ok {
		t.Fatal("missing fingerprint should not classify")
	}
	store.Put("browser", Fingerprint{JA4: "t13d1517h2_aaaaaaaaaaaa_bbbbbbbbbbbb"})
	label, cat, conf, ok := c.Classify("browser")
	if !ok || label != "unknown-browser-like" || cat != "browser" || conf != 40 {
		t.Fatalf("browser-like fallback mismatch: %q %q %d %v", label, cat, conf, ok)
	}
	store.Put("unknown", Fingerprint{JA4: "t12i010100_aaaaaaaaaaaa_bbbbbbbbbbbb"})
	label, cat, conf, ok = c.Classify("unknown")
	if !ok || label != "unknown" || cat != "unknown" || conf != 50 {
		t.Fatalf("unknown fallback mismatch: %q %q %d %v", label, cat, conf, ok)
	}
}

func TestDatabaseBrowserPrefix(t *testing.T) {
	db := mustDatabase(t)
	// Unknown exact, but Chrome-like prefix
	fp := Fingerprint{JA4: "t13d1517h2_aaaaaaaaaaaa_bbbbbbbbbbbb"}
	if !db.LooksLikeBrowser(fp) {
		t.Error("Chrome prefix should be classified as browser-like")
	}
}

func TestStoreTTL(t *testing.T) {
	s := NewStore(0) // default 10min
	s.Put("127.0.0.1:1234", Fingerprint{JA4: "t13d..."})
	fp, ok := s.Get("127.0.0.1:1234")
	if !ok || fp.JA4 != "t13d..." {
		t.Error("Store did not round-trip fingerprint")
	}
}

func TestStoreExpiresAndGCsEntries(t *testing.T) {
	s := NewStore(time.Nanosecond)
	s.Put("client", Fingerprint{JA4: "old"})
	time.Sleep(time.Millisecond)
	if _, ok := s.Get("client"); ok {
		t.Fatal("expired fingerprint should not be returned")
	}
	s.GC()
	if len(s.entries) != 0 {
		t.Fatalf("GC should remove expired entries, still have %d", len(s.entries))
	}
}

type tlsExtension struct {
	typ  uint16
	data []byte
}

func clientHelloRecord(t *testing.T, ciphers []uint16, exts []tlsExtension) []byte {
	t.Helper()
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0x00)
	body.Write(u16Vector(ciphers))
	body.Write([]byte{0x01, 0x00})

	var extBody bytes.Buffer
	for _, e := range exts {
		writeU16(&extBody, e.typ)
		writeU16(&extBody, uint16(len(e.data)))
		extBody.Write(e.data)
	}
	writeU16(&body, uint16(extBody.Len()))
	body.Write(extBody.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(0x01)
	bodyLen := body.Len()
	hs.Write([]byte{byte(bodyLen >> 16), byte(bodyLen >> 8), byte(bodyLen)})
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(0x16)
	rec.Write([]byte{0x03, 0x03})
	writeU16(&rec, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

func sniData(host string) []byte {
	var name bytes.Buffer
	name.WriteByte(0x00)
	writeU16(&name, uint16(len(host)))
	name.WriteString(host)
	return vector16(name.Bytes())
}

func alpnData(protocols ...string) []byte {
	var inner bytes.Buffer
	for _, p := range protocols {
		inner.WriteByte(byte(len(p)))
		inner.WriteString(p)
	}
	return vector16(inner.Bytes())
}

func vector16(b []byte) []byte {
	var out bytes.Buffer
	writeU16(&out, uint16(len(b)))
	out.Write(b)
	return out.Bytes()
}

func u16Vector(vs []uint16) []byte {
	var out bytes.Buffer
	writeU16(&out, uint16(len(vs)*2))
	for _, v := range vs {
		writeU16(&out, v)
	}
	return out.Bytes()
}

func writeU16(b *bytes.Buffer, v uint16) {
	b.WriteByte(byte(v >> 8))
	b.WriteByte(byte(v))
}
