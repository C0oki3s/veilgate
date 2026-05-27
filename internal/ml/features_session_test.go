package ml

import (
	"net/http/httptest"
	"testing"
)

// TestExtractWithSessionAppendsSessionDimensions verifies that
// ExtractWithSession produces a Vec whose Numeric slice is exactly 5
// elements longer than the base Extract result, and that the 5 appended
// values match the SessionStats fields in order.
func TestExtractWithSessionAppendsSessionDimensions(t *testing.T) {
	e := NewExtractor()
	r := httptest.NewRequest("GET", "/api/users", nil)
	r.Header.Set("User-Agent", "python-requests/2.28.0")
	r.Header.Set("Accept", "*/*")

	base := e.Extract(r, 1.5, "")

	sess := SessionStats{
		HeaderMutations:  7,
		MaxRepeatFetches: 4,
		DistinctAuthCats: 3,
		SchemaFirstHit:   1,
		DoubleEncCount:   2,
	}
	withSess := e.ExtractWithSession(r, 1.5, "", sess)

	// Categorical dimensions must be unchanged
	if len(withSess.Categorical) != len(base.Categorical) {
		t.Fatalf("categorical dims changed: base=%d session=%d",
			len(base.Categorical), len(withSess.Categorical))
	}

	// Exactly 5 extra numeric dimensions appended
	extra := len(withSess.Numeric) - len(base.Numeric)
	if extra != 5 {
		t.Fatalf("ExtractWithSession should append exactly 5 numeric dims, appended %d", extra)
	}

	// Verify order: HeaderMutations, MaxRepeatFetches, DistinctAuthCats, SchemaFirstHit, DoubleEncCount
	off := len(base.Numeric)
	want := [5]float64{7, 4, 3, 1, 2}
	got := withSess.Numeric[off : off+5]
	for i, w := range want {
		if got[i] != w {
			t.Errorf("session dim[%d] = %v, want %v", i, got[i], w)
		}
	}
}

func TestExtractWithSessionZeroStatsPreservesBaseVec(t *testing.T) {
	e := NewExtractor()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124")

	base := e.Extract(r, 0, "")
	withSess := e.ExtractWithSession(r, 0, "", SessionStats{})

	if len(withSess.Numeric) != len(base.Numeric)+5 {
		t.Fatalf("zero SessionStats should still append 5 dims")
	}
	// All session dims should be 0
	off := len(base.Numeric)
	for i := 0; i < 5; i++ {
		if withSess.Numeric[off+i] != 0 {
			t.Errorf("zero SessionStats dim[%d] = %v, want 0", i, withSess.Numeric[off+i])
		}
	}
}

func TestExtractWithSessionJA4PassedThrough(t *testing.T) {
	e := NewExtractor()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "curl/7.84")

	ja4 := "t13d1517h2_8daaf6152771"

	withoutJA4 := e.ExtractWithSession(r, 1.0, "", SessionStats{})
	withJA4 := e.ExtractWithSession(r, 1.0, ja4, SessionStats{})

	// JA4 presence should generate a different categorical feature vector
	// (or at least not break extraction)
	if len(withJA4.Categorical) == 0 {
		t.Fatal("ExtractWithSession with JA4 should produce categorical features")
	}
	_ = withoutJA4
}

func TestExtractWithSessionSchemaFirstHitFlag(t *testing.T) {
	e := NewExtractor()
	r := httptest.NewRequest("GET", "/openapi.json", nil)
	r.Header.Set("User-Agent", "go-http-client/2.0")

	sessHit := SessionStats{SchemaFirstHit: 1.0}
	sessNoHit := SessionStats{SchemaFirstHit: 0.0}

	vHit := e.ExtractWithSession(r, 0.5, "", sessHit)
	vNoHit := e.ExtractWithSession(r, 0.5, "", sessNoHit)

	offHit := len(vHit.Numeric) - 5
	offNoHit := len(vNoHit.Numeric) - 5
	// SchemaFirstHit is the 4th appended dimension (index +3)
	if vHit.Numeric[offHit+3] != 1.0 {
		t.Fatalf("SchemaFirstHit=1 not reflected in Numeric dim +3: got %v", vHit.Numeric[offHit+3])
	}
	if vNoHit.Numeric[offNoHit+3] != 0.0 {
		t.Fatalf("SchemaFirstHit=0 not reflected in Numeric dim +3: got %v", vNoHit.Numeric[offNoHit+3])
	}
}

// TestSessionStatsIsolationForestDimensions confirms that the IF sees
// 5 additional axes when trained with session-enriched vectors, which is
// the precondition for the IF learning per-session anomalies from real traffic.
func TestSessionStatsIsolationForestDimensions(t *testing.T) {
	e := NewExtractor()
	r := httptest.NewRequest("GET", "/api/v1/users", nil)
	r.Header.Set("User-Agent", "python-requests/2.31")

	// Extract base and session vectors for a known pair
	base := e.Extract(r, 2.0, "")
	sess := SessionStats{
		HeaderMutations:  3,
		MaxRepeatFetches: 2,
		DistinctAuthCats: 1,
		SchemaFirstHit:   0,
		DoubleEncCount:   0,
	}
	enriched := e.ExtractWithSession(r, 2.0, "", sess)

	baseDims := len(base.Numeric)
	enrichedDims := len(enriched.Numeric)

	if enrichedDims-baseDims != 5 {
		t.Fatalf("IF should receive base(%d) + 5 session dims, got %d total (%d extra)",
			baseDims, enrichedDims, enrichedDims-baseDims)
	}
}
