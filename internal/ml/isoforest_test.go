package ml

import (
	"math/rand"
	"testing"
)

func TestIsoForestEmptyReturnsHalf(t *testing.T) {
	f := NewIsoForest()
	if got := f.Score([]float64{1, 2, 3}); got != 0.5 {
		t.Fatalf("empty forest score = %v, want 0.5", got)
	}
}

func TestIsoForestAnomaliesScoreHigher(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	// Bulk of data: tight cluster around (0,0).
	data := make([][]float64, 0, 512)
	for i := 0; i < 512; i++ {
		data = append(data, []float64{rng.NormFloat64() * 0.1, rng.NormFloat64() * 0.1})
	}
	f := NewIsoForest()
	f.Fit(data, 100, 256, 0)

	normal := f.Score([]float64{0, 0})
	outlier := f.Score([]float64{50, 50})

	if outlier <= normal {
		t.Fatalf("outlier score %v not greater than normal %v", outlier, normal)
	}
	if outlier < 0.55 {
		t.Fatalf("outlier score %v, expected >0.55", outlier)
	}
}

func TestIsoForestFitResetsOnEmptyData(t *testing.T) {
	f := NewIsoForest()
	f.Fit([][]float64{{1, 2}}, 5, 8, 0)
	f.Fit(nil, 5, 8, 0)
	if f.TreeCount() != 0 {
		t.Fatalf("TreeCount=%d after empty fit, want 0", f.TreeCount())
	}
}

func TestExpectedPathMonotonic(t *testing.T) {
	prev := expectedPath(2)
	for n := 3; n < 1000; n += 7 {
		cur := expectedPath(n)
		if cur < prev {
			t.Fatalf("expectedPath not monotonic at n=%d: %v < %v", n, cur, prev)
		}
		prev = cur
	}
}
