package ml

import (
	"math"
	"math/rand"
	"runtime"
	"sync"
)

// IsoForest is a pure-Go Isolation Forest. Liu, Ting, Zhou 2008.
// Semi-supervised / unsupervised: trained on recent traffic (mostly
// human in a healthy deployment) so anomalies score high. Re-fit
// periodically from the persist store.
type IsoForest struct {
	mu    sync.RWMutex
	trees []*itree
	c     float64 // expected path length for sample size
}

type itree struct {
	feat       int
	split      float64
	left, right *itree
	depth      int
	size       int // leaf size, 0 for internal nodes
}

// NewIsoForest returns an empty forest. Call Fit to train.
func NewIsoForest() *IsoForest {
	return &IsoForest{}
}

// Fit builds trees from the sample. treeCount trees, each built on
// sampleSize rows chosen without replacement. maxDepth caps depth;
// ceil(log2(sampleSize)) is a good default.
//
// Trees are grown in parallel across runtime.NumCPU() workers. Each
// worker owns its own RNG (seeded deterministically off the tree
// index) so the fit is reproducible AND embarrassingly parallel.
// Readers are only blocked during the final pointer-swap at the end;
// Score() keeps serving the previous forest throughout the fit.
func (f *IsoForest) Fit(data [][]float64, treeCount, sampleSize, maxDepth int) {
	if treeCount <= 0 {
		treeCount = 50
	}
	if sampleSize <= 0 {
		sampleSize = 256
	}
	if maxDepth <= 0 {
		maxDepth = int(math.Ceil(math.Log2(float64(sampleSize))))
	}
	if len(data) == 0 {
		f.mu.Lock()
		f.trees = nil
		f.mu.Unlock()
		return
	}

	workers := runtime.NumCPU()
	if workers > treeCount {
		workers = treeCount
	}
	if workers < 1 {
		workers = 1
	}

	trees := make([]*itree, treeCount)
	jobs := make(chan int, treeCount)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				// Per-tree seed keeps fits reproducible even though trees
				// are built out of order across workers.
				rng := rand.New(rand.NewSource(int64(idx) + 1))
				trees[idx] = growTree(sample(data, sampleSize, rng), 0, maxDepth, rng)
			}
		}()
	}
	for i := 0; i < treeCount; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	f.mu.Lock()
	f.trees = trees
	f.c = expectedPath(sampleSize)
	f.mu.Unlock()
}

// Score returns an anomaly score in [0,1]. ~0.5 is the expected score
// for a random point; values > 0.6 are commonly treated as anomalies.
func (f *IsoForest) Score(x []float64) float64 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.trees) == 0 || len(x) == 0 {
		return 0.5
	}
	var sum float64
	for _, t := range f.trees {
		sum += pathLength(t, x, 0)
	}
	avg := sum / float64(len(f.trees))
	c := f.c
	if c == 0 {
		c = 1
	}
	return math.Pow(2, -avg/c)
}

// TreeCount returns the number of trees currently in the forest.
func (f *IsoForest) TreeCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.trees)
}

func sample(data [][]float64, n int, rng *rand.Rand) [][]float64 {
	if n >= len(data) {
		out := make([][]float64, len(data))
		copy(out, data)
		return out
	}
	// Reservoir sampling keeps the scan O(n) without materializing the
	// whole index array.
	out := make([][]float64, n)
	for i := 0; i < n; i++ {
		out[i] = data[i]
	}
	for i := n; i < len(data); i++ {
		j := rng.Intn(i + 1)
		if j < n {
			out[j] = data[i]
		}
	}
	return out
}

func growTree(data [][]float64, depth, maxDepth int, rng *rand.Rand) *itree {
	if depth >= maxDepth || len(data) <= 1 {
		return &itree{depth: depth, size: len(data)}
	}
	// Feature count: all rows share the same width. Tolerate ragged
	// edges by picking the minimum.
	dim := minDim(data)
	if dim == 0 {
		return &itree{depth: depth, size: len(data)}
	}
	// Pick a split feature with non-zero range.
	var feat int
	var lo, hi float64
	for try := 0; try < 5; try++ {
		f := rng.Intn(dim)
		l, h := minMax(data, f)
		if h > l {
			feat, lo, hi = f, l, h
			break
		}
	}
	if hi == lo {
		return &itree{depth: depth, size: len(data)}
	}
	split := lo + rng.Float64()*(hi-lo)

	var leftRows, rightRows [][]float64
	for _, row := range data {
		if row[feat] < split {
			leftRows = append(leftRows, row)
		} else {
			rightRows = append(rightRows, row)
		}
	}
	return &itree{
		feat:  feat,
		split: split,
		left:  growTree(leftRows, depth+1, maxDepth, rng),
		right: growTree(rightRows, depth+1, maxDepth, rng),
		depth: depth,
	}
}

func pathLength(t *itree, x []float64, depth int) float64 {
	if t == nil {
		return float64(depth)
	}
	if t.left == nil && t.right == nil {
		// Leaf — add the expected path length of an unsplit subset of
		// size `t.size`. Matches the original paper's termination.
		return float64(depth) + expectedPath(t.size)
	}
	if t.feat >= len(x) {
		return float64(depth)
	}
	if x[t.feat] < t.split {
		return pathLength(t.left, x, depth+1)
	}
	return pathLength(t.right, x, depth+1)
}

// expectedPath is the average path length of an unsuccessful BST search
// over n samples — the Isolation Forest normalizer c(n).
func expectedPath(n int) float64 {
	if n <= 1 {
		return 0
	}
	h := math.Log(float64(n-1)) + 0.5772156649 // Euler-Mascheroni
	return 2*h - 2*float64(n-1)/float64(n)
}

func minDim(data [][]float64) int {
	m := len(data[0])
	for _, row := range data[1:] {
		if len(row) < m {
			m = len(row)
		}
	}
	return m
}

func minMax(data [][]float64, f int) (float64, float64) {
	lo := math.Inf(+1)
	hi := math.Inf(-1)
	for _, row := range data {
		if f >= len(row) {
			continue
		}
		v := row[f]
		if v < lo {
			lo = v
		}
		if v > hi {
			hi = v
		}
	}
	return lo, hi
}
