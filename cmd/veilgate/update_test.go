package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
)

// ── findUpdateAsset ───────────────────────────────────────────────────────────

func TestFindUpdateAssetMatchesCurrentPlatform(t *testing.T) {
	verClean := "1.2.0"
	assetName := fmt.Sprintf("veilgate_%s_%s_%s.tar.gz", verClean, runtime.GOOS, runtime.GOARCH)
	rel := &updateRelease{
		TagName: "v1.2.0",
		Assets: []updateAsset{
			{Name: assetName, BrowserDownloadURL: "https://github.com/C0oki3s/veilgate/releases/download/v1.2.0/" + assetName},
			{Name: "checksums.txt", BrowserDownloadURL: "https://github.com/C0oki3s/veilgate/releases/download/v1.2.0/checksums.txt"},
		},
	}
	name, dlURL, sumURL := findUpdateAsset(rel)
	if name != assetName {
		t.Fatalf("name = %q, want %q", name, assetName)
	}
	if dlURL == "" {
		t.Fatal("downloadURL should not be empty")
	}
	if sumURL == "" {
		t.Fatal("checksumURL should not be empty when checksums.txt is present")
	}
}

func TestFindUpdateAssetEmptyAssetsReturnsEmpty(t *testing.T) {
	rel := &updateRelease{TagName: "v9.0.0", Assets: []updateAsset{}}
	name, dlURL, _ := findUpdateAsset(rel)
	if name != "" || dlURL != "" {
		t.Fatalf("expected empty result, got name=%q dlURL=%q", name, dlURL)
	}
}

// ── verifyUpdateChecksum (pure math, no HTTP) ─────────────────────────────────

// verifyChecksumBody is the SHA-256 verification logic extracted for unit
// testing without the HTTP + GitHub domain-allowlist layer.
func verifyChecksumBody(data []byte, assetName, checksumBody string) error {
	want := ""
	for _, line := range strings.Split(checksumBody, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			want = fields[0]
			break
		}
	}
	if want == "" {
		return fmt.Errorf("asset %q not listed in checksums.txt", assetName)
	}
	sum := sha256.Sum256(data)
	got := hex.EncodeToString(sum[:])
	if got != want {
		return fmt.Errorf("checksum mismatch — got %s, want %s", got, want)
	}
	return nil
}

func TestVerifyChecksumOK(t *testing.T) {
	payload := []byte("fake veilgate binary")
	sum := sha256.Sum256(payload)
	asset := "veilgate_1.2.0_linux_amd64.tar.gz"
	body := hex.EncodeToString(sum[:]) + "  " + asset + "\n"
	if err := verifyChecksumBody(payload, asset, body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyChecksumMismatch(t *testing.T) {
	asset := "veilgate_1.2.0_linux_amd64.tar.gz"
	body := strings.Repeat("0", 64) + "  " + asset + "\n"
	err := verifyChecksumBody([]byte("data"), asset, body)
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("expected mismatch error, got: %v", err)
	}
}

func TestVerifyChecksumNotListed(t *testing.T) {
	body := "abc123  other.tar.gz\n"
	err := verifyChecksumBody([]byte("data"), "veilgate_1.2.0_linux_amd64.tar.gz", body)
	if err == nil {
		t.Fatal("expected error for unlisted asset")
	}
}

// ── extractBinaryFromTarGz ────────────────────────────────────────────────────

func makeTarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Size:     int64(len(content)),
		Mode:     0755,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

func TestExtractBinaryFromTarGz(t *testing.T) {
	want := []byte("fake veilgate binary bytes")
	got, err := extractBinaryFromTarGz(makeTarGz(t, "veilgate", want))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("extracted content differs from original")
	}
}

func TestExtractBinaryFromTarGzWithDirectoryPrefix(t *testing.T) {
	// GoReleaser may prefix entries: "veilgate_1.2.0_linux_amd64/veilgate"
	want := []byte("binary content")
	got, err := extractBinaryFromTarGz(makeTarGz(t, "veilgate_1.2.0_linux_amd64/veilgate", want))
	if err != nil {
		t.Fatalf("unexpected error with prefixed path: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("extracted content differs")
	}
}

func TestExtractBinaryFromTarGzMissingBinary(t *testing.T) {
	archive := makeTarGz(t, "configs/veilgate.yaml", []byte("config: true"))
	_, err := extractBinaryFromTarGz(archive)
	if err == nil {
		t.Fatal("expected error when binary not present in archive")
	}
}

func TestExtractBinaryFromTarGzBadGzip(t *testing.T) {
	_, err := extractBinaryFromTarGz([]byte("not a gzip file"))
	if err == nil {
		t.Fatal("expected error for invalid gzip data")
	}
}

// ── atomicReplaceExecutable ───────────────────────────────────────────────────

func TestAtomicReplaceExecutable(t *testing.T) {
	exe := t.TempDir() + "/veilgate"
	if err := os.WriteFile(exe, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}

	newBin := []byte("new binary content")
	if err := atomicReplaceExecutable(exe, newBin); err != nil {
		t.Fatalf("atomicReplaceExecutable: %v", err)
	}

	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, newBin) {
		t.Fatalf("content after replace: got %q, want %q", got, newBin)
	}
	if _, err := os.Stat(exe + ".new"); !os.IsNotExist(err) {
		t.Error("temp file exe.new should have been removed after rename")
	}
}

func TestAtomicReplaceExecutableNonexistentTarget(t *testing.T) {
	err := atomicReplaceExecutable("/nonexistent/path/veilgate", []byte("x"))
	if err == nil {
		t.Fatal("expected error for nonexistent target directory")
	}
}
