package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	updateOwner    = "C0oki3s"
	updateRepo     = "veilgate"
	updateAPIBase  = "https://api.github.com/repos/" + updateOwner + "/" + updateRepo
	updateHTMLBase = "https://github.com/" + updateOwner + "/" + updateRepo
	maxBinarySize  = 100 * 1024 * 1024 // 100 MB hard cap
)

// updateRelease is the minimal subset of the GitHub Releases API
// response that the self-update command needs.
type updateRelease struct {
	TagName    string          `json:"tag_name"`
	Name       string          `json:"name"`
	HTMLURL    string          `json:"html_url"`
	Draft      bool            `json:"draft"`
	PreRelease bool            `json:"prerelease"`
	Assets     []updateAsset   `json:"assets"`
}

type updateAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// runUpdate implements `veilgate update`.
//
// It fetches a release from the veilgate GitHub repository, downloads
// the binary archive for the current OS/arch, verifies the checksum,
// extracts the binary, and atomically replaces the running executable.
//
// The subcommand requires write permission to the directory containing
// the running binary. On a standard install that means running with sudo.
func runUpdate(args []string) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	targetVer := fs.String("version", "latest", `release tag to install, e.g. "v1.2.0", or "latest"`)
	checkOnly := fs.Bool("check", false, "check whether an update is available without installing")
	_ = fs.Parse(args)

	rel, err := fetchUpdateRelease(*targetVer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: resolve release %q: %v\n", *targetVer, err)
		os.Exit(1)
	}

	current := version // set by -ldflags at build time, e.g. "v1.1.0"

	if *checkOnly {
		if current == rel.TagName {
			fmt.Printf("update: up to date (%s)\n", current)
		} else {
			fmt.Printf("update: %s → %s available\n", current, rel.TagName)
			fmt.Printf("        Run `sudo veilgate update` to install.\n")
			os.Exit(2) // non-zero so scripts can detect update available
		}
		return
	}

	if current == rel.TagName {
		fmt.Printf("update: already at %s — nothing to do\n", current)
		fmt.Printf("        Use --version to force a specific tag.\n")
		return
	}

	if current == "dev" {
		fmt.Printf("update: dev build → installing %s\n", rel.TagName)
	} else {
		fmt.Printf("update: %s → %s\n", current, rel.TagName)
	}

	assetName, downloadURL, checksumURL := findUpdateAsset(rel)
	if downloadURL == "" {
		fmt.Fprintf(os.Stderr, "update: no binary asset found for %s/%s in release %s\n",
			runtime.GOOS, runtime.GOARCH, rel.TagName)
		fmt.Fprintf(os.Stderr, "        Available assets: %s/releases/tag/%s\n",
			updateHTMLBase, rel.TagName)
		os.Exit(1)
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: resolve executable path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("update: downloading %s\n", assetName)
	data, err := downloadUpdateAsset(downloadURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: download: %v\n", err)
		os.Exit(1)
	}

	if checksumURL != "" {
		fmt.Printf("update: verifying checksum\n")
		if err := verifyUpdateChecksum(data, assetName, checksumURL); err != nil {
			fmt.Fprintf(os.Stderr, "update: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("update: checksum OK\n")
	} else {
		fmt.Fprintf(os.Stderr, "update: warning: no checksums.txt in release — skipping verification\n")
	}

	newBin, err := extractBinaryFromTarGz(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update: extract binary: %v\n", err)
		os.Exit(1)
	}

	if err := atomicReplaceExecutable(exe, newBin); err != nil {
		fmt.Fprintf(os.Stderr, "update: install: %v\n", err)
		if strings.Contains(err.Error(), "permission") {
			fmt.Fprintf(os.Stderr, "        Try: sudo veilgate update\n")
		}
		os.Exit(1)
	}

	fmt.Printf("update: installed %s → %s\n", rel.TagName, exe)
	fmt.Printf("update: restart to use the new version:\n")
	fmt.Printf("          sudo systemctl restart veilgate\n")
}

// fetchUpdateRelease returns release metadata from the GitHub Releases API.
func fetchUpdateRelease(ver string) (*updateRelease, error) {
	var apiURL string
	if ver == "latest" {
		apiURL = updateAPIBase + "/releases/latest"
	} else {
		apiURL = updateAPIBase + "/releases/tags/" + ver
	}
	// apiGET and validateGitHubURL are defined in update_rules.go (same package).
	body, err := apiGET(apiURL)
	if err != nil {
		return nil, err
	}
	var rel updateRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parse release JSON: %w", err)
	}
	if rel.TagName == "" {
		return nil, fmt.Errorf("release not found — check the version tag or visit %s/releases", updateHTMLBase)
	}
	return &rel, nil
}

// findUpdateAsset locates the tar.gz binary asset and checksums.txt URL
// for the current OS and architecture.
// GoReleaser naming: veilgate_{version_no_v}_{goos}_{goarch}.tar.gz
func findUpdateAsset(rel *updateRelease) (name, downloadURL, checksumURL string) {
	verClean := strings.TrimPrefix(rel.TagName, "v")
	want := fmt.Sprintf("veilgate_%s_%s_%s.tar.gz", verClean, runtime.GOOS, runtime.GOARCH)
	for _, a := range rel.Assets {
		switch a.Name {
		case want:
			name = a.Name
			downloadURL = a.BrowserDownloadURL
		case "checksums.txt":
			checksumURL = a.BrowserDownloadURL
		}
	}
	return
}

// downloadUpdateAsset fetches a release asset over HTTPS. It enforces HTTPS,
// GitHub domain allowlist, and a 100 MB size cap.
func downloadUpdateAsset(rawURL string) ([]byte, error) {
	if err := validateGitHubURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "veilgate-update/"+version)
	req.Header.Set("Accept", "application/octet-stream")

	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return fmt.Errorf("too many redirects")
			}
			return validateGitHubURL(req.URL.String())
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBinarySize))
}

// verifyUpdateChecksum downloads checksums.txt and verifies that the SHA-256
// of data matches the entry for assetName.
func verifyUpdateChecksum(data []byte, assetName, checksumURL string) error {
	// checksums.txt is a small text file; apiGET's 1 MB cap is fine here.
	body, err := apiGET(checksumURL)
	if err != nil {
		return fmt.Errorf("fetch checksums.txt: %w", err)
	}
	want := ""
	for _, line := range strings.Split(string(body), "\n") {
		// sha256sum format: "<hash>  <filename>" (two spaces)
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

// extractBinaryFromTarGz reads a GoReleaser tar.gz archive and returns the
// contents of the "veilgate" binary entry.
func extractBinaryFromTarGz(data []byte) ([]byte, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if filepath.Base(hdr.Name) == "veilgate" {
			return io.ReadAll(io.LimitReader(tr, maxBinarySize))
		}
	}
	return nil, fmt.Errorf("binary 'veilgate' not found in archive")
}

// atomicReplaceExecutable writes newBin to exe+".new" (preserving the
// existing file mode) then renames it over exe. Rename is atomic on Linux
// when both paths are on the same filesystem, which is the common case for
// /usr/local/bin. Cleans up the temp file on any error.
func atomicReplaceExecutable(exe string, newBin []byte) error {
	fi, err := os.Stat(exe)
	if err != nil {
		return fmt.Errorf("stat %s: %w", exe, err)
	}

	tmp := exe + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode())
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	if _, err := f.Write(newBin); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename %s → %s: %w", tmp, exe, err)
	}
	return nil
}
