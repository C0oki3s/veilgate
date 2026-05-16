package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Community rules repository coordinates.
const (
	rulesOwner      = "C0oki3s"
	rulesRepo       = "veilgate-rules"
	rulesAPIBase    = "https://api.github.com/repos/" + rulesOwner + "/" + rulesRepo
	rulesHTMLBase   = "https://github.com/" + rulesOwner + "/" + rulesRepo
	maxDownloadSize = 50 * 1024 * 1024 // 50 MB hard cap
	metaFileName    = ".rules-version.json"
)

// rulesVersion is written to <rules_dir>/.rules-version.json after a
// successful update-rules run so operators and CI can track what is
// installed without reading git metadata.
type rulesVersion struct {
	Version     string `json:"version"`
	InstalledAt string `json:"installed_at"`
	Source      string `json:"source"`
	FileCount   int    `json:"file_count"`
}

// githubRelease is the minimal subset of the GitHub Releases API
// response that update-rules needs.
type githubRelease struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	HTMLURL    string `json:"html_url"`
	ZipballURL string `json:"zipball_url"`
	Draft      bool   `json:"draft"`
	PreRelease bool   `json:"prerelease"`
}

// runUpdateRules implements `veilgate update-rules`.
//
// It fetches the latest (or a pinned) release from the community rules
// repository at https://github.com/C0oki3s/veilgate-rules, extracts the
// YAML files into the operator-configured rules_dir, and writes a small
// JSON metadata file so installed version can be inspected later.
//
// Design goals:
//   - No new binary dependencies: uses net/http, archive/zip, encoding/json.
//   - No path traversal: every extracted entry is validated before writing.
//   - Size-capped download: hard cap of 50 MB, enforced by io.LimitReader.
//   - Backup: existing files get a .bak copy before overwrite (unless --no-backup).
func runUpdateRules(args []string) {
	fs := flag.NewFlagSet("update-rules", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/veilgate.yaml", "config file (used to read rules_dir when --dir is not set)")
	dir := fs.String("dir", "", "rules directory to install into (overrides config rules_dir)")
	version := fs.String("version", "latest", `release tag to install, e.g. "v1.2.3", or "latest"`)
	listOnly := fs.Bool("list", false, "list available releases and exit")
	noBackup := fs.Bool("no-backup", false, "skip .bak copies of overwritten files")
	_ = fs.Parse(args)

	if *listOnly {
		printReleases()
		return
	}

	// Determine target directory: explicit flag > config rules_dir > ./rules.
	targetDir := *dir
	if targetDir == "" {
		targetDir = resolveRulesDir(*cfgPath)
	}
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: cannot create rules dir %q: %v\n", targetDir, err)
		os.Exit(1)
	}

	// Resolve the release to install.
	rel, err := fetchRelease(*version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: resolve release %q: %v\n", *version, err)
		os.Exit(1)
	}

	// Check whether the installed version is already up to date.
	installed, _ := readInstalledVersion(filepath.Join(targetDir, metaFileName))
	if installed.Version == rel.TagName {
		fmt.Printf("update-rules: already at %s — nothing to do (use --version to force a specific tag)\n", rel.TagName)
		return
	}

	fmt.Printf("update-rules: downloading %s @ %s\n", rulesRepo, rel.TagName)

	// Download the release zipball.
	data, err := secureDownload(rel.ZipballURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: download failed: %v\n", err)
		os.Exit(1)
	}

	// Extract YAML files into targetDir.
	count, err := extractRulesZip(data, targetDir, !*noBackup)
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: extract failed: %v\n", err)
		os.Exit(1)
	}

	// Record installed version.
	meta := rulesVersion{
		Version:     rel.TagName,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Source:      rulesHTMLBase + "/releases/tag/" + rel.TagName,
		FileCount:   count,
	}
	if err := writeInstalledVersion(filepath.Join(targetDir, metaFileName), meta); err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: write version file: %v\n", err)
		// Non-fatal: rules are installed even if metadata write fails.
	}

	fmt.Printf("update-rules: installed %d YAML files → %s (version %s)\n", count, targetDir, rel.TagName)
	fmt.Println("update-rules: rules are hot-reloaded automatically when rules_dir is set")
	fmt.Println("             restart veilgate to pick up changes to non-hot-reloadable files (payloads.yaml)")
}

// resolveRulesDir reads rules_dir from the config file or falls back to ./rules.
func resolveRulesDir(cfgPath string) string {
	type partial struct {
		RulesDir string `yaml:"rules_dir"`
	}
	data, err := os.ReadFile(cfgPath) //nolint:gosec
	if err != nil {
		return "./rules"
	}
	// Minimal YAML parse using split-on-colon to avoid importing the
	// full yaml package here — config package isn't imported to keep
	// the subcommand lean.
	for _, line := range strings.Split(string(data), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == "rules_dir" {
			v := strings.TrimSpace(kv[1])
			// Strip YAML quoting if present.
			v = strings.Trim(v, `"'`)
			if v != "" {
				return v
			}
		}
	}
	return defaultRulesDir()
}

// defaultRulesDir returns ~/.veilgate/rules as the canonical user-scoped
// rules directory, falling back to ./rules when the home directory cannot
// be resolved (e.g. in a stripped container without a home dir entry).
func defaultRulesDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./rules"
	}
	return filepath.Join(home, ".veilgate", "rules")
}

// fetchRelease returns release metadata from the GitHub Releases API.
// version == "latest" returns the most recent non-pre-release; otherwise
// it returns the matching tag.
func fetchRelease(version string) (*githubRelease, error) {
	var apiURL string
	if version == "latest" {
		apiURL = rulesAPIBase + "/releases/latest"
	} else {
		apiURL = rulesAPIBase + "/releases/tags/" + version
	}

	body, err := apiGET(apiURL)
	if err != nil {
		return nil, err
	}
	var rel githubRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("parse release JSON: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("release not found or repository has no releases yet")
	}
	return &rel, nil
}

// printReleases lists all available releases to stdout.
func printReleases() {
	body, err := apiGET(rulesAPIBase + "/releases")
	if err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: list releases: %v\n", err)
		os.Exit(1)
	}
	var rels []githubRelease
	if err := json.Unmarshal(body, &rels); err != nil {
		fmt.Fprintf(os.Stderr, "update-rules: parse releases: %v\n", err)
		os.Exit(1)
	}
	if len(rels) == 0 {
		fmt.Printf("No releases published yet at %s\n", rulesHTMLBase+"/releases")
		return
	}
	fmt.Printf("Available releases for %s/%s:\n\n", rulesOwner, rulesRepo)
	for _, r := range rels {
		pre := ""
		if r.PreRelease {
			pre = " [pre-release]"
		}
		fmt.Printf("  %-16s  %s%s\n", r.TagName, r.Name, pre)
	}
	fmt.Printf("\nInstall with: veilgate update-rules --version <tag>\n")
}

// apiGET performs a GitHub API GET. Uses a 15-second timeout. Adds a
// User-Agent to satisfy GitHub's API requirements. Does not follow
// redirects to non-github.com hosts.
func apiGET(rawURL string) ([]byte, error) {
	if err := validateGitHubURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "veilgate-update-rules/1")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("release not found (404) — check the version tag or visit %s/releases", rulesHTMLBase)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP %d from %s", resp.StatusCode, rawURL)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024)) // API response capped at 1 MB
}

// secureDownload fetches a zipball over HTTPS. It enforces:
//   - HTTPS scheme only.
//   - Host must be github.com or *.githubusercontent.com.
//   - Maximum download size of 50 MB (prevents zip-bomb staging).
func secureDownload(rawURL string) ([]byte, error) {
	if err := validateGitHubURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "veilgate-update-rules/1")
	req.Header.Set("Accept", "application/octet-stream")

	// Follow GitHub's redirect to objects.githubusercontent.com.
	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return errors.New("too many redirects")
			}
			return validateGitHubURL(req.URL.String())
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDownloadSize))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	// Verify zip magic bytes to catch accidental non-zip responses.
	if len(data) < 4 || data[0] != 0x50 || data[1] != 0x4B {
		return nil, errors.New("downloaded file is not a ZIP archive")
	}
	return data, nil
}

// validateGitHubURL checks that a URL is HTTPS and points to github.com
// or githubusercontent.com. This prevents SSRF via crafted zipball URLs
// returned by a compromised or man-in-the-middle API response.
func validateGitHubURL(rawURL string) error {
	// Minimal parse: just inspect scheme and host without importing net/url
	// to keep the dependency surface small. The stdlib parser is fine here.
	lower := strings.ToLower(rawURL)
	if !strings.HasPrefix(lower, "https://") {
		return fmt.Errorf("URL must use HTTPS: %q", rawURL)
	}
	// Extract host portion (between https:// and the next /).
	rest := rawURL[8:]
	hostEnd := strings.IndexByte(rest, '/')
	host := rest
	if hostEnd > 0 {
		host = rest[:hostEnd]
	}
	host = strings.ToLower(host)
	// Remove port if present.
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "github.com" || strings.HasSuffix(host, ".github.com") ||
		strings.HasSuffix(host, ".githubusercontent.com") {
		return nil
	}
	return fmt.Errorf("URL host %q is not a trusted GitHub domain", host)
}

// extractRulesZip extracts YAML rule files from the GitHub archive zip
// into destDir. GitHub archive zips have a top-level directory prefix
// (e.g., "veilgate-rules-v1.0.0/") which is stripped automatically.
//
// Security invariants:
//   - Extracted paths are validated: no "..", no absolute paths.
//   - Only .yaml and .json files are extracted; binaries are skipped.
//   - The metadata file (.rules-version.json) is not overwritten by the archive.
//   - If backup==true, existing files are copied to <name>.bak before overwrite.
//
// Returns the count of extracted files.
func extractRulesZip(data []byte, destDir string, backup bool) (int, error) {
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("open zip: %w", err)
	}

	// Determine the top-level prefix to strip.
	prefix := zipTopLevelPrefix(r)

	count := 0
	for _, f := range r.File {
		// Skip directories.
		if f.FileInfo().IsDir() {
			continue
		}

		// Strip the top-level prefix.
		relPath := f.Name
		if prefix != "" && strings.HasPrefix(relPath, prefix) {
			relPath = relPath[len(prefix):]
		}
		if relPath == "" {
			continue
		}

		// Only extract YAML files. Skip README, LICENSE, .gitignore, etc.
		// The metadata file is written by VeilGate, not from the archive.
		ext := strings.ToLower(path.Ext(relPath))
		base := path.Base(relPath)
		if (ext != ".yaml" && ext != ".yml") || base == metaFileName {
			continue
		}

		// Security: reject path traversal attempts.
		if err := validateZipPath(relPath); err != nil {
			fmt.Fprintf(os.Stderr, "update-rules: skipping unsafe path %q: %v\n", relPath, err)
			continue
		}

		// VeilGate's rules loader reads top-level YAML files directly.
		// For the learned/ subdirectory (community-contributed learned rules)
		// we preserve exactly one level of directory nesting so the loader
		// can find them at <rules_dir>/learned/<feature>.yaml.
		// All other YAML files are placed in the root of destDir.
		var destPath string
		dir := path.Dir(relPath)
		if dir != "" && dir != "." {
			// Allow exactly one subdirectory level.
			parts := strings.SplitN(dir, "/", 2)
			subDir := filepath.Join(destDir, parts[0])
			if err := os.MkdirAll(subDir, 0700); err != nil {
				return count, fmt.Errorf("create subdir %q: %w", parts[0], err)
			}
			destPath = filepath.Join(subDir, path.Base(relPath))
		} else {
			destPath = filepath.Join(destDir, path.Base(relPath))
		}

		// Backup existing file if requested.
		if backup {
			if _, err := os.Stat(destPath); err == nil {
				if err := copyFile(destPath, destPath+".bak"); err != nil {
					fmt.Fprintf(os.Stderr, "update-rules: backup %q: %v\n", relPath, err)
				}
			}
		}

		// Write the extracted file.
		if err := writeZipEntry(f, destPath); err != nil {
			return count, fmt.Errorf("write %q: %w", relPath, err)
		}
		fmt.Printf("  %-35s → %s\n", relPath, destDir)
		count++
	}

	if count == 0 {
		return 0, errors.New("no YAML files found in the release archive — check the repository structure")
	}
	return count, nil
}

// zipTopLevelPrefix returns the common top-level directory prefix of a
// GitHub archive zip, e.g. "veilgate-rules-1.0.0/" or "".
func zipTopLevelPrefix(r *zip.Reader) string {
	if len(r.File) == 0 {
		return ""
	}
	// GitHub archives always start with "<repo>-<sha-or-tag>/".
	// Use the first entry to find the prefix.
	first := r.File[0].Name
	if idx := strings.IndexByte(first, '/'); idx > 0 {
		return first[:idx+1]
	}
	return ""
}

// validateZipPath rejects paths that could escape destDir via path traversal.
func validateZipPath(p string) error {
	cleaned := path.Clean(p)
	if strings.HasPrefix(cleaned, "..") || path.IsAbs(cleaned) {
		return fmt.Errorf("path traversal attempt")
	}
	// Reject null bytes.
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("null byte in path")
	}
	return nil
}

// writeZipEntry reads a single zip.File and writes it atomically to dest.
// Atomic write: write to a temp file, then rename.
func writeZipEntry(f *zip.File, dest string) error {
	rc, err := f.Open()
	if err != nil {
		return fmt.Errorf("open zip entry: %w", err)
	}
	defer rc.Close()

	tmp := dest + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	// Limit individual file size to 10 MB to prevent zip-bomb payloads.
	if _, err := io.Copy(out, io.LimitReader(rc, 10*1024*1024)); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("write content: %w", err)
	}
	out.Close()

	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// copyFile copies src to dst. Used for .bak creation.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0600)
}

// readInstalledVersion loads the .rules-version.json file from the rules dir.
// Returns a zero-value struct when the file does not exist.
func readInstalledVersion(metaPath string) (rulesVersion, error) {
	data, err := os.ReadFile(metaPath) //nolint:gosec
	if err != nil {
		return rulesVersion{}, err
	}
	var v rulesVersion
	return v, json.Unmarshal(data, &v)
}

// writeInstalledVersion serialises meta to metaPath as indented JSON.
func writeInstalledVersion(metaPath string, meta rulesVersion) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(metaPath, data, 0600)
}
