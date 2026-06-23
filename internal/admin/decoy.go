package admin

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Decoy endpoints turn the admin port into a deception surface. Any scanner or
// agent that finds the admin server and probes common attack paths
// (CMS panels, .git/.env leaks, cloud-metadata SSRF bait, actuator dumps) is
// served a plausible-but-fake response, delayed slightly, and logged as a
// security event — instead of a clean 404 that confirms "nothing here".
//
// The default path list is sourced from the community VeilGate rules repo:
//
//	https://github.com/C0oki3s/veilgate-rules
//	  detector/paths/{core,cloud-and-k8s}.yaml
//	  vulnerabilities/cms-probes/cms-and-infra.yaml
//	  injection_strategy/routes/{infra-panels,sensitive-data}.yaml
//
// Decoys are NOT registered as individual mux routes (Go's ServeMux can't add
// or remove routes at runtime). Instead the catch-all handler matches each
// request against an in-memory list that operators can edit live from the
// admin UI (Configuration → Decoys), persisted to decoys.yaml.

// decoyKind selects the deceptive response served for a probe.
type decoyKind string

const (
	decoyLogin     decoyKind = "login"     // fake admin/CMS login page (200)
	decoyForbidden decoyKind = "forbidden" // fake 403 for secret files
	decoyAPIError  decoyKind = "apierror"  // fake JSON 500 for actuator / cloud metadata
	decoyNotFound  decoyKind = "notfound"  // fake 404 for everything else
)

// decoyKinds is the ordered set of valid kinds (drives the UI dropdown).
var decoyKinds = []decoyKind{decoyLogin, decoyForbidden, decoyAPIError, decoyNotFound}

func validDecoyKind(k decoyKind) bool {
	for _, v := range decoyKinds {
		if v == k {
			return true
		}
	}
	return false
}

// decoyLabel is a human-readable description of a kind (for the UI).
func decoyLabel(k decoyKind) string {
	switch k {
	case decoyLogin:
		return "Fake login page (200)"
	case decoyForbidden:
		return "Forbidden — secret file (403)"
	case decoyAPIError:
		return "API/cloud error (500 JSON)"
	default:
		return "Not found (404)"
	}
}

// decoyRoute is one honeypot path.
type decoyRoute struct {
	Path   string    `yaml:"path"`             // request path; if prefix, must end with "/"
	Prefix bool      `yaml:"prefix,omitempty"` // true → match the whole subtree
	Kind   decoyKind `yaml:"kind"`
}

// defaultDecoys is the curated honeypot path set (authentic scanner targets).
// Used to seed decoys.yaml on first run.
var defaultDecoys = []decoyRoute{
	// ── CMS / infra admin panels → fake login page ──────────────────────────
	{"/wp-login.php", false, decoyLogin},
	{"/wp-admin/", true, decoyLogin},
	{"/wp-admin/install.php", false, decoyLogin},
	{"/wp-admin/setup-config.php", false, decoyLogin},
	{"/administrator/index.php", false, decoyLogin},
	{"/administrator/", true, decoyLogin},
	{"/user/login", false, decoyLogin},
	{"/admin/", true, decoyLogin},
	{"/admin/login", false, decoyLogin},
	{"/admin.php", false, decoyLogin},
	{"/login.php", false, decoyLogin},
	{"/phpmyadmin/", true, decoyLogin},
	{"/phpMyAdmin/", true, decoyLogin},
	{"/pma/", true, decoyLogin},
	{"/myadmin/", true, decoyLogin},
	{"/dbadmin/", true, decoyLogin},
	{"/mysql/", true, decoyLogin},
	{"/adminer.php", false, decoyLogin},
	{"/jenkins/", true, decoyLogin},
	{"/manager/html", false, decoyLogin},
	{"/host-manager/html", false, decoyLogin},
	{"/solr/", true, decoyLogin},
	{"/grafana/login", false, decoyLogin},
	{"/grafana/admin/", true, decoyLogin},
	{"/kibana/", true, decoyLogin},
	{"/portainer/", true, decoyLogin},

	// ── Secret files → fake 403 Forbidden ───────────────────────────────────
	{"/.env", false, decoyForbidden},
	{"/.env.local", false, decoyForbidden},
	{"/.env.production", false, decoyForbidden},
	{"/.env.development", false, decoyForbidden},
	{"/config/.env", false, decoyForbidden},
	{"/.git/config", false, decoyForbidden},
	{"/.git/HEAD", false, decoyForbidden},
	{"/.git/", true, decoyForbidden},
	{"/.svn/entries", false, decoyForbidden},
	{"/.aws/credentials", false, decoyForbidden},
	{"/.ssh/id_rsa", false, decoyForbidden},
	{"/config.php", false, decoyForbidden},
	{"/configuration.php", false, decoyForbidden},
	{"/wp-config.php", false, decoyForbidden},
	{"/backup.zip", false, decoyForbidden},
	{"/backup.sql", false, decoyForbidden},
	{"/database.sql", false, decoyForbidden},
	{"/.DS_Store", false, decoyForbidden},
	{"/.htpasswd", false, decoyForbidden},
	{"/server-status", false, decoyForbidden},
	{"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", false, decoyForbidden},

	// ── Cloud metadata / actuator (SSRF bait) → fake JSON error ─────────────
	{"/actuator/env", false, decoyAPIError},
	{"/actuator/health", false, decoyAPIError},
	{"/actuator/beans", false, decoyAPIError},
	{"/actuator/mappings", false, decoyAPIError},
	{"/actuator/", true, decoyAPIError},
	{"/latest/meta-data/", true, decoyAPIError},
	{"/latest/user-data", false, decoyAPIError},
	{"/computeMetadata/v1/", true, decoyAPIError},
	{"/metadata/instance", false, decoyAPIError},
	{"/debug/pprof/", true, decoyAPIError},

	// ── Misc shell / probe paths → fake 404 ─────────────────────────────────
	{"/xmlrpc.php", false, decoyNotFound},
	{"/wp-cron.php", false, decoyNotFound},
	{"/wp-content/", true, decoyNotFound},
	{"/cgi-bin/", true, decoyNotFound},
	{"/shell.php", false, decoyNotFound},
	{"/cmd.php", false, decoyNotFound},
	{"/.well-known/acme-challenge/", true, decoyNotFound},
}

// decoyStore holds the live, editable decoy list and persists it to disk.
type decoyStore struct {
	mu   sync.RWMutex
	list []decoyRoute
	path string // decoys.yaml location
}

// newDecoyStore loads decoys.yaml, seeding it with defaults if absent.
func newDecoyStore(path string) *decoyStore {
	s := &decoyStore{path: path}
	if err := s.load(); err != nil {
		s.mu.Lock()
		s.list = append([]decoyRoute(nil), defaultDecoys...)
		s.mu.Unlock()
		_ = s.save() // best-effort seed
	}
	return s
}

type decoyFile struct {
	Decoys []decoyRoute `yaml:"decoys"`
}

func (s *decoyStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var f decoyFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return err
	}
	s.mu.Lock()
	s.list = f.Decoys
	s.mu.Unlock()
	return nil
}

func (s *decoyStore) save() error {
	s.mu.RLock()
	f := decoyFile{Decoys: append([]decoyRoute(nil), s.list...)}
	s.mu.RUnlock()
	b, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	header := "# VeilGate admin decoy endpoints — edited via Configuration → Decoys.\n" +
		"# kind: login | forbidden | apierror | notfound\n"
	return os.WriteFile(s.path, append([]byte(header), b...), 0o600)
}

// all returns a sorted copy of the current decoys (for display).
func (s *decoyStore) all() []decoyRoute {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := append([]decoyRoute(nil), s.list...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// match returns the decoy for a request path (exact first, then longest prefix).
func (s *decoyStore) match(path string) (decoyRoute, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best decoyRoute
	found := false
	for _, d := range s.list {
		if !d.Prefix {
			if d.Path == path {
				return d, true // exact wins immediately
			}
			continue
		}
		if strings.HasPrefix(path, d.Path) {
			if !found || len(d.Path) > len(best.Path) {
				best, found = d, true
			}
		}
	}
	return best, found
}

// add inserts a decoy (de-duplicated by path) and persists.
func (s *decoyStore) add(d decoyRoute) error {
	s.mu.Lock()
	for i, ex := range s.list {
		if ex.Path == d.Path {
			s.list[i] = d // update in place
			s.mu.Unlock()
			return s.save()
		}
	}
	s.list = append(s.list, d)
	s.mu.Unlock()
	return s.save()
}

// remove deletes a decoy by exact path and persists.
func (s *decoyStore) remove(path string) error {
	s.mu.Lock()
	out := s.list[:0]
	for _, d := range s.list {
		if d.Path != path {
			out = append(out, d)
		}
	}
	s.list = out
	s.mu.Unlock()
	return s.save()
}

// resetDefaults restores the curated default set and persists.
func (s *decoyStore) resetDefaults() error {
	s.mu.Lock()
	s.list = append([]decoyRoute(nil), defaultDecoys...)
	s.mu.Unlock()
	return s.save()
}

// ── Serving ─────────────────────────────────────────────────────────────────

// serveDecoyMatch logs the probe, stalls briefly, and serves the decoy.
func (s *Server) serveDecoyMatch(w http.ResponseWriter, r *http.Request, d decoyRoute) {
	s.logAudit(r, "decoy_probe",
		fmt.Sprintf("%s %s ua=%q", r.Method, r.URL.Path, r.UserAgent()), false)

	// Tarpit-lite: slow the scanner without holding the connection long.
	time.Sleep(time.Duration(200+rand.Intn(700)) * time.Millisecond)

	// Pose as a generic web server — never reveal VeilGate.
	w.Header().Set("Server", "nginx")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	switch d.Kind {
	case decoyLogin:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(decoyLoginHTML))
	case decoyForbidden:
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(decoyForbiddenHTML))
	case decoyAPIError:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"timestamp":"` +
			time.Now().UTC().Format(time.RFC3339) +
			`","status":500,"error":"Internal Server Error","path":"` +
			r.URL.Path + `"}`))
	default: // decoyNotFound
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(decoyNotFoundHTML))
	}
}

// serveGeneric404 answers any unknown path with a plausible nginx 404 (no delay,
// no audit) so the admin port never confirms which paths are "real".
func (s *Server) serveGeneric404(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(decoyNotFoundHTML))
}

// handleCatchAll is the mux fallback ("/"). The bare root redirects to the
// dashboard; every other unmatched path is matched against the live decoy list
// (served as deception) or falls through to a generic 404.
func (s *Server) handleCatchAll(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		s.protect(s.redirect("/dashboard"))(w, r)
		return
	}
	if d, ok := s.decoys.match(r.URL.Path); ok {
		s.serveDecoyMatch(w, r, d)
		return
	}
	s.serveGeneric404(w, r)
}

// ── Admin page: Configuration → Decoys ──────────────────────────────────────

// DecoysData backs the decoy-management page.
type DecoysData struct {
	Decoys []decoyRoute
	Path   string
}

// handleDecoys lists, adds, deletes, and resets decoy endpoints.
func (s *Server) handleDecoys(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		switch r.FormValue("_action") {
		case "add":
			path := strings.TrimSpace(r.FormValue("path"))
			kind := decoyKind(r.FormValue("kind"))
			prefix := r.FormValue("prefix") != ""
			if path == "" || !strings.HasPrefix(path, "/") {
				s.renderDecoys(w, r, &Flash{Kind: "error", Message: "Path must start with /"})
				return
			}
			if !validDecoyKind(kind) {
				kind = decoyNotFound
			}
			if prefix && !strings.HasSuffix(path, "/") {
				path += "/"
			}
			if err := s.decoys.add(decoyRoute{Path: path, Prefix: prefix, Kind: kind}); err != nil {
				s.renderDecoys(w, r, &Flash{Kind: "error", Message: "Save failed: " + err.Error()})
				return
			}
			s.logAudit(r, "decoy.add", path, true)
			s.renderDecoys(w, r, &Flash{Kind: "success", Message: "Decoy added — live immediately, no restart needed."})
			return
		case "delete":
			path := r.FormValue("path")
			_ = s.decoys.remove(path)
			s.logAudit(r, "decoy.delete", path, true)
			s.renderDecoys(w, r, &Flash{Kind: "success", Message: "Decoy removed."})
			return
		case "reset":
			_ = s.decoys.resetDefaults()
			s.logAudit(r, "decoy.reset", "restored default decoy set", true)
			s.renderDecoys(w, r, &Flash{Kind: "success", Message: "Restored the default decoy set."})
			return
		}
	}
	s.renderDecoys(w, r, nil)
}

func (s *Server) renderDecoys(w http.ResponseWriter, r *http.Request, flash *Flash) {
	s.render(w, r, "decoys", &PageData{
		Title:      "Decoy Endpoints",
		ActivePage: "decoys",
		Flash:      flash,
		Data:       &DecoysData{Decoys: s.decoys.all(), Path: s.decoys.path},
	})
}

// ── Deceptive response bodies (generic, non-attributable) ───────────────────

const decoyLoginHTML = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Sign In</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:Arial,Helvetica,sans-serif;background:#f0f0f1;margin:0}
.box{max-width:320px;margin:8% auto;padding:26px 24px;background:#fff;border:1px solid #c3c4c7;border-radius:4px}
h1{font-size:18px;color:#1d2327;margin:0 0 18px}label{display:block;font-size:13px;color:#3c434a;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:8px;border:1px solid #8c8f94;border-radius:3px}
button{margin-top:18px;width:100%;padding:9px;background:#2271b1;color:#fff;border:0;border-radius:3px;cursor:pointer}</style>
</head><body><form class="box" method="post" action="">
<h1>Log In</h1>
<label>Username</label><input type="text" name="username" autocomplete="username">
<label>Password</label><input type="password" name="password" autocomplete="current-password">
<button type="submit">Log In</button></form></body></html>`

const decoyForbiddenHTML = `<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>`

const decoyNotFoundHTML = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`
