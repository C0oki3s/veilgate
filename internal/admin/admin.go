// Package admin provides the VeilGate configuration web UI.
package admin

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/persist"
)

// AdminConfig holds everything New() needs.
type AdminConfig struct {
	ConfigPath string
	Version    string
	// AdminUser / AdminPass seed the first user in the DB on startup.
	// If the DB already contains this user the password is updated.
	// Leave both empty to disable authentication entirely.
	AdminUser string
	AdminPass string
	// DBPath is the SQLite database for users + audit log.
	// Default: <config-dir>/admin.db (same directory as veilgate.yaml).
	DBPath string
	// AuditPath is an optional JSONL backup of audit events alongside the DB.
	// Default: <config-dir>/audit.log
	AuditPath string
}

// Server is the admin HTTP server.
type Server struct {
	cfg            *config.Config
	configPath     string
	version        string
	startedAt      time.Time
	configPending  bool // true after config saved — VeilGate proxy needs restart
	defaultCreds   bool // true when auto-seeded default admin/veilgate was used
	db             *AdminDB
	templates      map[string]*template.Template
	mux            *http.ServeMux
	auth           *AuthState     // nil = no auth
	audit          *AuditLogger   // nil = no audit
	decoys         *decoyStore    // editable honeypot endpoints
	store          *persist.Store // proxy event store (correlation DB), nil if persist disabled
}

// New creates and initializes a Server.
func New(adminCfg AdminConfig) (*Server, error) {
	cfg, _ := config.Load(adminCfg.ConfigPath)
	if cfg == nil {
		cfg = &config.Config{}
	}

	s := &Server{
		configPath: adminCfg.ConfigPath,
		cfg:        cfg,
		version:    adminCfg.Version,
		startedAt:  time.Now(),
		templates:  make(map[string]*template.Template),
		mux:        http.NewServeMux(),
	}

	// Open SQLite DB — default alongside the config so all files live together.
	dbPath := adminCfg.DBPath
	if dbPath == "" {
		if adminCfg.ConfigPath != "" {
			dir := filepath.Dir(adminCfg.ConfigPath)
			if dir == "." {
				dir, _ = os.Getwd()
			}
			dbPath = filepath.Join(dir, "admin.db")
		} else {
			home, _ := os.UserHomeDir()
			dbPath = filepath.Join(home, ".veilgate", "admin.db")
		}
	}

	// Editable decoy endpoints live alongside the admin DB.
	s.decoys = newDecoyStore(filepath.Join(filepath.Dir(dbPath), "decoys.yaml"))
	if db, err := OpenDB(dbPath); err == nil {
		s.db = db
		if adminCfg.AdminUser != "" && adminCfg.AdminPass != "" {
			// Explicit flags: seed / update that user, force reset on first login.
			if err := db.UpsertUser(adminCfg.AdminUser, adminCfg.AdminPass, true); err != nil {
				log.Printf("admin: upsert user: %v", err)
			}
		} else if !db.HasUsers() {
			// Empty DB: auto-seed default credentials and require a reset.
			if err := db.UpsertUser("admin", "veilgate", true); err == nil {
				s.defaultCreds = true
				log.Printf("admin: ⚠  seeded default credentials admin/veilgate — user will be required to change password on first login")
			}
		}
		if db.HasUsers() {
			s.auth = NewAuthDB(db)
		}
	} else {
		log.Printf("admin: db unavailable (%v) — falling back to flag-based auth", err)
		if adminCfg.AdminUser != "" && adminCfg.AdminPass != "" {
			s.auth = NewAuth(adminCfg.AdminUser, adminCfg.AdminPass)
		}
	}

	// Audit logger: DB (primary) + JSONL (backup)
	auditPath := adminCfg.AuditPath
	if auditPath == "" {
		auditPath = filepath.Join(filepath.Dir(dbPath), "audit.log")
	}
	if al, err := NewAuditLogger(auditPath, s.db); err == nil {
		s.audit = al
	} else {
		log.Printf("audit log unavailable: %v", err)
	}

	// Open the proxy's event store (correlation DB) read-side when persist is
	// configured. SQLite WAL lets the admin read while the proxy writes. This
	// powers dashboard analytics, request logs, and the recommender.
	s.openEventStore()

	if err := s.parseTemplates(); err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	s.registerRoutes()
	s.registerAPI()
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// parseTemplates loads all page templates. Each page gets shell + all partials + the page file.
func (s *Server) parseTemplates() error {
	funcMap := template.FuncMap{
		"lower":     strings.ToLower,
		"upper":     strings.ToUpper,
		"hasPrefix": strings.HasPrefix,
		"join":      strings.Join,
		"formatTime": func(t time.Time) string {
			return t.Format("15:04:05")
		},
		"formatDateTime": func(s string) string {
			t, err := time.Parse(time.RFC3339, s)
			if err != nil {
				return s
			}
			return t.Local().Format("Jan 2, 15:04:05")
		},
		"signalGroups": SignalGroups,
		"decoyLabel":   func(k decoyKind) string { return decoyLabel(k) },
		"decoyKinds":   func() []decoyKind { return decoyKinds },
		"pct":          func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"add":          func(a, b int) int { return a + b },
		"sub":          func(a, b int) int { return a - b },
		"negate":       func(a int) int { return -a },
		"mul":          func(a, b int) int { return a * b },
		"safeHTML":     func(s string) template.HTML { return template.HTML(s) }, //nolint:gosec
		"derefBool":    func(b *bool) bool { return b != nil && *b },
		"derefInt": func(n *int) int {
			if n == nil {
				return 0
			}
			return *n
		},
		"scoreTier": func(score int) string {
			switch {
			case score >= 80:
				return "critical"
			case score >= 60:
				return "high"
			case score >= 30:
				return "medium"
			default:
				return "low"
			}
		},
		// joinLines joins a string slice with newlines (for textarea pre-fill).
		"joinLines": func(ss []string) string { return strings.Join(ss, "\n") },
		// octal formats an int as 0o600 style (for file_mode display).
		"octal": func(n int) string {
			if n == 0 {
				return "0o600"
			}
			return fmt.Sprintf("0o%o", n)
		},
		// kvmap2lines formats map[string]string as sorted "key: value\n" lines.
		"kvmap2lines": func(m map[string]string) string {
			if len(m) == 0 {
				return ""
			}
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var lines []string
			for _, k := range keys {
				lines = append(lines, k+": "+m[k])
			}
			return strings.Join(lines, "\n")
		},
	}

	pages := []string{
		"dashboard",
		"analytics",
		"change_password",
		"forgot_password",
		"reset_password",
		"settings",
		"decoys",
		"recommender",
		"rules",
		"rule_edit",
		"signals",
		"openapi",
		"login",
		"audit",
		"logs",
	}

	for _, page := range pages {
		t := template.New("shell").Funcs(funcMap)
		t, err := t.ParseFS(Assets,
			"templates/shell.html",
			"templates/partials/sidebar.html",
			"templates/partials/veilo.html",
			"templates/pages/"+page+".html",
		)
		if err != nil {
			return fmt.Errorf("parse page %q: %w", page, err)
		}
		s.templates[page] = t
	}
	return nil
}

// registerRoutes wires all HTTP routes.
func (s *Server) registerRoutes() {
	staticFS, _ := fs.Sub(Assets, "static")
	s.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.HandleFunc("/forgot-password", s.withMiddleware(s.handleForgotPassword))
	s.mux.HandleFunc("/reset-password", s.withMiddleware(s.handleResetPassword))
	s.mux.HandleFunc("/account/password", s.protect(s.withMiddleware(s.handleChangePassword)))

	s.mux.HandleFunc("/", s.handleCatchAll)
	s.mux.HandleFunc("/dashboard", s.protect(s.withMiddleware(s.handleDashboard)))
	s.mux.HandleFunc("/analytics", s.protect(s.withMiddleware(s.handleAnalytics)))
	s.mux.HandleFunc("/settings", s.protect(s.withMiddleware(s.handleSettings)))
	s.mux.HandleFunc("/decoys", s.protect(s.withMiddleware(s.handleDecoys)))
	s.mux.HandleFunc("/recommender", s.protect(s.withMiddleware(s.handleRecommender)))
	s.mux.HandleFunc("/rules", s.protect(s.withMiddleware(s.handleRules)))
	s.mux.HandleFunc("/rules/", s.protect(s.withMiddleware(s.handleRuleEdit)))
	s.mux.HandleFunc("/signals", s.protect(s.withMiddleware(s.handleSignals)))
	s.mux.HandleFunc("/openapi", s.protect(s.withMiddleware(s.handleOpenAPI)))
	s.mux.HandleFunc("/audit", s.protect(s.withMiddleware(s.handleAudit)))
	s.mux.HandleFunc("/logs", s.protect(s.withMiddleware(s.handleLogs)))
}

// protect checks auth before calling next. If auth is disabled, calls next directly.
// After successful auth it checks must_change: if set, only /account/password is
// reachable until the user picks a new password.
func (s *Server) protect(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.auth == nil {
			ctx := context.WithValue(r.Context(), ctxKeyUser{}, "admin")
			next(w, r.WithContext(ctx))
			return
		}
		if !s.auth.Check(r) {
			http.Redirect(w, r, "/login?next="+r.URL.Path, http.StatusFound)
			return
		}
		username := s.auth.Username(r)
		ctx := context.WithValue(r.Context(), ctxKeyUser{}, username)
		// Force-reset gate: redirect to change-password until must_change is cleared.
		if s.db != nil && s.db.MustChange(username) && r.URL.Path != "/account/password" {
			http.Redirect(w, r, "/account/password", http.StatusFound)
			return
		}
		next(w, r.WithContext(ctx))
	}
}

// withMiddleware adds CSP + security headers + request log.
func (s *Server) withMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"font-src 'self'; "+
				"img-src 'self' data:; "+
				"object-src 'none'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")

		start := time.Now()
		next(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	}
}

func (s *Server) redirect(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, to, http.StatusFound)
	}
}

// ── PageData ──────────────────────────────────────────────────────────────

// PageData is passed to every template.
type PageData struct {
	Title         string
	ActivePage    string
	Theme         string
	Version       string
	Config        *config.Config
	ConfigPath    string
	RulesDir      string
	Flash         *Flash
	AuthEnabled   bool
	ConfigPending bool // proxy needs restart to apply config changes
	DefaultCreds  bool // auto-seeded admin/veilgate — show change-password nudge
	Data          any
}

type Flash struct {
	Kind    string // "success", "error", "warn", "info"
	Message string
}

func theme(r *http.Request) string {
	c, err := r.Cookie("theme")
	if err != nil || (c.Value != "dark" && c.Value != "light") {
		return "dark"
	}
	return c.Value
}

// render executes the named page template.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data *PageData) {
	t, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	data.Theme = theme(r)
	data.Version = s.version
	data.Config = s.cfg
	data.ConfigPath = s.configPath
	data.AuthEnabled = s.auth != nil
	data.ConfigPending = s.configPending
	data.DefaultCreds = s.defaultCreds
	if s.cfg != nil {
		data.RulesDir = s.cfg.RulesDir
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "shell", data); err != nil {
		log.Printf("template error (page=%s): %v", page, err)
	}
}

// logAudit writes to audit log if enabled.
func (s *Server) logAudit(r *http.Request, action, detail string, ok bool) {
	if s.audit != nil {
		s.audit.Log(r, action, detail, ok)
	}
}

// ── Config helpers ────────────────────────────────────────────────────────

func (s *Server) reloadConfig() error {
	cfg, err := config.Load(s.configPath)
	if err != nil {
		return err
	}
	s.cfg = cfg
	return nil
}

func (s *Server) writeConfigFile(content string) error {
	return os.WriteFile(s.configPath, []byte(content), 0o600)
}

func (s *Server) rulesDir() string {
	if s.cfg != nil && s.cfg.RulesDir != "" {
		return s.cfg.RulesDir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".veilgate", "rules")
}

func (s *Server) readRuleFile(name string) (string, error) {
	name = filepath.Clean(name)
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("invalid path")
	}
	path := filepath.Join(s.rulesDir(), name)
	b, err := os.ReadFile(path)
	return string(b), err
}

func (s *Server) writeRuleFile(name, content string) error {
	name = filepath.Clean(name)
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid path")
	}
	path := filepath.Join(s.rulesDir(), name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func (s *Server) listRuleFiles() ([]RuleFileInfo, error) {
	root := s.rulesDir()
	var files []RuleFileInfo
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		info, _ := d.Info()
		size, mod := int64(0), time.Time{}
		if info != nil {
			size, mod = info.Size(), info.ModTime()
		}
		files = append(files, RuleFileInfo{Path: rel, Size: size, ModTime: mod})
		return nil
	})
	return files, err
}

type RuleFileInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
}

