package admin

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ── Auth ──────────────────────────────────────────────────────────────────

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; script-src 'self' 'unsafe-inline'; "+
			"style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; object-src 'none'")

	// If auth is disabled, skip straight to dashboard.
	if s.auth == nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	// Already logged in?
	if s.auth.Check(r) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.render(w, r, "login", &PageData{
			Title:      "Sign in — VeilGate Admin",
			ActivePage: "login",
		})

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		user := r.FormValue("username")
		pass := r.FormValue("password")
		next := r.FormValue("next")
		if next == "" || !strings.HasPrefix(next, "/") {
			next = "/dashboard"
		}

		if !s.auth.Validate(user, pass) {
			s.logAudit(r, "login", "invalid credentials for user: "+user, false)
			s.render(w, r, "login", &PageData{
				Title:      "Sign in — VeilGate Admin",
				ActivePage: "login",
				Flash:      &Flash{Kind: "error", Message: "Invalid username or password."},
			})
			return
		}

		id, err := s.auth.NewSession(user)
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		s.auth.SetCookie(w, id)
		s.logAudit(r, "login", "user logged in: "+user, true)
		// If must_change is set the protect middleware will redirect automatically.
		http.Redirect(w, r, next, http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil {
		s.logAudit(r, "logout", "session ended", true)
		s.auth.Destroy(r)
		s.auth.ClearCookie(w)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ── Account: change password ──────────────────────────────────────────────

type changePasswordData struct {
	MustChange bool   // true = forced reset, show banner
	Username   string
	Flash      *Flash
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	username := ctxUser(r)
	mustChange := s.db != nil && s.db.MustChange(username)

	switch r.Method {
	case http.MethodGet:
		s.render(w, r, "change_password", &PageData{
			Title:      "Change Password",
			ActivePage: "account",
			Data:       &changePasswordData{MustChange: mustChange, Username: username},
		})

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		current := r.FormValue("current_password")
		newPass := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")

		renderErr := func(msg string) {
			s.render(w, r, "change_password", &PageData{
				Title:      "Change Password",
				ActivePage: "account",
				Data: &changePasswordData{
					MustChange: mustChange, Username: username,
					Flash: &Flash{Kind: "error", Message: msg},
				},
			})
		}

		if newPass != confirm {
			renderErr("New passwords do not match.")
			return
		}
		if s.db == nil {
			renderErr("No database available.")
			return
		}
		if err := s.db.ChangePassword(username, current, newPass); err != nil {
			renderErr(err.Error())
			return
		}
		s.logAudit(r, "account.password_change", "user changed password: "+username, true)
		// Redirect to dashboard; must_change is now cleared so protect will allow it.
		http.Redirect(w, r, "/dashboard?flash=password_changed", http.StatusSeeOther)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ── Account: forgot password ──────────────────────────────────────────────

func (s *Server) handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.render(w, r, "forgot_password", &PageData{
			Title:      "Forgot Password",
			ActivePage: "login",
		})

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))

		// Always show success to avoid username enumeration.
		showSuccess := func() {
			s.render(w, r, "forgot_password", &PageData{
				Title:      "Forgot Password",
				ActivePage: "login",
				Flash: &Flash{
					Kind:    "success",
					Message: "If that account exists, a reset link has been printed to the server log.",
				},
			})
		}

		if s.db == nil || username == "" {
			showSuccess()
			return
		}

		token, err := s.db.CreateResetToken(username)
		if err != nil {
			// Log internally; user still sees success.
			log.Printf("admin: reset token error for %q: %v", username, err)
			showSuccess()
			return
		}

		// No SMTP: print the link to the server log so the operator can relay it.
		log.Printf("admin: 🔑 PASSWORD RESET for %q — link (expires 1h): /reset-password?token=%s", username, token)
		s.logAudit(r, "account.forgot_password", "reset token issued for: "+username, true)
		showSuccess()

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ── Account: reset password (token link) ─────────────────────────────────

type resetPasswordData struct {
	Token    string
	Username string
	Err      string
	Done     bool
}

func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.FormValue("token")
	}

	renderPage := func(data *resetPasswordData) {
		s.render(w, r, "reset_password", &PageData{
			Title:      "Reset Password",
			ActivePage: "login",
			Data:       data,
		})
	}

	if s.db == nil {
		renderPage(&resetPasswordData{Err: "No database available."})
		return
	}

	switch r.Method {
	case http.MethodGet:
		username, err := s.db.UsernameByResetToken(token)
		if err != nil {
			renderPage(&resetPasswordData{Token: token, Err: err.Error()})
			return
		}
		renderPage(&resetPasswordData{Token: token, Username: username})

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		token = r.FormValue("token")
		newPass := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")

		if newPass != confirm {
			username, _ := s.db.UsernameByResetToken(token)
			renderPage(&resetPasswordData{Token: token, Username: username, Err: "Passwords do not match."})
			return
		}
		username, lookupErr := s.db.UsernameByResetToken(token)
		if lookupErr != nil {
			renderPage(&resetPasswordData{Token: token, Err: lookupErr.Error()})
			return
		}
		if err := s.db.ConsumeResetToken(token, newPass); err != nil {
			renderPage(&resetPasswordData{Token: token, Username: username, Err: err.Error()})
			return
		}
		s.logAudit(r, "account.password_reset", "password reset via token for: "+username, true)
		renderPage(&resetPasswordData{Done: true})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ── Dashboard ─────────────────────────────────────────────────────────────

type DashboardData struct {
	Mode            string
	TarpitThresh    int
	ChallengeThresh int
	RulesDir        string
	RulesDirOK      bool
	ConfigOK        bool
	StatCards       []StatCard
	AuditStats      AuditStats
	Analytics       Analytics
}

type StatCard struct {
	Label string
	Value string
	Sub   string
	Kind  string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/dashboard" {
		http.NotFound(w, r)
		return
	}

	_, rdErr := os.Stat(s.rulesDir())
	var auditStats AuditStats
	if s.audit != nil {
		auditStats = s.audit.Stats()
	}

	stats := []StatCard{
		{Label: "Mode", Value: modeLabel(s.cfg.Mode), Kind: modeKind(s.cfg.Mode)},
		{Label: "Challenge Threshold", Value: fmt.Sprintf("%d pts", s.cfg.Detector.ScoreChallengeThreshold), Kind: "default", Sub: "score ≥ this → challenge"},
		{Label: "Tarpit Threshold", Value: fmt.Sprintf("%d pts", s.cfg.Detector.ScoreTarpitThreshold), Kind: "warn", Sub: "score ≥ this → tarpit"},
		{Label: "Window", Value: fmt.Sprintf("%ds", s.cfg.Detector.WindowSeconds), Kind: "default", Sub: "scoring window"},
	}

	s.render(w, r, "dashboard", &PageData{
		Title:      "Dashboard",
		ActivePage: "dashboard",
		Data: &DashboardData{
			Mode:            s.cfg.Mode,
			TarpitThresh:    s.cfg.Detector.ScoreTarpitThreshold,
			ChallengeThresh: s.cfg.Detector.ScoreChallengeThreshold,
			RulesDir:        s.rulesDir(),
			RulesDirOK:      rdErr == nil,
			ConfigOK:        s.cfg != nil,
			StatCards:       stats,
			AuditStats:      auditStats,
			Analytics:       s.loadAnalytics(),
		},
	})
}

// ── Settings ──────────────────────────────────────────────────────────────

type SettingsData struct {
	Raw string
	Tab string // active tab: proxy|detector|challenge|tarpit|tls|persistence|observability|verifiers|raw
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		raw, _ := os.ReadFile(s.configPath)
		tab := r.URL.Query().Get("tab")
		if tab == "" {
			tab = "proxy"
		}
		s.render(w, r, "settings", &PageData{
			Title:      "Settings",
			ActivePage: "settings",
			Data:       &SettingsData{Raw: string(raw), Tab: tab},
		})

	case http.MethodPost:
		s.settingsPOST(w, r)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) settingsPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.settingsFlash(w, r, &Flash{Kind: "error", Message: "Invalid form."}, "", "proxy")
		return
	}

	tab := r.FormValue("_tab")
	if tab == "" {
		tab = "proxy"
	}

	// ── Raw YAML mode ─────────────────────────────────────────────────────
	if r.FormValue("_mode") == "raw" {
		content := r.FormValue("content")
		if err := s.writeConfigFile(content); err != nil {
			s.logAudit(r, "settings.save", "raw save failed: "+err.Error(), false)
			s.settingsFlash(w, r, &Flash{Kind: "error", Message: "Save failed: " + err.Error()}, content, "raw")
			return
		}
		_ = s.reloadConfig()
		s.configPending = true
		s.logAudit(r, "settings.save", "raw YAML saved", true)
		raw, _ := os.ReadFile(s.configPath)
		s.settingsFlash(w, r, &Flash{Kind: "success", Message: "Config saved — restart VeilGate proxy to apply changes."}, string(raw), "raw")
		return
	}

	// ── Form mode — surgical YAML patch ───────────────────────────────────
	rawBytes, err := os.ReadFile(s.configPath)
	if err != nil {
		s.settingsFlash(w, r, &Flash{Kind: "error", Message: "Cannot read config: " + err.Error()}, "", tab)
		return
	}

	str := func(key string) string { return strings.TrimSpace(r.FormValue(key)) }
	chk := func(key string) bool { return r.FormValue(key) == "on" }

	parseInt := func(key string) (int, bool) {
		v := strings.TrimSpace(r.FormValue(key))
		if v == "" {
			return 0, false
		}
		n, e := strconv.Atoi(v)
		return n, e == nil
	}
	parseInt64 := func(key string) (int64, bool) {
		v := strings.TrimSpace(r.FormValue(key))
		if v == "" {
			return 0, false
		}
		n, e := strconv.ParseInt(v, 10, 64)
		return n, e == nil
	}
	parseFloat := func(key string) (float64, bool) {
		v := strings.TrimSpace(r.FormValue(key))
		if v == "" {
			return 0, false
		}
		f, e := strconv.ParseFloat(v, 64)
		return f, e == nil
	}
	parseOctal := func(key string) (int, bool) {
		v := strings.TrimSpace(r.FormValue(key))
		v = strings.TrimPrefix(strings.TrimPrefix(v, "0o"), "0")
		if v == "" {
			return 0o600, true
		}
		n, e := strconv.ParseInt(v, 8, 64)
		return int(n), e == nil
	}

	var patches []YAMLPatch
	add := func(p YAMLPatch) { patches = append(patches, p) }

	// Each section is gated on its matching tab so that saving one tab never
	// clobbers fields from other tabs (e.g. saving "detector" must NOT set
	// listen/upstream/mode/rules_dir to "" or flip TLS/persist booleans).
	switch tab {
	case "proxy":
		add(PatchString([]string{"listen"}, str("listen")))
		add(PatchString([]string{"upstream"}, str("upstream")))
		add(PatchString([]string{"mode"}, str("mode")))
		add(PatchString([]string{"rules_dir"}, str("rules_dir")))

	case "detector":
		if n, ok := parseInt("score_challenge_threshold"); ok {
			add(PatchInt([]string{"detector", "score_challenge_threshold"}, n))
		}
		if n, ok := parseInt("score_tarpit_threshold"); ok {
			add(PatchInt([]string{"detector", "score_tarpit_threshold"}, n))
		}
		if n, ok := parseInt("window_seconds"); ok {
			add(PatchInt([]string{"detector", "window_seconds"}, n))
		}
		add(PatchStrings([]string{"detector", "probe_paths"}, parseLines(r.FormValue("probe_paths"))))
		add(PatchStrings([]string{"detector", "trusted_ips"}, parseLines(r.FormValue("trusted_ips"))))
		add(PatchStrings([]string{"detector", "trusted_proxies"}, parseLines(r.FormValue("trusted_proxies"))))
		add(PatchString([]string{"detector", "cdn_mode"}, str("cdn_mode")))

	case "challenge":
		add(PatchString([]string{"challenge", "secret"}, str("challenge_secret")))
		if n, ok := parseInt("challenge_difficulty"); ok {
			add(PatchInt([]string{"challenge", "difficulty"}, n))
		}
		if n, ok := parseInt("challenge_ttl_minutes"); ok {
			add(PatchInt([]string{"challenge", "ttl_minutes"}, n))
		}
		if n, ok := parseInt("challenge_max_ttl_minutes"); ok {
			add(PatchInt([]string{"challenge", "max_ttl_minutes"}, n))
		}

	case "tarpit":
		if n, ok := parseInt("min_latency_ms"); ok {
			add(PatchInt([]string{"tarpit", "min_latency_ms"}, n))
		}
		if n, ok := parseInt("max_latency_ms"); ok {
			add(PatchInt([]string{"tarpit", "max_latency_ms"}, n))
		}
		if n, ok := parseInt("max_body_bytes"); ok {
			add(PatchInt([]string{"tarpit", "max_body_bytes"}, n))
		}
		if n, ok := parseInt("tarpit_cache_ttl"); ok {
			add(PatchInt([]string{"tarpit", "response_cache_ttl_minutes"}, n))
		}
		if n, ok := parseInt("tarpit_cache_size"); ok {
			add(PatchInt([]string{"tarpit", "response_cache_max_size"}, n))
		}

	case "tls":
		add(PatchBool([]string{"tls", "enabled"}, chk("tls_enabled")))
		add(PatchString([]string{"tls", "cert_file"}, str("tls_cert_file")))
		add(PatchString([]string{"tls", "key_file"}, str("tls_key_file")))

	case "persistence":
		add(PatchBool([]string{"persist", "enabled"}, chk("persist_enabled")))
		add(PatchString([]string{"persist", "path"}, str("persist_path")))
		if n, ok := parseInt("persist_retention_days"); ok {
			add(PatchInt([]string{"persist", "retention_days"}, n))
		}
		if n, ok := parseInt("persist_flush_every_ms"); ok {
			add(PatchInt([]string{"persist", "flush_every_ms"}, n))
		}
		if n, ok := parseInt("persist_queue_size"); ok {
			add(PatchInt([]string{"persist", "queue_size"}, n))
		}
		add(PatchString([]string{"persist", "dump_path"}, str("persist_dump_path")))
		if n, ok := parseInt("persist_cache_size_kb"); ok {
			add(PatchInt([]string{"persist", "cache_size_kb"}, n))
		}

	case "observability":
		add(PatchBool([]string{"capture", "enabled"}, chk("capture_enabled")))
		add(PatchString([]string{"capture", "path"}, str("capture_path")))
		if n, ok := parseInt("capture_max_mb"); ok {
			add(PatchInt([]string{"capture", "max_mb"}, n))
		}
		if n, ok := parseInt("capture_retention_hours"); ok {
			add(PatchInt([]string{"capture", "retention_hours"}, n))
		}
		add(PatchString([]string{"capture", "janitor_every"}, str("capture_janitor_every")))
		if n, ok := parseOctal("capture_file_mode"); ok {
			add(PatchOctal([]string{"capture", "file_mode"}, n))
		}
		add(PatchBool([]string{"metrics", "disabled"}, chk("metrics_disabled")))
		add(PatchString([]string{"metrics", "listen"}, str("metrics_listen")))
		add(PatchString([]string{"metrics", "api_key"}, str("metrics_api_key")))
		add(PatchString([]string{"telemetry", "otlp", "endpoint"}, str("otlp_endpoint")))
		add(PatchBool([]string{"telemetry", "otlp", "insecure"}, chk("otlp_insecure")))
		if kv := parseKVLines(r.FormValue("otlp_headers")); len(kv) > 0 {
			add(PatchKVMap([]string{"telemetry", "otlp", "headers"}, kv))
		}
		add(PatchBool([]string{"telemetry", "traces", "disabled"}, chk("traces_disabled")))
		if f, ok := parseFloat("traces_sample_rate"); ok {
			add(PatchFloat([]string{"telemetry", "traces", "sample_rate"}, f))
		}
		add(PatchBool([]string{"telemetry", "logs", "enabled"}, chk("logs_enabled")))
		add(PatchBool([]string{"telemetry", "metrics_push", "enabled"}, chk("metrics_push_enabled")))
		add(PatchString([]string{"telemetry", "metrics_push", "interval"}, str("metrics_push_interval")))

	case "verifiers":
		add(PatchBool([]string{"verifiers", "hmac", "enabled"}, chk("hmac_enabled")))
		add(PatchString([]string{"verifiers", "hmac", "header_signature"}, str("hmac_header_signature")))
		add(PatchString([]string{"verifiers", "hmac", "header_client"}, str("hmac_header_client")))
		if n, ok := parseInt("hmac_clock_skew_sec"); ok {
			add(PatchInt([]string{"verifiers", "hmac", "clock_skew_sec"}, n))
		}
		if n, ok := parseInt64("hmac_max_body_bytes"); ok {
			add(PatchInt64([]string{"verifiers", "hmac", "max_body_bytes"}, n))
		}
		add(PatchString([]string{"verifiers", "hmac", "clients_dir"}, str("hmac_clients_dir")))
		add(PatchBool([]string{"verifiers", "bearer", "enabled"}, chk("bearer_enabled")))
		add(PatchString([]string{"verifiers", "bearer", "header"}, str("bearer_header")))
		add(PatchString([]string{"verifiers", "bearer", "scheme"}, str("bearer_scheme")))
		add(PatchString([]string{"verifiers", "bearer", "tokens_dir"}, str("bearer_tokens_dir")))
	}

	// ── Apply patches ──────────────────────────────────────────────────────
	newRaw, err := ApplyYAMLPatches(string(rawBytes), patches)
	if err != nil {
		s.logAudit(r, "settings.save", "patch error: "+err.Error(), false)
		s.settingsFlash(w, r, &Flash{Kind: "error", Message: "Patch failed: " + err.Error()}, string(rawBytes), tab)
		return
	}
	if err := s.writeConfigFile(newRaw); err != nil {
		s.logAudit(r, "settings.save", "write error: "+err.Error(), false)
		s.settingsFlash(w, r, &Flash{Kind: "error", Message: "Save failed: " + err.Error()}, string(rawBytes), tab)
		return
	}
	_ = s.reloadConfig()
	s.configPending = true
	s.logAudit(r, "settings.save", fmt.Sprintf("saved via form tab=%s mode=%s", tab, str("mode")), true)
	s.settingsFlash(w, r, &Flash{Kind: "success", Message: "Settings saved — restart VeilGate proxy to apply changes."}, newRaw, tab)
}

func (s *Server) settingsFlash(w http.ResponseWriter, r *http.Request, fl *Flash, rawContent, tab string) {
	raw := rawContent
	if raw == "" {
		b, _ := os.ReadFile(s.configPath)
		raw = string(b)
	}
	s.render(w, r, "settings", &PageData{
		Title:      "Settings",
		ActivePage: "settings",
		Flash:      fl,
		Data:       &SettingsData{Raw: raw, Tab: tab},
	})
}

// ── Rules ─────────────────────────────────────────────────────────────────

type RulesData struct {
	Files  []RuleFileInfo
	Root   string
	Exists bool
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	files, _ := s.listRuleFiles()
	_, existErr := os.Stat(s.rulesDir())
	s.render(w, r, "rules", &PageData{
		Title:      "Rule Files",
		ActivePage: "rules",
		Data:       &RulesData{Files: files, Root: s.rulesDir(), Exists: existErr == nil},
	})
}

type RuleEditData struct {
	FileName string
	Content  string
	Exists   bool
	FilePath string
}

func (s *Server) handleRuleEdit(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/rules/")
	if name == "" {
		http.Redirect(w, r, "/rules", http.StatusFound)
		return
	}

	switch r.Method {
	case http.MethodGet:
		content, err := s.readRuleFile(name)
		exists := err == nil
		if !exists {
			content = "# New rule file\n"
		}
		s.render(w, r, "rule_edit", &PageData{
			Title:      "Edit: " + name,
			ActivePage: "rules",
			Data: &RuleEditData{
				FileName: name,
				Content:  content,
				Exists:   exists,
				FilePath: filepath.Join(s.rulesDir(), name),
			},
		})

	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		content := r.FormValue("content")
		if err := s.writeRuleFile(name, content); err != nil {
			s.logAudit(r, "rule.save", "failed to save "+name+": "+err.Error(), false)
			s.render(w, r, "rule_edit", &PageData{
				Title:      "Edit: " + name,
				ActivePage: "rules",
				Flash:      &Flash{Kind: "error", Message: "Save failed: " + err.Error()},
				Data:       &RuleEditData{FileName: name, Content: content, FilePath: filepath.Join(s.rulesDir(), name)},
			})
			return
		}
		s.logAudit(r, "rule.save", "saved "+name, true)
		s.render(w, r, "rule_edit", &PageData{
			Title:      "Edit: " + name,
			ActivePage: "rules",
			Flash:      &Flash{Kind: "success", Message: "Saved — VeilGate hot-reloads within 500 ms."},
			Data:       &RuleEditData{FileName: name, Content: content, Exists: true, FilePath: filepath.Join(s.rulesDir(), name)},
		})

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ── Signals ───────────────────────────────────────────────────────────────
// Types moved to signals.go (SignalsFile, SignalOverride, CustomSignal).

type SignalsData struct {
	Groups        []SignalGroupView
	CustomSignals []CustomSignal
	FilePath      string
}

type SignalGroupView struct {
	Name    string
	Signals []SignalView
}

type SignalView struct {
	SignalDef
	Enabled  bool
	Points   int
	Override bool
}

func (s *Server) handleSignals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.signalsGET(w, r)
	case http.MethodPost:
		s.signalsPOST(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) signalsGET(w http.ResponseWriter, r *http.Request) {
	sf, _ := loadSignalsFile(s.rulesDir())
	groups := SignalGroups()
	var views []SignalGroupView
	for _, g := range groups {
		var sigs []SignalView
		for _, def := range g.Signals {
			sv := SignalView{SignalDef: def, Enabled: true, Points: def.Default}
			if ov, ok := sf.Signals[def.Name]; ok {
				sv.Override = true
				if ov.Enabled != nil {
					sv.Enabled = *ov.Enabled
				}
				if ov.Points != nil && *ov.Points > 0 {
					sv.Points = *ov.Points
				}
			}
			sigs = append(sigs, sv)
		}
		views = append(views, SignalGroupView{Name: g.Name, Signals: sigs})
	}

	var flash *Flash
	if r.URL.Query().Get("saved") == "1" {
		flash = &Flash{Kind: "success", Message: "Signals saved — VeilGate hot-reloads within 500 ms."}
	}

	s.render(w, r, "signals", &PageData{
		Title:      "Detection Signals",
		ActivePage: "signals",
		Flash:      flash,
		Data: &SignalsData{
			Groups:        views,
			CustomSignals: sf.CustomSignals,
			FilePath:      filepath.Join(s.rulesDir(), "signals.yaml"),
		},
	})
}

func (s *Server) signalsPOST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	// Read existing file to preserve custom_signals
	existing, _ := loadSignalsFile(s.rulesDir())

	// Build overrides — only write signals that differ from defaults
	overrides := make(map[string]SignalOverride)
	disabled, customized := 0, 0
	for _, def := range KnownSignals {
		ov := SignalOverride{}
		changed := false
		if r.FormValue("enabled_"+def.Name) != "on" {
			f := false
			ov.Enabled = &f
			changed = true
			disabled++
		}
		if ptsStr := r.FormValue("pts_" + def.Name); ptsStr != "" {
			if n, err := strconv.Atoi(ptsStr); err == nil && n != def.Default {
				ov.Points = &n
				changed = true
				customized++
			}
		}
		if changed {
			overrides[def.Name] = ov
		}
	}

	sf := SignalsFile{
		Signals:       overrides,
		CustomSignals: existing.CustomSignals, // preserve custom signals
	}
	content, err := marshalSignalsFile(sf)
	if err != nil {
		s.logAudit(r, "signals.save", "marshal error: "+err.Error(), false)
		http.Error(w, "marshal error", http.StatusInternalServerError)
		return
	}
	if err := s.writeRuleFile("signals.yaml", content); err != nil {
		s.logAudit(r, "signals.save", "write error: "+err.Error(), false)
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
	s.logAudit(r, "signals.save",
		fmt.Sprintf("%d disabled, %d custom weights", disabled, customized), true)
	http.Redirect(w, r, "/signals?saved=1", http.StatusSeeOther)
}

// ── OpenAPI ───────────────────────────────────────────────────────────────

type OpenAPIData struct {
	Content   string
	Exists    bool
	FilePath  string
	PathCount int
}

func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.openAPIGET(w, r)
	case http.MethodPost:
		s.openAPIPOST(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) openAPIGET(w http.ResponseWriter, r *http.Request) {
	fp := filepath.Join(s.rulesDir(), "openapi.yaml")
	content, err := os.ReadFile(fp)
	exists := err == nil
	pathCount := 0
	if exists {
		pathCount = countOpenAPIPaths(content)
	}

	var flash *Flash
	if r.URL.Query().Get("saved") == "1" {
		flash = &Flash{Kind: "success", Message: fmt.Sprintf("Blueprint saved — %d paths registered. VeilGate hot-reloads within 500 ms.", pathCount)}
	}

	s.render(w, r, "openapi", &PageData{
		Title:      "OpenAPI Blueprint",
		ActivePage: "openapi",
		Flash:      flash,
		Data:       &OpenAPIData{Content: string(content), Exists: exists, FilePath: fp, PathCount: pathCount},
	})
}

func (s *Server) openAPIPOST(w http.ResponseWriter, r *http.Request) {
	var content string
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}
		if f, _, err := r.FormFile("file"); err == nil {
			defer f.Close()
			buf := make([]byte, 4<<20)
			n, _ := f.Read(buf)
			content = string(buf[:n])
		}
		if content == "" {
			content = r.FormValue("content")
		}
	} else {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "parse error", http.StatusBadRequest)
			return
		}
		content = r.FormValue("content")
	}

	if content == "" {
		http.Error(w, "no content", http.StatusBadRequest)
		return
	}
	if err := s.writeRuleFile("openapi.yaml", content); err != nil {
		s.logAudit(r, "openapi.import", "write error: "+err.Error(), false)
		http.Error(w, "write error", http.StatusInternalServerError)
		return
	}
	paths := countOpenAPIPaths([]byte(content))
	s.logAudit(r, "openapi.import", fmt.Sprintf("imported %d paths", paths), true)
	http.Redirect(w, r, "/openapi?saved=1", http.StatusSeeOther)
}

func countOpenAPIPaths(content []byte) int {
	var doc map[string]any
	if yaml.Unmarshal(content, &doc) != nil {
		return 0
	}
	paths, _ := doc["paths"].(map[string]any)
	return len(paths)
}

// ── Audit Log ─────────────────────────────────────────────────────────────

type AuditData struct {
	Entries []AuditEntry
	Stats   AuditStats
	Path    string
	Empty   bool
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	var entries []AuditEntry
	var stats AuditStats
	var auditPath string

	if s.audit != nil {
		entries, _ = s.audit.Read(200)
		stats = s.audit.Stats()
		auditPath = s.audit.path
	}

	s.render(w, r, "audit", &PageData{
		Title:      "Audit Log",
		ActivePage: "audit",
		Data: &AuditData{
			Entries: entries,
			Stats:   stats,
			Path:    auditPath,
			Empty:   len(entries) == 0,
		},
	})
}

// ── Request Logs ──────────────────────────────────────────────────────────

type LogsData struct {
	Entries     []RequestLogEntry
	CapturePath string
	HasCapture  bool
	Empty       bool
	Source      string // "capture" (JSONL) or "store" (events.db)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	capturePath := ""
	if s.cfg != nil && s.cfg.Capture.Enabled {
		capturePath = s.cfg.Capture.Path
	}

	var entries []RequestLogEntry
	hasCapture := false
	source := ""
	if capturePath != "" {
		if _, err := os.Stat(capturePath); err == nil {
			hasCapture = true
			source = "capture"
			entries, _ = ReadRequestLogs(capturePath, 200)
		}
	}

	// Fall back to the event store (correlation DB) when JSONL capture is off.
	if len(entries) == 0 && s.store != nil {
		if rows, err := s.store.RecentEvents(200); err == nil && len(rows) > 0 {
			source = "store"
			for _, e := range rows {
				entries = append(entries, RequestLogEntry{
					Time:     e.Time,
					Client:   e.ClientID,
					Method:   e.Method,
					Path:     e.Path,
					Score:    e.Score,
					Decision: e.Decision,
					Threat:   scoreTierLabel(e.Score),
				})
			}
		}
	}

	s.render(w, r, "logs", &PageData{
		Title:      "Request Logs",
		ActivePage: "logs",
		Data: &LogsData{
			Entries:     entries,
			CapturePath: capturePath,
			HasCapture:  hasCapture,
			Empty:       len(entries) == 0,
			Source:      source,
		},
	})
}

// scoreTierLabel maps a score to a coarse threat tier for the request log.
func scoreTierLabel(score int) string {
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
}

// ── helpers ───────────────────────────────────────────────────────────────

func modeLabel(m string) string {
	switch m {
	case "observe":
		return "Observe"
	case "challenge":
		return "Challenge"
	case "tarpit":
		return "Tarpit"
	case "auto":
		return "Auto"
	default:
		return "Unknown"
	}
}

func modeKind(m string) string {
	switch m {
	case "observe":
		return "neutral"
	case "challenge":
		return "warn"
	case "tarpit", "auto":
		return "danger"
	default:
		return "default"
	}
}

var startTime = time.Now()
