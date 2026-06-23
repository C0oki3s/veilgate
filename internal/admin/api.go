package admin

// api.go — /api/v1/* REST endpoints.
//
// All responses are application/json.
// Auth: same session cookie as the UI pages.
// Errors: {"error": "...", "code": "ERR_CODE"} with appropriate HTTP status.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ── API wiring ─────────────────────────────────────────────────────────────

func (s *Server) registerAPI() {
	// api registers a method-qualified route: "GET /api/v1/foo", "PUT /api/v1/foo"
	// Go 1.22+ mux supports "METHOD /path" patterns directly.
	api := func(method, path string, h http.HandlerFunc) {
		s.mux.HandleFunc(method+" "+path, s.apiAuth(h))
	}
	apiAny := func(path string, h http.HandlerFunc) {
		s.mux.HandleFunc(path, s.apiAuth(h))
	}

	// Public
	s.mux.HandleFunc("/api/v1/health", s.apiHealth)
	s.mux.HandleFunc("/api/v1/auth/login", s.apiLogin)

	// Protected
	api("POST", "/api/v1/auth/logout", s.apiLogout)
	api("GET", "/api/v1/auth/me", s.apiMe)

	api("GET", "/api/v1/status", s.apiStatus)

	api("GET", "/api/v1/config", s.apiConfigGet)
	api("PUT", "/api/v1/config", s.apiConfigPut)
	api("GET", "/api/v1/config/raw", s.apiConfigRawGet)
	api("PUT", "/api/v1/config/raw", s.apiConfigRawPut)

	apiAny("/api/v1/rules", s.apiRules)
	apiAny("/api/v1/rules/", s.apiRuleFile)

	api("GET", "/api/v1/signals", s.apiSignalsGet)
	api("PUT", "/api/v1/signals", s.apiSignalsPut)

	api("GET", "/api/v1/openapi", s.apiOpenAPIGet)
	api("PUT", "/api/v1/openapi", s.apiOpenAPIPut)

	api("GET", "/api/v1/audit", s.apiAuditGet)
	api("GET", "/api/v1/audit/stats", s.apiAuditStats)

	api("GET", "/api/v1/logs", s.apiLogsGet)
}

// apiAuth wraps a handler with auth check, returning 401 JSON (not redirect).
func (s *Server) apiAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Skip auth for public endpoints
		path := r.URL.Path
		if path == "/api/v1/health" || path == "/api/v1/auth/login" {
			next(w, r)
			return
		}
		if s.auth != nil && !s.auth.Check(r) {
			apiErr(w, "authentication required", "UNAUTHENTICATED", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// ── Health ─────────────────────────────────────────────────────────────────

func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
		"uptime":  time.Since(s.startedAt).Truncate(time.Second).String(),
	})
}

// ── Auth ───────────────────────────────────────────────────────────────────

func (s *Server) apiLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiErr(w, "POST required", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	if s.auth == nil {
		apiErr(w, "authentication not configured", "AUTH_DISABLED", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, "invalid JSON body", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if !s.auth.Validate(body.Username, body.Password) {
		s.logAudit(r, "login", "invalid credentials: "+body.Username, false)
		apiErr(w, "invalid username or password", "INVALID_CREDENTIALS", http.StatusUnauthorized)
		return
	}
	id, err := s.auth.NewSession(body.Username)
	if err != nil {
		apiErr(w, "session error", "INTERNAL", http.StatusInternalServerError)
		return
	}
	s.auth.SetCookie(w, id)
	s.logAudit(r, "login", body.Username, true)
	apiJSON(w, http.StatusOK, map[string]any{"ok": true, "username": body.Username})
}

func (s *Server) apiLogout(w http.ResponseWriter, r *http.Request) {
	if s.auth != nil {
		s.logAudit(r, "logout", "", true)
		s.auth.Destroy(r)
		s.auth.ClearCookie(w)
	}
	apiJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) apiMe(w http.ResponseWriter, r *http.Request) {
	user := requestUser(r)
	apiJSON(w, http.StatusOK, map[string]any{
		"username":     user,
		"auth_enabled": s.auth != nil,
	})
}

// ── Status ─────────────────────────────────────────────────────────────────

func (s *Server) apiStatus(w http.ResponseWriter, r *http.Request) {
	_, rdErr := os.Stat(s.rulesDir())
	apiJSON(w, http.StatusOK, map[string]any{
		"version":                s.version,
		"uptime":                 time.Since(s.startedAt).Truncate(time.Second).String(),
		"config_path":            s.configPath,
		"config_pending_restart": s.configPending,
		"rules_dir":              s.rulesDir(),
		"rules_dir_ok":           rdErr == nil,
		"auth_enabled":           s.auth != nil,
		"mode":                   s.cfg.Mode,
	})
}

// ── Config ─────────────────────────────────────────────────────────────────

func (s *Server) apiConfigGet(w http.ResponseWriter, r *http.Request) {
	apiJSON(w, http.StatusOK, map[string]any{
		"config":          s.cfg,
		"pending_restart": s.configPending,
	})
}

// apiConfigPut accepts a nested JSON body matching the Config struct shape
// and applies changes surgically to the raw YAML file, preserving comments.
//
// Any field omitted from the body is left untouched in the file.
func (s *Server) apiConfigPut(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	rawBytes, err := os.ReadFile(s.configPath)
	if err != nil {
		apiErr(w, "read config: "+err.Error(), "READ_ERROR", http.StatusInternalServerError)
		return
	}

	var patches []YAMLPatch

	// helper: extract typed values from the nested body map
	str := func(obj map[string]any, key string) (string, bool) {
		v, ok := obj[key].(string)
		return v, ok
	}
	boolVal := func(obj map[string]any, key string) (bool, bool) {
		v, ok := obj[key].(bool)
		return v, ok
	}
	intVal := func(obj map[string]any, key string) (int, bool) {
		return floatToInt(obj[key])
	}
	int64Val := func(obj map[string]any, key string) (int64, bool) {
		switch n := obj[key].(type) {
		case float64:
			return int64(n), true
		case int64:
			return n, true
		}
		return 0, false
	}
	floatVal := func(obj map[string]any, key string) (float64, bool) {
		v, ok := obj[key].(float64)
		return v, ok
	}
	strSlice := func(obj map[string]any, key string) ([]string, bool) {
		raw, ok := obj[key].([]any)
		if !ok {
			return nil, false
		}
		var ss []string
		for _, item := range raw {
			if s, ok := item.(string); ok {
				ss = append(ss, s)
			}
		}
		return ss, true
	}
	strMap := func(obj map[string]any, key string) (map[string]string, bool) {
		raw, ok := obj[key].(map[string]any)
		if !ok {
			return nil, false
		}
		m := make(map[string]string)
		for k, v := range raw {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
		return m, true
	}
	sub := func(key string) (map[string]any, bool) {
		v, ok := body[key].(map[string]any)
		return v, ok
	}
	sub2 := func(obj map[string]any, key string) (map[string]any, bool) {
		v, ok := obj[key].(map[string]any)
		return v, ok
	}

	addStr := func(path []string, obj map[string]any, key string) {
		if v, ok := str(obj, key); ok {
			patches = append(patches, PatchString(path, v))
		}
	}
	addBool := func(path []string, obj map[string]any, key string) {
		if v, ok := boolVal(obj, key); ok {
			patches = append(patches, PatchBool(path, v))
		}
	}
	addInt := func(path []string, obj map[string]any, key string) {
		if v, ok := intVal(obj, key); ok {
			patches = append(patches, PatchInt(path, v))
		}
	}
	addFloat := func(path []string, obj map[string]any, key string) {
		if v, ok := floatVal(obj, key); ok {
			patches = append(patches, PatchFloat(path, v))
		}
	}

	// ── Proxy ──────────────────────────────────────────────────────────────
	addStr([]string{"listen"}, body, "listen")
	addStr([]string{"upstream"}, body, "upstream")
	addStr([]string{"mode"}, body, "mode")
	addStr([]string{"rules_dir"}, body, "rules_dir")

	// ── Detector ───────────────────────────────────────────────────────────
	if det, ok := sub("detector"); ok {
		addInt([]string{"detector", "score_challenge_threshold"}, det, "score_challenge_threshold")
		addInt([]string{"detector", "score_tarpit_threshold"}, det, "score_tarpit_threshold")
		addInt([]string{"detector", "window_seconds"}, det, "window_seconds")
		if ss, ok := strSlice(det, "probe_paths"); ok {
			patches = append(patches, PatchStrings([]string{"detector", "probe_paths"}, ss))
		}
		if ss, ok := strSlice(det, "trusted_ips"); ok {
			patches = append(patches, PatchStrings([]string{"detector", "trusted_ips"}, ss))
		}
		if ss, ok := strSlice(det, "trusted_proxies"); ok {
			patches = append(patches, PatchStrings([]string{"detector", "trusted_proxies"}, ss))
		}
	}

	// ── Challenge ──────────────────────────────────────────────────────────
	if ch, ok := sub("challenge"); ok {
		addStr([]string{"challenge", "secret"}, ch, "secret")
		addInt([]string{"challenge", "difficulty"}, ch, "difficulty")
		addInt([]string{"challenge", "ttl_minutes"}, ch, "ttl_minutes")
		addInt([]string{"challenge", "max_ttl_minutes"}, ch, "max_ttl_minutes")
	}

	// ── Tarpit ─────────────────────────────────────────────────────────────
	if tp, ok := sub("tarpit"); ok {
		addInt([]string{"tarpit", "min_latency_ms"}, tp, "min_latency_ms")
		addInt([]string{"tarpit", "max_latency_ms"}, tp, "max_latency_ms")
		addInt([]string{"tarpit", "max_body_bytes"}, tp, "max_body_bytes")
		addInt([]string{"tarpit", "response_cache_ttl_minutes"}, tp, "response_cache_ttl_minutes")
		addInt([]string{"tarpit", "response_cache_max_size"}, tp, "response_cache_max_size")
	}

	// ── TLS ────────────────────────────────────────────────────────────────
	if tls, ok := sub("tls"); ok {
		addBool([]string{"tls", "enabled"}, tls, "enabled")
		addStr([]string{"tls", "cert_file"}, tls, "cert_file")
		addStr([]string{"tls", "key_file"}, tls, "key_file")
	}

	// ── Persist ────────────────────────────────────────────────────────────
	if p, ok := sub("persist"); ok {
		addBool([]string{"persist", "enabled"}, p, "enabled")
		addStr([]string{"persist", "path"}, p, "path")
		addInt([]string{"persist", "retention_days"}, p, "retention_days")
		addInt([]string{"persist", "flush_every_ms"}, p, "flush_every_ms")
		addInt([]string{"persist", "queue_size"}, p, "queue_size")
		addStr([]string{"persist", "dump_path"}, p, "dump_path")
		addInt([]string{"persist", "cache_size_kb"}, p, "cache_size_kb")
	}

	// ── Capture ────────────────────────────────────────────────────────────
	if c, ok := sub("capture"); ok {
		addBool([]string{"capture", "enabled"}, c, "enabled")
		addStr([]string{"capture", "path"}, c, "path")
		addInt([]string{"capture", "max_mb"}, c, "max_mb")
		addInt([]string{"capture", "retention_hours"}, c, "retention_hours")
		addStr([]string{"capture", "janitor_every"}, c, "janitor_every")
		addInt([]string{"capture", "file_mode"}, c, "file_mode")
	}

	// ── Metrics ────────────────────────────────────────────────────────────
	if m, ok := sub("metrics"); ok {
		addBool([]string{"metrics", "disabled"}, m, "disabled")
		addStr([]string{"metrics", "listen"}, m, "listen")
		addStr([]string{"metrics", "api_key"}, m, "api_key")
	}

	// ── Telemetry ──────────────────────────────────────────────────────────
	if tel, ok := sub("telemetry"); ok {
		if otlp, ok := sub2(tel, "otlp"); ok {
			addStr([]string{"telemetry", "otlp", "endpoint"}, otlp, "endpoint")
			addBool([]string{"telemetry", "otlp", "insecure"}, otlp, "insecure")
			if m, ok := strMap(otlp, "headers"); ok {
				patches = append(patches, PatchKVMap([]string{"telemetry", "otlp", "headers"}, m))
			}
		}
		if tr, ok := sub2(tel, "traces"); ok {
			addBool([]string{"telemetry", "traces", "disabled"}, tr, "disabled")
			addFloat([]string{"telemetry", "traces", "sample_rate"}, tr, "sample_rate")
		}
		if lg, ok := sub2(tel, "logs"); ok {
			addBool([]string{"telemetry", "logs", "enabled"}, lg, "enabled")
		}
		if mp, ok := sub2(tel, "metrics_push"); ok {
			addBool([]string{"telemetry", "metrics_push", "enabled"}, mp, "enabled")
			addStr([]string{"telemetry", "metrics_push", "interval"}, mp, "interval")
		}
	}

	// ── Verifiers ──────────────────────────────────────────────────────────
	if vf, ok := sub("verifiers"); ok {
		if hmac, ok := sub2(vf, "hmac"); ok {
			addBool([]string{"verifiers", "hmac", "enabled"}, hmac, "enabled")
			addStr([]string{"verifiers", "hmac", "header_signature"}, hmac, "header_signature")
			addStr([]string{"verifiers", "hmac", "header_client"}, hmac, "header_client")
			addInt([]string{"verifiers", "hmac", "clock_skew_sec"}, hmac, "clock_skew_sec")
			if v, ok := int64Val(hmac, "max_body_bytes"); ok {
				patches = append(patches, PatchInt64([]string{"verifiers", "hmac", "max_body_bytes"}, v))
			}
			addStr([]string{"verifiers", "hmac", "clients_dir"}, hmac, "clients_dir")
		}
		if b, ok := sub2(vf, "bearer"); ok {
			addBool([]string{"verifiers", "bearer", "enabled"}, b, "enabled")
			addStr([]string{"verifiers", "bearer", "header"}, b, "header")
			addStr([]string{"verifiers", "bearer", "scheme"}, b, "scheme")
			addStr([]string{"verifiers", "bearer", "tokens_dir"}, b, "tokens_dir")
		}
	}

	// ── Write ──────────────────────────────────────────────────────────────
	if len(patches) == 0 {
		apiErr(w, "no recognized fields in body", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	newRaw, err := ApplyYAMLPatches(string(rawBytes), patches)
	if err != nil {
		apiErr(w, "patch error: "+err.Error(), "INTERNAL", http.StatusInternalServerError)
		return
	}
	if err := s.writeConfigFile(newRaw); err != nil {
		s.logAudit(r, "settings.save", "api PUT /config write failed: "+err.Error(), false)
		apiErr(w, "write error: "+err.Error(), "WRITE_ERROR", http.StatusInternalServerError)
		return
	}
	_ = s.reloadConfig()
	s.configPending = true
	s.logAudit(r, "settings.save", fmt.Sprintf("api: %d patches applied", len(patches)), true)
	apiJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"patches_applied": len(patches),
		"pending_restart": true,
		"message":         "Config saved — restart VeilGate proxy to apply changes.",
	})
}

func (s *Server) apiConfigRawGet(w http.ResponseWriter, r *http.Request) {
	raw, err := os.ReadFile(s.configPath)
	if err != nil {
		apiErr(w, "read error: "+err.Error(), "READ_ERROR", http.StatusInternalServerError)
		return
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"content":         string(raw),
		"pending_restart": s.configPending,
	})
}

func (s *Server) apiConfigRawPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if body.Content == "" {
		apiErr(w, "content is required", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if err := s.writeConfigFile(body.Content); err != nil {
		s.logAudit(r, "settings.save", "api PUT /config/raw failed: "+err.Error(), false)
		apiErr(w, "write error: "+err.Error(), "WRITE_ERROR", http.StatusInternalServerError)
		return
	}
	_ = s.reloadConfig()
	s.configPending = true
	s.logAudit(r, "settings.save", "raw YAML saved via API", true)
	apiJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"pending_restart": true,
		"message":         "Config saved — restart VeilGate proxy to apply changes.",
	})
}

// ── Rules ──────────────────────────────────────────────────────────────────

func (s *Server) apiRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiErr(w, "GET /api/v1/rules to list files, PUT /api/v1/rules/{name} to edit", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
		return
	}
	files, err := s.listRuleFiles()
	if err != nil && !os.IsNotExist(err) {
		apiErr(w, "list error: "+err.Error(), "READ_ERROR", http.StatusInternalServerError)
		return
	}
	type fileInfo struct {
		Path    string    `json:"path"`
		Size    int64     `json:"size_bytes"`
		ModTime time.Time `json:"mod_time"`
	}
	var out []fileInfo
	for _, f := range files {
		out = append(out, fileInfo{Path: f.Path, Size: f.Size, ModTime: f.ModTime})
	}
	if out == nil {
		out = []fileInfo{}
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"files":     out,
		"rules_dir": s.rulesDir(),
	})
}

func (s *Server) apiRuleFile(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/")
	if name == "" {
		apiErr(w, "file name required", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		content, err := s.readRuleFile(name)
		if err != nil {
			if os.IsNotExist(err) {
				apiErr(w, "file not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			apiErr(w, "read error: "+err.Error(), "READ_ERROR", http.StatusInternalServerError)
			return
		}
		apiJSON(w, http.StatusOK, map[string]any{
			"name":    name,
			"path":    filepath.Join(s.rulesDir(), name),
			"content": content,
		})

	case http.MethodPut:
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			apiErr(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		if err := s.writeRuleFile(name, body.Content); err != nil {
			s.logAudit(r, "rule.save", "api PUT /rules/"+name+": "+err.Error(), false)
			apiErr(w, "write error: "+err.Error(), "WRITE_ERROR", http.StatusInternalServerError)
			return
		}
		s.logAudit(r, "rule.save", name+" via API", true)
		apiJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"name":    name,
			"message": "Rule saved — VeilGate hot-reloads within 500 ms.",
		})

	case http.MethodDelete:
		name = filepath.Clean(name)
		if strings.Contains(name, "..") {
			apiErr(w, "invalid path", "BAD_REQUEST", http.StatusBadRequest)
			return
		}
		path := filepath.Join(s.rulesDir(), name)
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				apiErr(w, "file not found", "NOT_FOUND", http.StatusNotFound)
				return
			}
			s.logAudit(r, "rule.delete", name+": "+err.Error(), false)
			apiErr(w, "delete error: "+err.Error(), "DELETE_ERROR", http.StatusInternalServerError)
			return
		}
		s.logAudit(r, "rule.delete", name, true)
		apiJSON(w, http.StatusOK, map[string]any{"ok": true, "name": name})

	default:
		apiErr(w, "GET, PUT, or DELETE", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed)
	}
}

// ── Signals ────────────────────────────────────────────────────────────────

func (s *Server) apiSignalsGet(w http.ResponseWriter, r *http.Request) {
	sig, err := loadSignalsFile(s.rulesDir())
	if err != nil {
		apiErr(w, "read error: "+err.Error(), "READ_ERROR", http.StatusInternalServerError)
		return
	}

	// Merge builtin defaults with overrides
	type SignalView struct {
		Name        string `json:"name"`
		Group       string `json:"group"`
		Default     int    `json:"default_points"`
		Points      int    `json:"points"`
		Enabled     bool   `json:"enabled"`
		Overridden  bool   `json:"overridden"`
		Description string `json:"description"`
	}
	var builtins []SignalView
	for _, def := range KnownSignals {
		sv := SignalView{
			Name:        def.Name,
			Group:       def.Group,
			Default:     def.Default,
			Points:      def.Default,
			Enabled:     true,
			Description: def.Desc,
		}
		if ov, ok := sig.Signals[def.Name]; ok {
			sv.Overridden = true
			if ov.Enabled != nil {
				sv.Enabled = *ov.Enabled
			}
			if ov.Points != nil && *ov.Points > 0 {
				sv.Points = *ov.Points
			}
		}
		builtins = append(builtins, sv)
	}

	// Return the raw overrides map so clients can preserve it in PUT requests
	overrides := sig.Signals
	if overrides == nil {
		overrides = map[string]SignalOverride{}
	}
	cs := sig.CustomSignals
	if cs == nil {
		cs = []CustomSignal{}
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"builtin_signals": builtins,
		"custom_signals":  cs,
		"overrides":       overrides,
		"file_path":       filepath.Join(s.rulesDir(), "signals.yaml"),
	})
}

func (s *Server) apiSignalsPut(w http.ResponseWriter, r *http.Request) {
	var body SignalsFile
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}

	// Read existing to preserve fields we don't manage
	existing, _ := loadSignalsFile(s.rulesDir())
	if body.CustomSignals == nil {
		body.CustomSignals = existing.CustomSignals
	}

	content, err := marshalSignalsFile(body)
	if err != nil {
		apiErr(w, "marshal error: "+err.Error(), "INTERNAL", http.StatusInternalServerError)
		return
	}
	if err := s.writeRuleFile("signals.yaml", content); err != nil {
		s.logAudit(r, "signals.save", "api: "+err.Error(), false)
		apiErr(w, "write error: "+err.Error(), "WRITE_ERROR", http.StatusInternalServerError)
		return
	}

	disabled := 0
	for _, ov := range body.Signals {
		if ov.Enabled != nil && !*ov.Enabled {
			disabled++
		}
	}
	s.logAudit(r, "signals.save",
		fmt.Sprintf("api: %d overrides, %d custom signals", len(body.Signals), len(body.CustomSignals)), true)
	apiJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"overrides":      len(body.Signals),
		"custom_signals": len(body.CustomSignals),
		"disabled":       disabled,
		"message":        "Signals saved — VeilGate hot-reloads within 500 ms.",
	})
}

// ── OpenAPI Blueprint ─────────────────────────────────────────────────────

func (s *Server) apiOpenAPIGet(w http.ResponseWriter, r *http.Request) {
	fp := filepath.Join(s.rulesDir(), "openapi.yaml")
	content, err := os.ReadFile(fp)
	exists := err == nil
	paths := 0
	if exists {
		paths = countOpenAPIPaths(content)
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"exists":     exists,
		"file_path":  fp,
		"path_count": paths,
		"content":    string(content),
	})
}

func (s *Server) apiOpenAPIPut(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiErr(w, "invalid JSON", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if body.Content == "" {
		apiErr(w, "content is required", "BAD_REQUEST", http.StatusBadRequest)
		return
	}
	if err := s.writeRuleFile("openapi.yaml", body.Content); err != nil {
		s.logAudit(r, "openapi.import", "api: "+err.Error(), false)
		apiErr(w, "write error: "+err.Error(), "WRITE_ERROR", http.StatusInternalServerError)
		return
	}
	paths := countOpenAPIPaths([]byte(body.Content))
	s.logAudit(r, "openapi.import", fmt.Sprintf("api: %d paths", paths), true)
	apiJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"path_count": paths,
		"message":    fmt.Sprintf("Blueprint saved — %d paths registered. Hot-reloads within 500 ms.", paths),
	})
}

// ── Audit ──────────────────────────────────────────────────────────────────

func (s *Server) apiAuditGet(w http.ResponseWriter, r *http.Request) {
	n := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	var entries []AuditEntry
	if s.audit != nil {
		entries, _ = s.audit.Read(n)
	}
	if entries == nil {
		entries = []AuditEntry{}
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"count":   len(entries),
	})
}

func (s *Server) apiAuditStats(w http.ResponseWriter, r *http.Request) {
	var stats AuditStats
	if s.audit != nil {
		stats = s.audit.Stats()
	}
	apiJSON(w, http.StatusOK, stats)
}

// ── Request Logs ───────────────────────────────────────────────────────────

func (s *Server) apiLogsGet(w http.ResponseWriter, r *http.Request) {
	n := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	capturePath := ""
	if s.cfg != nil && s.cfg.Capture.Enabled {
		capturePath = s.cfg.Capture.Path
	}

	var entries []RequestLogEntry
	if capturePath != "" {
		if _, err := os.Stat(capturePath); err == nil {
			entries, _ = ReadRequestLogs(capturePath, n)
		}
	}
	if entries == nil {
		entries = []RequestLogEntry{}
	}
	apiJSON(w, http.StatusOK, map[string]any{
		"entries":      entries,
		"count":        len(entries),
		"capture_path": capturePath,
		"enabled":      s.cfg != nil && s.cfg.Capture.Enabled,
	})
}

// ── Helpers ────────────────────────────────────────────────────────────────

func apiJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func apiErr(w http.ResponseWriter, msg, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": msg,
		"code":  code,
	})
}

func floatToInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	}
	return 0, false
}
