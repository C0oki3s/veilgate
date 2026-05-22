package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/C0oki3s/veilgate/internal/audit"
	"github.com/C0oki3s/veilgate/internal/challenge"
	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/h2fp"
	"github.com/C0oki3s/veilgate/internal/ml"
	"github.com/C0oki3s/veilgate/internal/payloads"
	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/proxy"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/tarpit"
	"github.com/C0oki3s/veilgate/internal/telemetry"
	"github.com/C0oki3s/veilgate/internal/tlsfp"
	"github.com/C0oki3s/veilgate/internal/verifier"
)

// buildVerifierChain constructs the operator-configured authenticator
// chain. Each enabled block adds one verifier; a misconfigured
// enabled block (e.g. hmac.enabled=true with no clients_dir) is a
// fatal startup error rather than a silent skip.
func buildVerifierChain(cfg *config.Config, log zerolog.Logger) *verifier.Chain {
	verifiers := []verifier.Verifier{}
	if cfg.Verifiers.HMAC.Enabled {
		v, err := verifier.NewHMACVerifier(verifier.HMACConfig{
			HeaderSignature: cfg.Verifiers.HMAC.HeaderSignature,
			HeaderClient:    cfg.Verifiers.HMAC.HeaderClient,
			ClockSkewSec:    cfg.Verifiers.HMAC.ClockSkewSec,
			MaxBodyBytes:    cfg.Verifiers.HMAC.MaxBodyBytes,
			ClientsDir:      cfg.Verifiers.HMAC.ClientsDir,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("hmac verifier: bad config")
		}
		verifiers = append(verifiers, v)
		log.Info().
			Str("clients_dir", cfg.Verifiers.HMAC.ClientsDir).
			Msg("hmac verifier enabled")
	}
	if cfg.Verifiers.Bearer.Enabled {
		v, err := verifier.NewBearerVerifier(verifier.BearerConfig{
			Header:    cfg.Verifiers.Bearer.Header,
			Scheme:    cfg.Verifiers.Bearer.Scheme,
			TokensDir: cfg.Verifiers.Bearer.TokensDir,
		})
		if err != nil {
			log.Fatal().Err(err).Msg("bearer verifier: bad config")
		}
		verifiers = append(verifiers, v)
		log.Info().
			Str("tokens_dir", cfg.Verifiers.Bearer.TokensDir).
			Int("loaded", v.LoadedTokens()).
			Msg("bearer verifier enabled")
	}
	for _, cc := range cfg.Verifiers.Cookies {
		val, err := buildValidator(cc.Validator, validatorArgs{
			TokensDir:       cc.TokensDir,
			JWKSURL:         cc.JWKSURL,
			Issuer:          cc.Issuer,
			Audience:        cc.Audience,
			ClientClaim:     cc.ClientClaim,
			Algorithms:      cc.Algorithms,
			RefreshInterval: cc.RefreshInterval,
			URL:             cc.URL,
			CacheTTL:        cc.CacheTTL,
			Timeout:         cc.Timeout,
			AuthHeader:      cc.AuthHeader,
			AuthValue:       cc.AuthValue,
		})
		if err != nil {
			log.Fatal().Err(err).Str("cookie", cc.Name).Msg("cookie verifier: bad config")
		}
		v, err := verifier.NewCookieVerifier(cc.Name, val)
		if err != nil {
			log.Fatal().Err(err).Str("cookie", cc.Name).Msg("cookie verifier: bad config")
		}
		verifiers = append(verifiers, v)
		log.Info().
			Str("cookie", cc.Name).
			Str("validator", cc.Validator).
			Msg("cookie verifier enabled")
	}
	for _, hc := range cfg.Verifiers.Headers {
		val, err := buildValidator(hc.Validator, validatorArgs{
			TokensDir:       hc.TokensDir,
			JWKSURL:         hc.JWKSURL,
			Issuer:          hc.Issuer,
			Audience:        hc.Audience,
			ClientClaim:     hc.ClientClaim,
			Algorithms:      hc.Algorithms,
			RefreshInterval: hc.RefreshInterval,
			URL:             hc.URL,
			CacheTTL:        hc.CacheTTL,
			Timeout:         hc.Timeout,
			AuthHeader:      hc.AuthHeader,
			AuthValue:       hc.AuthValue,
		})
		if err != nil {
			log.Fatal().Err(err).Str("header", hc.Name).Msg("header verifier: bad config")
		}
		v, err := verifier.NewHeaderVerifier(hc.Name, val)
		if err != nil {
			log.Fatal().Err(err).Str("header", hc.Name).Msg("header verifier: bad config")
		}
		verifiers = append(verifiers, v)
		log.Info().
			Str("header", hc.Name).
			Str("validator", hc.Validator).
			Msg("header verifier enabled")
	}
	return verifier.NewChain(verifiers...)
}

// validatorArgs collects every field cookie- and header-verifier
// entries can supply to their validator. Each validator type ignores
// fields it doesn't use; bad combinations (e.g. validator=jwt with
// no jwks_url) fail at NewJWTValidator, not silently.
type validatorArgs struct {
	TokensDir       string
	JWKSURL         string
	Issuer          string
	Audience        string
	ClientClaim     string
	Algorithms      []string
	RefreshInterval string
	URL             string
	CacheTTL        string
	Timeout         string
	AuthHeader      string
	AuthValue       string
}

// buildValidator constructs the Validator implementation named in a
// cookie/header verifier entry. Shared so cookie (#2) and header
// (#3) entries pick the same validator surface. Unknown validator
// names are a startup-fatal config error to avoid silent
// misconfiguration.
func buildValidator(kind string, a validatorArgs) (verifier.Validator, error) {
	switch kind {
	case "opaque", "":
		return verifier.NewOpaqueValidator(a.TokensDir)
	case "jwt":
		refresh, err := parseDurationOrZero(a.RefreshInterval)
		if err != nil {
			return nil, fmt.Errorf("jwt validator: refresh_interval: %w", err)
		}
		return verifier.NewJWTValidator(verifier.JWTConfig{
			JWKSURL:         a.JWKSURL,
			Issuer:          a.Issuer,
			Audience:        a.Audience,
			ClientClaim:     a.ClientClaim,
			Algorithms:      a.Algorithms,
			RefreshInterval: refresh,
		})
	case "callout":
		ttl, err := parseDurationOrZero(a.CacheTTL)
		if err != nil {
			return nil, fmt.Errorf("callout validator: cache_ttl: %w", err)
		}
		timeout, err := parseDurationOrZero(a.Timeout)
		if err != nil {
			return nil, fmt.Errorf("callout validator: timeout: %w", err)
		}
		return verifier.NewCalloutValidator(verifier.CalloutConfig{
			URL:        a.URL,
			CacheTTL:   ttl,
			Timeout:    timeout,
			AuthHeader: a.AuthHeader,
			AuthValue:  a.AuthValue,
		})
	default:
		return nil, fmt.Errorf("unknown validator type %q", kind)
	}
}

func parseDurationOrZero(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// canaryAdapter wraps persist.Store so it satisfies the
// detector.CanaryLookup interface (which deliberately doesn't import
// persist to avoid the import cycle).
type canaryAdapter struct{ s *persist.Store }

func (c canaryAdapter) HitCanary(token, clientID string) (string, bool) {
	return c.s.CanaryProbe(token, clientID)
}

// listenTLS starts the HTTPS server with a JA4-sniffing listener in front
// of Go's TLS handshake.
func listenTLS(srv *http.Server, cfg *config.Config, store *tlsfp.Store) error {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return err
	}
	raw, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	sniffed := tlsfp.NewListener(raw, store)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2", "http/1.1"},
	}
	tlsLn := tls.NewListener(sniffed, tlsCfg)
	return srv.Serve(proxy.NewFramingGuardListener(tlsLn))
}

// version is set at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	// Subcommand dispatch. The proxy's serve flow remains the default
	// when no subcommand is given. New subcommands plug in here.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "forget":
			runForget(os.Args[2:])
			return
		case "update-rules":
			runUpdateRules(os.Args[2:])
			return
		case "update":
			runUpdate(os.Args[2:])
			return
		case "-version", "--version", "version":
			fmt.Println(version)
			return
		}
	}

	cfgPath := flag.String("config", "configs/veilgate.yaml", "path to config file")
	flag.Parse()

	log := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}
	if envSecret := strings.TrimSpace(os.Getenv("VEILGATE_SECRET")); envSecret != "" {
		cfg.Challenge.Secret = envSecret
	}
	const insecureDefaultSecret = "change-me-in-production-or-set-VEILGATE_SECRET"
	if cfg.Challenge.Secret == insecureDefaultSecret {
		if cfg.Mode == "observe" {
			log.Warn().Msg("challenge secret uses insecure default; challenge mode should set VEILGATE_SECRET or config.challenge.secret")
		} else {
			log.Fatal().Msg("refusing to start with insecure default challenge secret; set VEILGATE_SECRET or config.challenge.secret")
		}
	}
	// Score is hard-capped at 100 in the detector. A tarpit threshold above
	// that value can never be reached and silently disables the tarpit.
	const maxScore = 100
	if cfg.Detector.ScoreTarpitThreshold > maxScore {
		log.Warn().
			Int("score_tarpit_threshold", cfg.Detector.ScoreTarpitThreshold).
			Int("max_score", maxScore).
			Msg("score_tarpit_threshold exceeds maximum possible score — tarpit will never fire; lower it to 100 or below")
	}
	log.Info().Str("mode", cfg.Mode).Str("upstream", cfg.Upstream).Msg("starting veilgate")

	// Root context so background goroutines shut down cleanly.
	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	detectorRules, err := rules.LoadDetector(cfg.RulesDir)
	if err != nil {
		log.Fatal().Err(err).Msg("load detector rules")
	}
	ipRep, err := rules.LoadIPReputation(cfg.RulesDir)
	if err != nil {
		log.Fatal().Err(err).Msg("load ip_reputation rules")
	}

	tracker := detector.NewTracker(cfg.Detector.WindowSeconds)
	scorer := detector.NewScorer(tracker, cfg.Detector.HoneypotPaths, cfg.Detector.TrustedIPs)
	scorer.SetRules(detectorRules)
	scorer.SetIPReputation(ipRep)

	// HTTP/2 SETTINGS fingerprint store. Always-on; the actual capture
	// happens at the http2 connection-establishment hook (operators
	// wire it into their TLS listener if they want H2 fingerprinting).
	// The classifier reads from the store on the request hot path.
	h2Store := h2fp.NewStore(10 * time.Minute)
	h2DB := h2fp.NewDatabase()
	scorer.SetH2Lookup(h2fp.NewClassifier(h2Store, h2DB))

	// Hot-reload rule holders — one per subsystem. Populated from disk
	// (or embedded default) once, then swapped atomically by the watcher.
	templatesVal, _ := rules.LoadTemplates(cfg.RulesDir)
	fakeDataVal, _ := rules.LoadFakeData(cfg.RulesDir)
	vulnVal, _ := rules.LoadVulnerabilities(cfg.RulesDir)
	strategyVal, _ := rules.LoadInjectionStrategy(cfg.RulesDir)
	challengeVal, _ := rules.LoadChallenge(cfg.RulesDir)
	mlVal, err := rules.LoadML(cfg.RulesDir)
	if err != nil {
		log.Warn().Err(err).Msg("load ml rules failed; online ML and miner disabled until ml.yaml loads")
		mlVal = &rules.ML{}
	}
	dashboardVal, _ := rules.LoadDashboard(cfg.RulesDir)

	templatesHolder := rules.NewHolder(templatesVal)
	fakeDataHolder := rules.NewHolder(fakeDataVal)
	vulnHolder := rules.NewHolder(vulnVal)
	strategyHolder := rules.NewHolder(strategyVal)
	challengeHolder := rules.NewHolder(challengeVal)
	mlHolder := rules.NewHolder(mlVal)
	dashboardHolder := rules.NewHolder(dashboardVal)

	// TLS fingerprinting — active only when TLS is enabled.
	var tlsStore *tlsfp.Store
	var tlsDB *tlsfp.Database
	if cfg.TLS.Enabled {
		tlsStore = tlsfp.NewStore(10 * time.Minute)
		tlsDB, err = tlsfp.NewDatabaseFromDir(cfg.RulesDir)
		if err != nil {
			log.Fatal().Err(err).Msg("load TLS fingerprints")
		}
		scorer.SetTLSLookup(tlsfp.NewClassifier(tlsStore, tlsDB))
		log.Info().Msg("TLS fingerprinting enabled (JA3/JA4)")
	}

	// Persistence — opt-in via persist.enabled.
	var store *persist.Store
	if cfg.Persist.Enabled {
		store, err = persist.Open(persist.Config{
			Path:      cfg.Persist.Path,
			QueueSize: cfg.Persist.QueueSize,
			WalMB:     cfg.Persist.CacheSizeKB / 1024,
		})
		if err != nil {
			log.Fatal().Err(err).Str("path", cfg.Persist.Path).Msg("open persist store")
		}
		log.Info().Str("path", cfg.Persist.Path).Msg("persist store open")
		defer store.Close()

		// Canary table lives in the same store; wire the detector lookup.
		scorer.SetCanaryLookup(canaryAdapter{store})

		// Periodic maintenance: WAL checkpoint truncation + canary GC.
		go store.Maintenance(rootCtx, 5*time.Minute, func(err error) {
			log.Warn().Err(err).Msg("persist maintenance")
		})
	}

	// Audit logger. Writes to both an append-only JSONL file (for SIEM
	// shipping) and the audit_log SQLite table (for local query).
	var auditLog *audit.Logger
	{
		var fileW *audit.FileWriter
		var seedHash string
		auditPath := filepath.Join(filepath.Dir(cfg.Persist.Path), "audit.log")
		if w, last, err := audit.NewFileWriter(auditPath); err == nil {
			fileW = w
			seedHash = last
			defer fileW.Close()
		}
		var sqlW audit.Writer
		if store != nil {
			sqlW = &audit.SQLBackend{DB: store}
			if h := store.LastAuditHash(); h != "" {
				seedHash = h
			}
		}
		auditLog = audit.NewLogger(fileW, sqlW)
		auditLog.SetSeedHash(seedHash)
		_ = auditLog.Log(audit.Entry{
			Actor: "system", Action: "process.start",
			Detail: "veilgate started",
			Meta:   audit.FmtMeta("config", *cfgPath, "mode", cfg.Mode),
		})
	}

	// ML scorer — gated by ml.enabled in rules/ml.yaml. Always construct
	// so the miner and rollouts can reference a non-nil scorer; the gate
	// lives inside Score/Observe.
	mlExtractor := ml.NewExtractor()
	if m := mlHolder.Load(); m != nil && len(m.Bayes.TimingBucketsSeconds) > 0 {
		mlExtractor.TimingBuckets = m.Bayes.TimingBucketsSeconds
	}
	if m := mlHolder.Load(); m != nil && m.Bayes.MaxNgramLength > 0 {
		mlExtractor.MaxNgramLength = m.Bayes.MaxNgramLength
	}
	mlScorer := ml.NewScorer(mlHolder)
	scorer.SetML(mlScorer, mlExtractor, cfg.Detector.ScoreChallengeThreshold)

	// Path redaction. Built-in default rules cover UUIDs / numeric IDs
	// / hex / base64; any custom regexes in ml.yaml are appended.
	if m := mlHolder.Load(); m == nil || m.PathRedaction.Enabled {
		pr := ml.NewDefaultPathRedactor()
		if m != nil {
			for _, c := range m.PathRedaction.Custom {
				pr.AddCustom(c.Regex, c.Replace)
			}
		}
		ml.SetActiveRedactor(pr)
		log.Info().Msg("ML path redaction active (UUIDs / IDs / hex / tokens scrubbed)")
	}

	// Load learned rules (miner output + community rules from learned/)
	// and seed the Bayes classifier so active candidates take effect
	// immediately — before the burn-in period fills from live traffic.
	if learned, err := rules.LoadLearned(cfg.RulesDir); err != nil {
		log.Warn().Err(err).Msg("failed to load learned rules at startup")
	} else if n := mlScorer.SeedFromLearned(learned.Candidates); n > 0 {
		log.Info().Int("candidates", n).Msg("seeded Bayes from learned rules")
	}

	// Background GC for stale client state + cardinality gauges.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-ticker.C:
				tracker.GC(30 * time.Minute)
				scorer.FleetGC(30 * time.Minute)
				if tlsStore != nil {
					tlsStore.GC()
				}
				if h2Store != nil {
					h2Store.GC()
				}
			}
		}
	}()

	// Cardinality gauges — tiny poll so the Prometheus graphs have
	// something to plot for "how many unique clients / fingerprints
	// are we tracking right now". 30s is short enough to feel live,
	// long enough that the locks don't cost anything.
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-ticker.C:
				telemetry.ClientCardinality.Set(float64(tracker.Len()))
				fp := scorer.FleetSnapshot()
				telemetry.FleetFingerprintCardinality.Set(float64(len(fp)))
				for _, n := range fp {
					telemetry.FleetFingerprintIPs.Observe(float64(n))
				}
			}
		}
	}()

	// Isolation Forest refit loop — decoupled from request path AND
	// from the ticker itself. A fit runs on its own goroutine; if the
	// previous fit is still in-flight when the next tick arrives, we
	// skip it rather than stack, so ingestion (Observe) is never
	// slowed down by retrain contention.
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-rootCtx.Done():
				return
			case <-t.C:
				m := mlHolder.Load()
				if m == nil || !m.Enabled {
					telemetry.MLFitsTotal.WithLabelValues("skipped_disabled").Inc()
					continue
				}
				every := m.IsoForest.RetrainEveryNEvents
				if every <= 0 {
					every = 5000
				}
				if mlScorer.BufferedRows() < every {
					telemetry.MLFitsTotal.WithLabelValues("skipped_cold").Inc()
					continue
				}
				started := mlScorer.RefitIsoForestAsync(func(rows int, dur time.Duration) {
					telemetry.MLFitDuration.Observe(dur.Seconds())
					telemetry.MLFitRows.Observe(float64(rows))
					telemetry.MLFitsTotal.WithLabelValues("ok").Inc()
					telemetry.BayesObservedTotal.Set(float64(mlScorer.Observed()))
					log.Info().
						Int("rows", rows).
						Dur("took", dur).
						Int64("fits", mlScorer.FitCount()).
						Msg("iso forest refit")
				})
				if !started {
					telemetry.MLFitsTotal.WithLabelValues("skipped_busy").Inc()
					log.Debug().Msg("iso forest refit skipped — previous fit still running")
				}
			}
		}
	}()

	// Rule miner — proposes candidates into rules/learned.yaml.
	miner := ml.NewMiner(mlScorer.Bayes(), mlHolder, store, cfg.RulesDir)
	go miner.Run(rootCtx, func(err error) {
		log.Warn().Err(err).Msg("miner tick")
	})

	// Trim + CSV dump goroutine — replaces the old JSONL rotation script.
	if store != nil && cfg.Persist.RetentionDays > 0 {
		go func() {
			t := time.NewTicker(6 * time.Hour)
			defer t.Stop()
			for {
				select {
				case <-rootCtx.Done():
					return
				case <-t.C:
					cutoff := time.Now().Add(-time.Duration(cfg.Persist.RetentionDays) * 24 * time.Hour)
					if cfg.Persist.DumpPath != "" {
						dst := cfg.Persist.DumpPath + "/events-" + time.Now().UTC().Format("20060102-150405") + ".csv.gz"
						if n, err := store.DumpCSVGz(dst, cutoff); err != nil {
							log.Warn().Err(err).Msg("persist dump")
							continue
						} else {
							log.Info().Int("rows", n).Str("dst", dst).Msg("persist dumped")
						}
					}
					n, err := store.Trim(cutoff)
					if err != nil {
						log.Warn().Err(err).Msg("persist trim")
						continue
					}
					log.Info().Int64("rows", n).Msg("persist trimmed")
				}
			}
		}()
	}

	profileStore := tarpit.NewProfileStore()
	profileStore.SetFakeData(fakeDataHolder)

	lib, err := payloads.NewLibraryFromDir(cfg.RulesDir)
	if err != nil {
		log.Fatal().Err(err).Msg("load payload rules")
	}
	injStrat := strategyHolder.Load()
	maxPayloads := 3
	visitBucket := true
	if injStrat != nil {
		if injStrat.Injector.MaxPayloadsPerResponse > 0 {
			maxPayloads = injStrat.Injector.MaxPayloadsPerResponse
		}
		visitBucket = injStrat.Injector.VisitBucketRotation
	}
	injector := payloads.NewInjector(lib, maxPayloads, visitBucket)

	tp := tarpit.NewHandler(&cfg.Tarpit, profileStore, injector)
	tp.SetRules(templatesHolder, vulnHolder, strategyHolder)

	ch := challenge.NewHandler(
		cfg.Challenge.Secret,
		cfg.Challenge.Difficulty,
		time.Duration(cfg.Challenge.TTLMinutes)*time.Minute,
	)
	ch.SetRules(challengeHolder)

	dash := telemetry.NewDashboard(dashboardHolder)

	srv, err := proxy.NewServer(cfg, scorer, tp, ch, dash, log)
	if err != nil {
		log.Fatal().Err(err).Msg("build server")
	}
	srv.SetTracker(tracker)
	if store != nil {
		srv.SetPersist(store, mlExtractor)
	}

	// Build the alternate-authenticator chain. Disabled verifiers
	// don't contribute; absence of a clients_dir on the HMAC verifier
	// is a fatal config error if hmac.enabled is true.
	verifiers := buildVerifierChain(cfg, log)
	srv.SetVerifiers(verifiers)
	if verifiers.Len() > 0 {
		log.Info().Int("verifiers", verifiers.Len()).Msg("authenticator chain installed")
	}

	if cfg.Capture.Enabled {
		// Compile any operator-supplied scrub rules. Bad regexes are
		// silently dropped so a typo doesn't take the proxy down.
		scrubSpecs := make([]struct{ Pattern, Replace string }, 0, len(cfg.Capture.Scrub))
		for _, sp := range cfg.Capture.Scrub {
			scrubSpecs = append(scrubSpecs, struct{ Pattern, Replace string }{sp.Pattern, sp.Replace})
		}
		cap, err := telemetry.NewCaptureWithOptions(cfg.Capture.Path, telemetry.CaptureOptions{
			MaxMB:          cfg.Capture.MaxMB,
			RetentionHours: cfg.Capture.RetentionHours,
			FileMode:       os.FileMode(cfg.Capture.FileMode),
			Scrub:          telemetry.CompileScrubRules(scrubSpecs),
		})
		if err != nil {
			log.Fatal().Err(err).Msg("open capture file")
		}
		srv.SetCapture(cap)
		defer cap.Close()

		// Start the janitor when retention is configured. Idle goroutine
		// cost is one ticker — cheap.
		if cfg.Capture.RetentionHours > 0 {
			every, _ := time.ParseDuration(cfg.Capture.JanitorEvery)
			go cap.RunJanitor(rootCtx, every, func(err error) {
				log.Warn().Err(err).Msg("capture janitor")
			})
		}
		log.Info().
			Str("path", cfg.Capture.Path).
			Int("retention_hours", cfg.Capture.RetentionHours).
			Int("scrub_rules", len(cfg.Capture.Scrub)).
			Msg("request capture enabled")
	}

	// Rules hot-reload watcher.
	if w, err := rules.NewWatcher(cfg.RulesDir); err != nil {
		log.Warn().Err(err).Msg("rules watcher disabled")
	} else if w != nil {
		w.Register("detector.yaml", func() error {
			d, err := rules.LoadDetector(cfg.RulesDir)
			if err != nil {
				return err
			}
			scorer.SetRules(d)
			return nil
		})
		w.Register("ip_reputation.yaml", func() error {
			ir, err := rules.LoadIPReputation(cfg.RulesDir)
			if err != nil {
				return err
			}
			scorer.SetIPReputation(ir)
			return nil
		})
		w.Register("templates.yaml", func() error {
			v, err := rules.LoadTemplates(cfg.RulesDir)
			if err != nil {
				return err
			}
			templatesHolder.Store(v)
			return nil
		})
		w.Register("fake_data.yaml", func() error {
			v, err := rules.LoadFakeData(cfg.RulesDir)
			if err != nil {
				return err
			}
			fakeDataHolder.Store(v)
			return nil
		})
		w.Register("vulnerabilities.yaml", func() error {
			v, err := rules.LoadVulnerabilities(cfg.RulesDir)
			if err != nil {
				return err
			}
			vulnHolder.Store(v)
			return nil
		})
		w.Register("injection_strategy.yaml", func() error {
			v, err := rules.LoadInjectionStrategy(cfg.RulesDir)
			if err != nil {
				return err
			}
			strategyHolder.Store(v)
			return nil
		})
		w.Register("challenge.yaml", func() error {
			v, err := rules.LoadChallenge(cfg.RulesDir)
			if err != nil {
				return err
			}
			challengeHolder.Store(v)
			return nil
		})
		w.Register("ml.yaml", func() error {
			v, err := rules.LoadML(cfg.RulesDir)
			if err != nil {
				if auditLog != nil {
					_ = auditLog.Log(audit.Entry{Actor: "system", Action: "config.reload",
						Target: "ml.yaml", Outcome: "error", Detail: err.Error()})
				}
				return err
			}
			mlHolder.Store(v)
			// Reapply path redaction in case the operator updated the
			// custom regex list.
			if v.PathRedaction.Enabled {
				pr := ml.NewDefaultPathRedactor()
				for _, c := range v.PathRedaction.Custom {
					pr.AddCustom(c.Regex, c.Replace)
				}
				ml.SetActiveRedactor(pr)
			} else {
				ml.SetActiveRedactor(nil)
			}
			if auditLog != nil {
				_ = auditLog.Log(audit.Entry{Actor: "system", Action: "config.reload",
					Target: "ml.yaml", Outcome: "ok"})
			}
			return nil
		})
		w.Register("dashboard.yaml", func() error {
			v, err := rules.LoadDashboard(cfg.RulesDir)
			if err != nil {
				return err
			}
			dashboardHolder.Store(v)
			return nil
		})
		if tlsDB != nil {
			w.Register("tls_fingerprints.yaml", func() error {
				fp, err := rules.LoadTLS(cfg.RulesDir)
				if err != nil {
					return err
				}
				tlsDB.Apply(fp)
				return nil
			})
		}
		// learned.yaml + learned/ subdir — reload seeds the Bayes classifier.
		w.Register("learned.yaml", func() error {
			learned, err := rules.LoadLearned(cfg.RulesDir)
			if err != nil {
				return err
			}
			if n := mlScorer.SeedFromLearned(learned.Candidates); n > 0 {
				log.Info().Int("candidates", n).Msg("reseeded Bayes from learned rules")
			}
			return nil
		})
		// If learned/ subdirectory already exists, watch it so community
		// rule files added by update-rules hot-reload without a restart.
		if cfg.RulesDir != "" {
			learnedSubdir := filepath.Join(cfg.RulesDir, "learned")
			if info, err := os.Stat(learnedSubdir); err == nil && info.IsDir() {
				if err := w.AddSubdir(learnedSubdir, "learned.yaml"); err != nil {
					log.Warn().Err(err).Str("dir", learnedSubdir).Msg("could not watch learned/ subdir")
				}
			}
		}
		go w.Run(rootCtx, func(name string, err error) {
			log.Warn().Str("file", name).Err(err).Msg("rules reload")
		})
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.Handle("/", dash)

	mainSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	metricsSrv := &http.Server{
		Addr:              cfg.Metrics.Listen,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	go func() {
		log.Info().Str("addr", cfg.Listen).Bool("tls", cfg.TLS.Enabled).Msg("proxy listening")
		if cfg.TLS.Enabled {
			if err := listenTLS(mainSrv, cfg, tlsStore); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("proxy server")
			}
		} else {
			ln, err := net.Listen("tcp", cfg.Listen)
			if err != nil {
				log.Fatal().Err(err).Msg("proxy listen")
			}
			// Plain HTTP mode still accepts HTTP/2 clients via h2c. The
			// framing guard remains outside the HTTP server so ambiguous
			// HTTP/1.x CL/TE requests are rejected before net/http parses them,
			// while h2c prior-knowledge traffic is replayed into h2c.NewHandler.
			mainSrv.Handler = h2c.NewHandler(srv.Handler(), &http2.Server{})
			if err := mainSrv.Serve(proxy.NewFramingGuardListener(ln)); err != nil && err != http.ErrServerClosed {
				log.Fatal().Err(err).Msg("proxy server")
			}
		}
	}()
	go func() {
		log.Info().Str("addr", cfg.Metrics.Listen).Msg("metrics listening")
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("metrics server")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Info().Msg("shutting down")
	if auditLog != nil {
		_ = auditLog.Log(audit.Entry{Actor: "system", Action: "process.stop",
			Detail: "veilgate received SIGINT/SIGTERM"})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mainSrv.Shutdown(ctx)
	_ = metricsSrv.Shutdown(ctx)
}
