package persist

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGO
)

// Event is one captured request. Superset of telemetry.CaptureEvent plus
// the ML features_json column so the classifier can replay history
// without recomputing extractors.
type Event struct {
	Time         time.Time
	ClientID     string
	Method       string
	Path         string
	UserAgent    string
	HeaderBitmap int64
	JA3          string
	JA4          string
	Score        int
	Signals      []string
	Decision     string
	FeaturesJSON string // already-encoded feature vector from ml.Extract
}

// RollupDelta is one (feature, bucket, label) increment applied by the
// scorer whenever it assigns a weak label. Keeping the update local to
// the classifier loop avoids a second pass over events later.
type RollupDelta struct {
	Feature string
	Bucket  string
	Label   string // "agent" or "human"
}

// Candidate is one rule candidate emitted by the miner. Active flags
// and first_seen are persisted across restarts so operator promotions
// survive even if rules/learned.yaml is deleted.
type Candidate struct {
	Feature    string
	Bucket     string
	Posterior  float64
	Support    int
	Active     bool
	ProposedAt string
	FirstSeen  string
}

// Store is the SQLite-backed event sink and query layer.
//
// Writes are async: Record enqueues onto a buffered channel and a single
// goroutine batch-commits every flushInterval. This keeps the proxy hot
// path free of disk latency; when the queue saturates we drop with a
// metric so the proxy never blocks.
type Store struct {
	db            *sql.DB
	queue         chan Event
	rollupQueue   chan RollupDelta
	flushInterval time.Duration
	dropped       uint64
	wg            sync.WaitGroup
	stop          chan struct{}
}

// Config drives Open. All fields have sane zero-value defaults.
type Config struct {
	Path          string        // file path; ":memory:" allowed
	QueueSize     int           // default 4096
	FlushInterval time.Duration // default 1s
	WalMB         int           // page cache size in MB, default 64
}

// Open creates the database file if missing, runs migrations, and
// launches the background flusher.
func Open(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("persist: empty path")
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 4096
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	if cfg.WalMB <= 0 {
		cfg.WalMB = 64
	}
	if cfg.Path != ":memory:" {
		abs, err := filepath.Abs(cfg.Path)
		if err == nil {
			cfg.Path = abs
		}
		if dir := filepath.Dir(cfg.Path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("persist: mkdir %s: %w", dir, err)
			}
		}
	}

	// modernc.org/sqlite uses URI parameters via ?_pragma=...
	//
	// Pragma rationale:
	//   - journal_mode=WAL: better concurrency, the proxy is a single
	//     writer + (eventually) many readers via the dashboard.
	//   - synchronous=NORMAL: durability/throughput trade-off, fine for
	//     telemetry-class data; we never claim the WAL is fsync'd per row.
	//   - busy_timeout=5000: belt-and-braces for any read that races a
	//     drain commit.
	//   - cache_size=-<KiB>: negative means "KiB", not pages. 64 MB default.
	//   - temp_store=MEMORY: keep ORDER BY / GROUP BY scratch off disk —
	//     the dashboard's drift queries notice.
	//   - mmap_size=<bytes>: 512 MB by default, lets the kernel page cache
	//     handle hot reads without copying through SQLite's own cache.
	pragmas := url.Values{}
	pragmas.Add("_pragma", "journal_mode=WAL")
	pragmas.Add("_pragma", "synchronous=NORMAL")
	pragmas.Add("_pragma", "busy_timeout=5000")
	pragmas.Add("_pragma", fmt.Sprintf("cache_size=-%d", cfg.WalMB*1024))
	pragmas.Add("_pragma", "temp_store=MEMORY")
	pragmas.Add("_pragma", "mmap_size=536870912") // 512 MiB
	dsn := "file:" + cfg.Path + "?" + pragmas.Encode()

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("persist: open: %w", err)
	}
	// Single writer keeps WAL happy and makes batch commits predictable.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(ddl); err != nil {
		db.Close()
		return nil, fmt.Errorf("persist: ddl: %w", err)
	}
	if cfg.Path != ":memory:" {
		_ = os.Chmod(cfg.Path, 0o600)
	}
	if err := ensureCandidateColumns(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("persist: migrate rule_candidates: %w", err)
	}
	if err := recordSchemaVersion(db); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{
		db:            db,
		queue:         make(chan Event, cfg.QueueSize),
		rollupQueue:   make(chan RollupDelta, cfg.QueueSize),
		flushInterval: cfg.FlushInterval,
		stop:          make(chan struct{}),
	}
	s.wg.Add(1)
	go s.flusher()
	return s, nil
}

func recordSchemaVersion(db *sql.DB) error {
	var have int
	row := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`)
	if err := row.Scan(&have); err != nil {
		return fmt.Errorf("persist: read schema version: %w", err)
	}
	if have >= schemaVersion {
		return nil
	}
	_, err := db.Exec(
		`INSERT INTO schema_version (version, applied_at) VALUES (?, ?)`,
		schemaVersion, time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// Record enqueues an event. Drops (with a counter bump) when the queue
// is full — the proxy must never block on disk.
func (s *Store) Record(e Event) {
	if s == nil {
		return
	}
	select {
	case s.queue <- e:
	default:
		s.dropped++
	}
}

// RollupUpdate enqueues a feature-rollup delta. Same drop-on-full policy.
func (s *Store) RollupUpdate(d RollupDelta) {
	if s == nil || d.Label == "" {
		return
	}
	select {
	case s.rollupQueue <- d:
	default:
		s.dropped++
	}
}

// Dropped returns the cumulative count of events dropped due to back-pressure.
func (s *Store) Dropped() uint64 { return s.dropped }

func (s *Store) flusher() {
	defer s.wg.Done()
	t := time.NewTicker(s.flushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			s.drain()
			return
		case <-t.C:
			s.drain()
		}
	}
}

// drain commits every queued event + rollup in one transaction.
// Draining on ticks amortizes fsync and keeps write amplification low.
func (s *Store) drain() {
	// Snapshot both queues without blocking producers.
	var evs []Event
	for {
		select {
		case e := <-s.queue:
			evs = append(evs, e)
		default:
			goto rollupDrain
		}
	}
rollupDrain:
	var deltas []RollupDelta
	for {
		select {
		case d := <-s.rollupQueue:
			deltas = append(deltas, d)
		default:
			goto commit
		}
	}
commit:
	if len(evs) == 0 && len(deltas) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	if len(evs) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO events
			(ts, client_id, method, path, user_agent, header_bitmap, ja3, ja4,
			 score, signals_json, decision, features_json)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			tx.Rollback()
			return
		}
		for _, e := range evs {
			sigJSON, _ := json.Marshal(e.Signals)
			if _, err := stmt.Exec(
				e.Time.UTC().Format(time.RFC3339Nano),
				e.ClientID, e.Method, e.Path, e.UserAgent, e.HeaderBitmap,
				e.JA3, e.JA4, e.Score, string(sigJSON), e.Decision, e.FeaturesJSON,
			); err != nil {
				// keep draining — one bad row shouldn't abort the batch.
				continue
			}
		}
		stmt.Close()
	}
	if len(deltas) > 0 {
		now := time.Now().UTC().Format(time.RFC3339)
		for _, d := range deltas {
			col := "human_count"
			if d.Label == "agent" {
				col = "agent_count"
			}
			_, _ = tx.Exec(`INSERT INTO features_rollup (feature, bucket, `+col+`, updated_at)
				VALUES (?, ?, 1, ?)
				ON CONFLICT(feature, bucket) DO UPDATE SET `+col+` = `+col+` + 1, updated_at = ?`,
				d.Feature, d.Bucket, now, now,
			)
		}
	}
	_ = tx.Commit()
}

// QueryRollup returns every rollup row; small table by design (bounded by
// the number of distinct feature-bucket pairs the detector sees).
func (s *Store) QueryRollup() ([]RollupRow, error) {
	rows, err := s.db.Query(`SELECT feature, bucket, agent_count, human_count FROM features_rollup`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RollupRow
	for rows.Next() {
		var r RollupRow
		if err := rows.Scan(&r.Feature, &r.Bucket, &r.AgentCount, &r.HumanCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RollupRow is one feature_rollup row.
type RollupRow struct {
	Feature    string
	Bucket     string
	AgentCount int
	HumanCount int
}

// RecentFeatures returns the last n events' features_json for IF retraining.
func (s *Store) RecentFeatures(n int) ([]string, error) {
	rows, err := s.db.Query(`SELECT features_json FROM events ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpsertCandidate writes one miner-proposed rule. Preserves the active
// flag and first_seen timestamp across re-proposals so operator
// promotions survive subsequent miner ticks.
func (s *Store) UpsertCandidate(c Candidate) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO rule_candidates
		(feature, bucket, posterior, support, proposed_at, status, active, first_seen)
		VALUES (?, ?, ?, ?, ?, 'pending', 0, ?)
		ON CONFLICT(feature, bucket) DO UPDATE SET
			posterior   = excluded.posterior,
			support     = excluded.support,
			proposed_at = excluded.proposed_at`,
		c.Feature, c.Bucket, c.Posterior, c.Support, now, now,
	)
	return err
}

// SetCandidateActive flips the active flag on an existing candidate.
// Called by the miner when it picks up an `active: true` change from a
// hand-edited learned.yaml, so the flag is durable in SQLite too.
func (s *Store) SetCandidateActive(feature, bucket string, active bool) error {
	a := 0
	if active {
		a = 1
	}
	_, err := s.db.Exec(`UPDATE rule_candidates SET active = ? WHERE feature = ? AND bucket = ?`,
		a, feature, bucket,
	)
	return err
}

// ListCandidates returns pending rule candidates sorted by posterior DESC.
// Kept for API compatibility; callers that need the active flag should
// use ListAllCandidates.
func (s *Store) ListCandidates() ([]Candidate, error) {
	return s.queryCandidates(`WHERE status = 'pending' ORDER BY posterior DESC, support DESC`)
}

// ListAllCandidates returns every candidate including active state and
// timestamps. Active rows float to the top so operator-promoted entries
// are easy to spot when rendering learned.yaml.
func (s *Store) ListAllCandidates() ([]Candidate, error) {
	return s.queryCandidates(`ORDER BY active DESC, posterior DESC, support DESC`)
}

func (s *Store) queryCandidates(tail string) ([]Candidate, error) {
	rows, err := s.db.Query(`SELECT feature, bucket, posterior, support, active,
		COALESCE(proposed_at, ''), COALESCE(first_seen, proposed_at, '')
		FROM rule_candidates ` + tail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Candidate
	for rows.Next() {
		var c Candidate
		var active int
		if err := rows.Scan(&c.Feature, &c.Bucket, &c.Posterior, &c.Support, &active, &c.ProposedAt, &c.FirstSeen); err != nil {
			return nil, err
		}
		c.Active = active == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ensureCandidateColumns applies the v2 migration idempotently so
// pre-v2 databases pick up active/first_seen without manual SQL.
func ensureCandidateColumns(db *sql.DB) error {
	rows, err := db.Query(`PRAGMA table_info(rule_candidates)`)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt interface{}
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	if !have["active"] {
		if _, err := db.Exec(`ALTER TABLE rule_candidates ADD COLUMN active INTEGER NOT NULL DEFAULT 0`); err != nil {
			return err
		}
	}
	if !have["first_seen"] {
		if _, err := db.Exec(`ALTER TABLE rule_candidates ADD COLUMN first_seen TEXT`); err != nil {
			return err
		}
	}
	return nil
}

// Trim deletes events older than cutoff. Runs inside a single transaction.
// Returns number of rows removed.
func (s *Store) Trim(cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM events WHERE ts < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Close flushes the queue and closes the database.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	close(s.stop)
	s.wg.Wait()
	return s.db.Close()
}

// ForgetClient deletes every row anywhere in the schema that's keyed
// by the given client identifier. Used by the `veilgate forget` CLI to
// satisfy a GDPR right-to-be-forgotten request without manual SQL.
//
// Bayes/IF state lives in RAM and is wiped naturally on the next
// process restart — operators are expected to schedule one after a
// forget, and the function deliberately does not try to mutate
// in-flight RAM state across packages (that would require an
// import-cycle-breaking interface and is easier to reason about as a
// restart-after-forget operational rule).
//
// Returns the total rows deleted across all touched tables.
func (s *Store) ForgetClient(clientID string) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	var total int64
	stmts := []string{
		`DELETE FROM events WHERE client_id = ?`,
		`DELETE FROM tarpit_canaries WHERE client_id = ?`,
	}
	for _, q := range stmts {
		res, err := tx.Exec(q, clientID)
		if err != nil {
			_ = tx.Rollback()
			return total, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			total += n
		}
	}
	if err := tx.Commit(); err != nil {
		return total, err
	}
	return total, nil
}

// AppendAudit writes one audit_log row. Implements the SQLWriter
// interface in the audit package.
func (s *Store) AppendAudit(ts time.Time, actor, action, target, outcome, detail, meta, prevHash, hash string) error {
	if s == nil || s.db == nil {
		return nil
	}
	_, err := s.db.Exec(`INSERT INTO audit_log
		(ts, actor, action, target, outcome, detail, meta_json, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts.UTC().Format(time.RFC3339Nano),
		actor, action, target, outcome, detail, meta, prevHash, hash,
	)
	return err
}

// LastAuditHash returns the most recent audit_log entry's hash so the
// caller can seed an audit.Logger to keep the chain contiguous across
// process restarts. Returns "" when the table is empty.
func (s *Store) LastAuditHash() string {
	if s == nil || s.db == nil {
		return ""
	}
	var h string
	row := s.db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&h); err != nil {
		return ""
	}
	return h
}

// CanaryRow is one tarpit_canaries row. Exported so callers across
// packages can pass them around without re-quoting columns.
type CanaryRow struct {
	Token     string
	ClientID  string
	ServedAt  time.Time
	ExpiresAt time.Time
	Hits      int
	LastHitAt time.Time
	LastHitBy string
}

// InsertCanary records a token the tarpit served to clientID. Caller
// supplies the TTL — typically 24h. Idempotent on token (replaces).
func (s *Store) InsertCanary(token, clientID string, ttl time.Duration) error {
	if s == nil || s.db == nil || token == "" {
		return nil
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)
	_, err := s.db.Exec(`INSERT INTO tarpit_canaries
		(token, client_id, served_at, expires_at, hits)
		VALUES (?, ?, ?, ?, 0)
		ON CONFLICT(token) DO UPDATE SET
			client_id  = excluded.client_id,
			served_at  = excluded.served_at,
			expires_at = excluded.expires_at`,
		token, clientID, now.Format(time.RFC3339Nano), exp.Format(time.RFC3339Nano),
	)
	return err
}

// HitCanary reports whether a request from clientID carries one of our
// previously-served canary tokens. When it does, the row is updated
// (hit count, last seen) and the original-issued ClientID is returned
// so the caller can decide whether the same client is replaying or a
// different client is reusing leaked data — both are bad, but the
// reasons differ.
func (s *Store) HitCanary(token, clientID string) (CanaryRow, bool, error) {
	if s == nil || s.db == nil || token == "" {
		return CanaryRow{}, false, nil
	}
	row := s.db.QueryRow(`SELECT token, client_id, served_at, expires_at, hits, COALESCE(last_hit_at, ''), COALESCE(last_hit_by, '')
		FROM tarpit_canaries WHERE token = ?`, token)
	var r CanaryRow
	var served, exp, lastAt string
	if err := row.Scan(&r.Token, &r.ClientID, &served, &exp, &r.Hits, &lastAt, &r.LastHitBy); err != nil {
		if err == sql.ErrNoRows {
			return CanaryRow{}, false, nil
		}
		return CanaryRow{}, false, err
	}
	r.ServedAt, _ = time.Parse(time.RFC3339Nano, served)
	r.ExpiresAt, _ = time.Parse(time.RFC3339Nano, exp)
	if lastAt != "" {
		r.LastHitAt, _ = time.Parse(time.RFC3339Nano, lastAt)
	}
	if r.ExpiresAt.Before(time.Now().UTC()) {
		// Expired — treat as not-found, but don't bother deleting here;
		// the maintenance goroutine sweeps stale rows.
		return CanaryRow{}, false, nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = s.db.Exec(`UPDATE tarpit_canaries
		SET hits = hits + 1, last_hit_at = ?, last_hit_by = ?
		WHERE token = ?`, now, clientID, token)
	r.Hits++
	r.LastHitAt = time.Now().UTC()
	r.LastHitBy = clientID
	return r, true, nil
}

// CanaryProbe is a thin adapter over HitCanary that matches the
// detector.CanaryLookup interface — it returns just the original-issued
// clientID and a hit boolean. Errors are swallowed because the
// detector hot path can't usefully act on a transient SQL failure
// other than to skip the signal for this request.
func (s *Store) CanaryProbe(token, clientID string) (string, bool) {
	if s == nil {
		return "", false
	}
	row, hit, err := s.HitCanary(token, clientID)
	if err != nil || !hit {
		return "", false
	}
	return row.ClientID, true
}

// CanaryGC deletes expired canary rows. Called from the maintenance
// goroutine; no-op when nothing's expired.
func (s *Store) CanaryGC() (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	res, err := s.db.Exec(`DELETE FROM tarpit_canaries WHERE expires_at < ?`,
		time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Maintenance runs periodic housekeeping: WAL checkpoint truncation
// (so the WAL doesn't grow unbounded under sustained load) and canary
// GC. Designed to be launched once from main.go in a background
// goroutine — blocks until ctx is done.
func (s *Store) Maintenance(ctx context.Context, every time.Duration, onError func(error)) {
	if s == nil {
		return
	}
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil && onError != nil {
				onError(fmt.Errorf("wal_checkpoint: %w", err))
			}
			if _, err := s.CanaryGC(); err != nil && onError != nil {
				onError(fmt.Errorf("canary_gc: %w", err))
			}
		}
	}
}
