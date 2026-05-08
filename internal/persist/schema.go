// Package persist is the SQLite-backed event store. It replaces the
// append-only JSONL capture with something the ML subsystem can actually
// query. Schema is kept small on purpose: three tables — events,
// features_rollup, rule_candidates — each with an obvious access pattern.
package persist

// ddl is the canonical schema. Applied in one shot on first open; version
// table lets future migrations skip already-applied steps.
const ddl = `
CREATE TABLE IF NOT EXISTS schema_version (
	version INTEGER PRIMARY KEY,
	applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	ts              TEXT    NOT NULL,
	client_id       TEXT    NOT NULL,
	method          TEXT    NOT NULL,
	path            TEXT    NOT NULL,
	user_agent      TEXT    NOT NULL,
	header_bitmap   INTEGER NOT NULL,
	ja3             TEXT,
	ja4             TEXT,
	score           INTEGER NOT NULL,
	signals_json    TEXT    NOT NULL,
	decision        TEXT    NOT NULL,
	features_json   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_client_ts ON events(client_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

-- One row per (feature_name, bucket_value). Running counts by weak label.
-- The miner scans this to propose rule candidates.
CREATE TABLE IF NOT EXISTS features_rollup (
	feature      TEXT    NOT NULL,
	bucket       TEXT    NOT NULL,
	agent_count  INTEGER NOT NULL DEFAULT 0,
	human_count  INTEGER NOT NULL DEFAULT 0,
	updated_at   TEXT    NOT NULL,
	PRIMARY KEY (feature, bucket)
);

CREATE TABLE IF NOT EXISTS rule_candidates (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	feature     TEXT    NOT NULL,
	bucket      TEXT    NOT NULL,
	posterior   REAL    NOT NULL,
	support     INTEGER NOT NULL,
	proposed_at TEXT    NOT NULL,
	status      TEXT    NOT NULL DEFAULT 'pending',
	active      INTEGER NOT NULL DEFAULT 0,
	first_seen  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cand_feat_bucket ON rule_candidates(feature, bucket);
CREATE INDEX IF NOT EXISTS idx_cand_active ON rule_candidates(active);

-- v3: audit_log. Append-only. Hash chain in (prev_hash, hash) so a
-- downstream verifier can detect deletions or rewrites.
CREATE TABLE IF NOT EXISTS audit_log (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	ts        TEXT    NOT NULL,
	actor     TEXT    NOT NULL,
	action    TEXT    NOT NULL,
	target    TEXT,
	outcome   TEXT    NOT NULL,
	detail    TEXT,
	meta_json TEXT,
	prev_hash TEXT    NOT NULL,
	hash      TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);

-- v3: tarpit_canaries. The tarpit sometimes serves a unique fake admin
-- token / fake admin URL to a visitor; if a later request carries that
-- token, the client almost certainly is an LLM agent regurgitating
-- earlier output. One row per (token, served-to-client). expires_at
-- lets a janitor prune stale rows.
CREATE TABLE IF NOT EXISTS tarpit_canaries (
	token       TEXT    PRIMARY KEY,
	client_id   TEXT    NOT NULL,
	served_at   TEXT    NOT NULL,
	expires_at  TEXT    NOT NULL,
	hits        INTEGER NOT NULL DEFAULT 0,
	last_hit_at TEXT,
	last_hit_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_canary_expires ON tarpit_canaries(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_client ON tarpit_canaries(client_id);
`

// v3 adds audit_log + tarpit_canaries on top of v2. Both tables are
// new so the migration is purely additive — no ALTER on existing rows.
const schemaVersion = 3
