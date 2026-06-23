package admin

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const dbSchema = `
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    must_change   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE TABLE IF NOT EXISTS reset_tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT    NOT NULL,
    token      TEXT    NOT NULL UNIQUE,
    expires_at TEXT    NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     TEXT    NOT NULL,
    user   TEXT    NOT NULL DEFAULT '',
    ip     TEXT    NOT NULL DEFAULT '',
    action TEXT    NOT NULL,
    detail TEXT    NOT NULL DEFAULT '',
    ok     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit_log (id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action);
`

// migrations adds columns to existing databases that pre-date the schema above.
// Each statement is idempotent via ALTER TABLE … IF NOT EXISTS (not supported by
// old SQLite) so we ignore errors — the column either already exists or is new.
var migrations = []string{
	`ALTER TABLE users ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0`,
	`CREATE TABLE IF NOT EXISTS reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
        token TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)`,
}

// AdminDB is the SQLite-backed store for users and audit events.
type AdminDB struct {
	db *sql.DB
}

// OpenDB opens (or creates) the SQLite database at path.
func OpenDB(path string) (*AdminDB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_foreign_keys=on&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("db open: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(dbSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("db schema: %w", err)
	}
	d := &AdminDB{db: db}
	d.runMigrations()
	return d, nil
}

func (d *AdminDB) runMigrations() {
	for _, m := range migrations {
		d.db.Exec(m) //nolint:errcheck // ignore "duplicate column" errors on existing DBs
	}
}

func (d *AdminDB) Close() error { return d.db.Close() }

// ── Users ──────────────────────────────────────────────────────────────────

// HasUsers reports whether any users exist in the database.
func (d *AdminDB) HasUsers() bool {
	var n int
	d.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n) //nolint:errcheck
	return n > 0
}

// UpsertUser creates or replaces the password for username, optionally setting
// the must_change flag (true = force password reset on next login).
func (d *AdminDB) UpsertUser(username, plainPassword string, mustChange ...bool) error {
	if username == "" || plainPassword == "" {
		return fmt.Errorf("username and password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	mc := 0
	if len(mustChange) > 0 && mustChange[0] {
		mc = 1
	}
	_, err = d.db.Exec(`
		INSERT INTO users (username, password_hash, must_change) VALUES (?, ?, ?)
		ON CONFLICT(username) DO UPDATE SET
			password_hash = excluded.password_hash,
			must_change   = excluded.must_change
	`, username, string(hash), mc)
	return err
}

// CheckPassword returns true if username exists and plain matches the stored hash.
func (d *AdminDB) CheckPassword(username, plain string) bool {
	var hash string
	if err := d.db.QueryRow(
		`SELECT password_hash FROM users WHERE username = ?`, username,
	).Scan(&hash); err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// MustChange reports whether the user must change their password before
// accessing any other page.
func (d *AdminDB) MustChange(username string) bool {
	var mc int
	d.db.QueryRow(`SELECT must_change FROM users WHERE username = ?`, username).Scan(&mc) //nolint:errcheck
	return mc == 1
}

// ChangePassword updates the stored hash and clears must_change.
// Returns an error when currentPlain does not match the existing hash.
func (d *AdminDB) ChangePassword(username, currentPlain, newPlain string) error {
	if !d.CheckPassword(username, currentPlain) {
		return fmt.Errorf("current password is incorrect")
	}
	if len(newPlain) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPlain), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	_, err = d.db.Exec(
		`UPDATE users SET password_hash = ?, must_change = 0 WHERE username = ?`,
		string(hash), username,
	)
	return err
}

// ── Password-reset tokens ──────────────────────────────────────────────────

const resetTokenTTL = 1 * time.Hour

// CreateResetToken mints a 32-byte hex reset token for the user and persists
// it with a 1-hour expiry. Any previous unused tokens for the same user are
// invalidated first. Returns the raw token string.
func (d *AdminDB) CreateResetToken(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	token := hex.EncodeToString(b)
	exp := time.Now().Add(resetTokenTTL).UTC().Format(time.RFC3339)

	// Invalidate prior tokens for this user so only the latest works.
	d.db.Exec(`DELETE FROM reset_tokens WHERE username = ?`, username) //nolint:errcheck

	_, err := d.db.Exec(
		`INSERT INTO reset_tokens (username, token, expires_at) VALUES (?, ?, ?)`,
		username, token, exp,
	)
	return token, err
}

// ConsumeResetToken validates the token and, if valid, resets the password to
// newPlain and clears must_change. Returns an error on invalid/expired tokens.
func (d *AdminDB) ConsumeResetToken(token, newPlain string) error {
	if len(newPlain) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	var username, expiresAt string
	var used int
	err := d.db.QueryRow(
		`SELECT username, expires_at, used FROM reset_tokens WHERE token = ?`, token,
	).Scan(&username, &expiresAt, &used)
	if err != nil {
		return fmt.Errorf("invalid or expired reset link")
	}
	if used == 1 {
		return fmt.Errorf("this reset link has already been used")
	}
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().After(exp) {
		return fmt.Errorf("reset link has expired (valid for 1 hour)")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(newPlain), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	tx.Exec(`UPDATE users SET password_hash = ?, must_change = 0 WHERE username = ?`, string(hash), username) //nolint:errcheck
	tx.Exec(`UPDATE reset_tokens SET used = 1 WHERE token = ?`, token)                                        //nolint:errcheck
	return tx.Commit()
}

// UsernameByResetToken returns the username associated with a token so the
// reset form can display who is resetting (without consuming the token).
func (d *AdminDB) UsernameByResetToken(token string) (string, error) {
	var username, expiresAt string
	var used int
	if err := d.db.QueryRow(
		`SELECT username, expires_at, used FROM reset_tokens WHERE token = ?`, token,
	).Scan(&username, &expiresAt, &used); err != nil {
		return "", fmt.Errorf("invalid or expired reset link")
	}
	if used == 1 {
		return "", fmt.Errorf("this reset link has already been used")
	}
	exp, _ := time.Parse(time.RFC3339, expiresAt)
	if time.Now().After(exp) {
		return "", fmt.Errorf("reset link has expired")
	}
	return username, nil
}

// ── Audit ──────────────────────────────────────────────────────────────────

// WriteAudit appends one row to audit_log.
func (d *AdminDB) WriteAudit(ts, user, ip, action, detail string, ok bool) {
	okInt := 0
	if ok {
		okInt = 1
	}
	d.db.Exec(`INSERT INTO audit_log (ts, user, ip, action, detail, ok) VALUES (?,?,?,?,?,?)`, //nolint:errcheck
		ts, user, ip, action, detail, okInt)
}

// ReadAudit returns up to n most-recent audit entries (newest first).
func (d *AdminDB) ReadAudit(n int) ([]AuditEntry, error) {
	if n <= 0 {
		n = 500
	}
	rows, err := d.db.Query(`
		SELECT ts, user, ip, action, detail, ok
		FROM audit_log
		ORDER BY id DESC
		LIMIT ?
	`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var okInt int
		if err := rows.Scan(&e.Time, &e.User, &e.IP, &e.Action, &e.Detail, &okInt); err != nil {
			continue
		}
		e.OK = okInt == 1
		out = append(out, e)
	}
	return out, rows.Err()
}

// AuditStatsDB returns summary counters from the database.
func (d *AdminDB) AuditStatsDB() AuditStats {
	var s AuditStats
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&s.Total)                                            //nolint:errcheck
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE ok = 0`).Scan(&s.Failures)                            //nolint:errcheck
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'login'`).Scan(&s.Logins)                   //nolint:errcheck
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'settings.save'`).Scan(&s.ConfigSaves)      //nolint:errcheck
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'rule.save'`).Scan(&s.RuleSaves)            //nolint:errcheck
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'signals.save'`).Scan(&s.SignalSaves)       //nolint:errcheck
	d.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'openapi.import'`).Scan(&s.OpenAPISaves)    //nolint:errcheck
	return s
}
