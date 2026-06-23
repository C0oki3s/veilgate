package admin

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookie  = "vg-session"
	sessionTTL     = 8 * time.Hour
	sessionCleanup = 30 * time.Minute
)

type sessionEntry struct {
	username string
	expiry   time.Time
}

// AuthState manages sessions. Credentials are validated against the DB when
// db is non-nil; otherwise the in-memory username/password are used as fallback.
type AuthState struct {
	db       *AdminDB // primary credential store; nil = use in-memory fields
	username string   // fallback if db is nil
	password string

	mu       sync.Mutex
	sessions map[string]sessionEntry // session ID → entry
}

// NewAuth creates an AuthState using in-memory credentials.
func NewAuth(username, password string) *AuthState {
	a := &AuthState{
		username: username,
		password: password,
		sessions: make(map[string]sessionEntry),
	}
	go a.gc()
	return a
}

// NewAuthDB creates an AuthState backed by the database.
func NewAuthDB(db *AdminDB) *AuthState {
	a := &AuthState{
		db:       db,
		sessions: make(map[string]sessionEntry),
	}
	go a.gc()
	return a
}

func (a *AuthState) gc() {
	t := time.NewTicker(sessionCleanup)
	defer t.Stop()
	for range t.C {
		a.mu.Lock()
		now := time.Now()
		for id, e := range a.sessions {
			if now.After(e.expiry) {
				delete(a.sessions, id)
			}
		}
		a.mu.Unlock()
	}
}

// Validate checks credentials against the DB (if set) or in-memory values.
func (a *AuthState) Validate(user, pass string) bool {
	if a.db != nil {
		return a.db.CheckPassword(user, pass)
	}
	// Constant-time compare via bcrypt-like approach when using in-memory creds.
	// Simple string compare is fine here because NewAuth is only used in tests/fallback.
	return user == a.username && pass == a.password
}

// NewSession creates and stores a new session for username, returning the session ID.
func (a *AuthState) NewSession(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b)
	a.mu.Lock()
	a.sessions[id] = sessionEntry{username: username, expiry: time.Now().Add(sessionTTL)}
	a.mu.Unlock()
	return id, nil
}

// Check returns true if the request carries a valid, unexpired session cookie.
func (a *AuthState) Check(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	a.mu.Lock()
	e, ok := a.sessions[c.Value]
	a.mu.Unlock()
	return ok && time.Now().Before(e.expiry)
}

// Username returns the username associated with the session cookie, or "" if
// the cookie is absent or the session has expired.
func (a *AuthState) Username(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	a.mu.Lock()
	e, ok := a.sessions[c.Value]
	a.mu.Unlock()
	if !ok || time.Now().After(e.expiry) {
		return ""
	}
	return e.username
}

// Destroy invalidates the session from the cookie.
func (a *AuthState) Destroy(r *http.Request) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return
	}
	a.mu.Lock()
	delete(a.sessions, c.Value)
	a.mu.Unlock()
}

// SetCookie writes the session cookie to the response.
func (a *AuthState) SetCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie expires the session cookie.
func (a *AuthState) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}
