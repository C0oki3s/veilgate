package tarpit

import (
	"crypto/sha256"
	"encoding/binary"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// ShadowProfile is a fake app instance bound to one client.
// Every request from that client sees a consistent fake reality.
type ShadowProfile struct {
	ClientID      string
	Seed          int64
	CreatedAt     time.Time
	LastSeen      time.Time
	Visits        int
	FakeVersion   string
	FakeStack     string
	FakeAdminUser string
	FakeAdminPass string
	FakeCompany   string
	// Slug is the lowercased, punctuation-stripped first word of FakeCompany
	// — used by templates like env_backup / git_config where a filesystem-safe
	// identifier is required.
	Slug string
}

// ProfileStore creates and retrieves profiles keyed by client ID.
type ProfileStore struct {
	mu       sync.RWMutex
	profiles map[string]*ShadowProfile
	data     *rules.Holder[rules.FakeData]
}

// NewProfileStore builds a store backed by embedded fake-data defaults.
// Call SetFakeData to swap in a hot-reloadable holder.
func NewProfileStore() *ProfileStore {
	fd, _ := rules.LoadFakeData("")
	return &ProfileStore{
		profiles: make(map[string]*ShadowProfile),
		data:     rules.NewHolder(fd),
	}
}

// SetFakeData swaps in a rules holder. Existing profiles keep whatever
// they already drew from the old pool — determinism trumps freshness.
func (s *ProfileStore) SetFakeData(h *rules.Holder[rules.FakeData]) {
	if s == nil || h == nil {
		return
	}
	s.data = h
}

func (s *ProfileStore) Get(clientID string) *ShadowProfile {
	s.mu.RLock()
	p, ok := s.profiles[clientID]
	s.mu.RUnlock()
	if ok {
		p.LastSeen = time.Now()
		p.Visits++
		return p
	}
	return s.create(clientID)
}

func (s *ProfileStore) create(clientID string) *ShadowProfile {
	// Deterministic seed from clientID so restarts don't reset the illusion.
	h := sha256.Sum256([]byte(clientID))
	seed := int64(binary.BigEndian.Uint64(h[:8]))
	r := rand.New(rand.NewSource(seed))

	fd := s.data.Load()
	company := pick(fd.Companies, r, "Acme Corp")

	p := &ShadowProfile{
		ClientID:      clientID,
		Seed:          seed,
		CreatedAt:     time.Now(),
		LastSeen:      time.Now(),
		Visits:        1,
		FakeVersion:   pick(fd.Versions, r, "nginx/1.20.2"),
		FakeStack:     pick(fd.Stacks, r, "node-express"),
		FakeAdminUser: pick(fd.AdminUsers, r, "admin"),
		FakeAdminPass: pick(fd.AdminPasses, r, "password123"),
		FakeCompany:   company,
		Slug:          companySlug(company, fd.EmailDomains, r),
	}
	s.mu.Lock()
	s.profiles[clientID] = p
	s.mu.Unlock()
	return p
}

// Rand returns a deterministic *rand.Rand derived from the profile seed and salt.
// Use a distinct salt per response type to keep variety without losing consistency.
func (p *ShadowProfile) Rand(salt string) *rand.Rand {
	h := sha256.Sum256([]byte(p.ClientID + ":" + salt))
	s := int64(binary.BigEndian.Uint64(h[:8]))
	return rand.New(rand.NewSource(s))
}

// pick draws an element from xs using r; returns fallback on empty.
func pick(xs []string, r *rand.Rand, fallback string) string {
	if len(xs) == 0 {
		return fallback
	}
	return xs[r.Intn(len(xs))]
}

// companySlug returns a filesystem-safe identifier derived from the
// company name's first word. Falls back to an email-domain draw when the
// company name yields nothing usable.
func companySlug(company string, domains []string, r *rand.Rand) string {
	first := strings.ToLower(strings.Split(company, " ")[0])
	first = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, first)
	if first != "" {
		return first
	}
	return pick(domains, r, "example")
}
