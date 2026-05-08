package tlsfp

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"sync"
	"time"
)

// Store keeps per-remote-address fingerprints with TTL.
type Store struct {
	mu      sync.RWMutex
	entries map[string]entry
	ttl     time.Duration
}

type entry struct {
	Fingerprint Fingerprint
	At          time.Time
}

// Fingerprint is what the detector reads.
type Fingerprint struct {
	JA3 string
	JA4 string
	SNI string
}

func NewStore(ttl time.Duration) *Store {
	if ttl == 0 {
		ttl = 10 * time.Minute
	}
	return &Store{entries: make(map[string]entry), ttl: ttl}
}

func (s *Store) Put(remote string, fp Fingerprint) {
	s.mu.Lock()
	s.entries[remote] = entry{Fingerprint: fp, At: time.Now()}
	s.mu.Unlock()
}

func (s *Store) Get(remote string) (Fingerprint, bool) {
	s.mu.RLock()
	e, ok := s.entries[remote]
	s.mu.RUnlock()
	if !ok {
		return Fingerprint{}, false
	}
	if time.Since(e.At) > s.ttl {
		return Fingerprint{}, false
	}
	return e.Fingerprint, true
}

func (s *Store) GC() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.entries {
		if now.Sub(v.At) > s.ttl {
			delete(s.entries, k)
		}
	}
}

// Listener wraps a net.Listener. On each Accept it peeks the ClientHello,
// computes JA3/JA4, stores them keyed by remote address, then returns a
// connection whose Read replays the bytes so Go's TLS stack sees them.
type Listener struct {
	inner net.Listener
	store *Store
}

func NewListener(inner net.Listener, store *Store) *Listener {
	return &Listener{inner: inner, store: store}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &sniffConn{Conn: c, store: l.store}, nil
}

func (l *Listener) Close() error   { return l.inner.Close() }
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// sniffConn parses the ClientHello on first Read, then acts as a pass-through.
type sniffConn struct {
	net.Conn
	store    *Store
	replay   *bytes.Reader // replay buffer for the bytes we consumed
	sniffed  bool
	sniffErr error
}

func (c *sniffConn) Read(p []byte) (int, error) {
	if !c.sniffed {
		c.sniffed = true
		c.doSniff()
	}
	if c.replay != nil && c.replay.Len() > 0 {
		n, err := c.replay.Read(p)
		if err == io.EOF {
			c.replay = nil
			err = nil
		}
		if n > 0 || err != nil {
			return n, err
		}
	}
	return c.Conn.Read(p)
}

func (c *sniffConn) doSniff() {
	// Give ourselves a bounded time to peek — don't hang forever on slow clients.
	_ = c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})

	var buf bytes.Buffer
	tee := io.TeeReader(c.Conn, &buf)
	ch, _, err := ParseClientHello(tee)
	c.replay = bytes.NewReader(buf.Bytes())
	if err != nil || ch == nil {
		c.sniffErr = err
		return
	}
	fp := Fingerprint{JA3: JA3(ch), JA4: JA4(ch), SNI: ch.SNI}
	c.store.Put(c.Conn.RemoteAddr().String(), fp)
}

// WrapTLSConfig is a helper that returns a tls.Config clone with GetConfigForClient
// set to nothing special — provided for symmetry with other designs that use it.
// We don't need it here since we capture at the listener layer, but keeping this
// makes the integration surface explicit for readers.
func WrapTLSConfig(base *tls.Config) *tls.Config {
	if base == nil {
		return &tls.Config{}
	}
	return base.Clone()
}
