package proxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"
)

const maxFramingGuardHeaderBytes = 32 * 1024

// NewFramingGuardListener rejects ambiguous HTTP/1.x request framing before
// net/http normalizes it. This is intentionally narrow: it guards the
// CL+TE / malformed-TE class that can otherwise become request smuggling
// when a frontend and upstream disagree about body length.
func NewFramingGuardListener(inner net.Listener) net.Listener {
	return &framingGuardListener{inner: inner}
}

type framingGuardListener struct {
	inner net.Listener
}

func (l *framingGuardListener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &framingGuardConn{Conn: c}, nil
}

func (l *framingGuardListener) Close() error   { return l.inner.Close() }
func (l *framingGuardListener) Addr() net.Addr { return l.inner.Addr() }

type framingGuardConn struct {
	net.Conn
	checked bool
	replay  *bytes.Reader
	closed  bool
}

func (c *framingGuardConn) Read(p []byte) (int, error) {
	if !c.checked {
		c.checked = true
		c.checkFirstRequest()
	}
	if c.closed {
		return 0, io.EOF
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

func (c *framingGuardConn) checkFirstRequest() {
	if stateConn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		if stateConn.ConnectionState().NegotiatedProtocol == "h2" {
			// HTTP/2 framing is handled by the HTTP/2 stack. This guard only
			// examines raw HTTP/1.x request headers before net/http normalizes
			// them, which is where CL/TE request-smuggling ambiguity lives.
			return
		}
	}
	_ = c.Conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.Conn.SetReadDeadline(time.Time{})

	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for buf.Len() < maxFramingGuardHeaderBytes {
		n, err := c.Conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.Contains(buf.Bytes(), []byte("\r\n\r\n")) {
				break
			}
		}
		if err != nil {
			c.replay = bytes.NewReader(buf.Bytes())
			return
		}
	}
	raw := buf.Bytes()
	c.replay = bytes.NewReader(raw)
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return
	}
	if badHTTPRequestFraming(raw[:headerEnd]) {
		_, _ = c.Conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		_ = c.Conn.Close()
		c.closed = true
		c.replay = nil
	}
}

func badHTTPRequestFraming(header []byte) bool {
	lines := strings.Split(string(header), "\r\n")
	if len(lines) == 0 {
		return false
	}
	requestLine := lines[0]
	isHTTP10 := strings.HasSuffix(requestLine, "HTTP/1.0")
	isHTTP11 := strings.HasSuffix(requestLine, "HTTP/1.1")
	if !isHTTP10 && !isHTTP11 {
		return false
	}
	contentLengthCount := 0
	var transferCodings []string
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return true
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			contentLengthCount++
		case "transfer-encoding":
			for _, part := range strings.Split(value, ",") {
				if coding := strings.ToLower(strings.TrimSpace(part)); coding != "" {
					transferCodings = append(transferCodings, coding)
				}
			}
		}
	}
	if contentLengthCount > 1 {
		return true
	}
	if len(transferCodings) == 0 {
		return false
	}
	if isHTTP10 || contentLengthCount > 0 {
		return true
	}
	return len(transferCodings) != 1 || transferCodings[0] != "chunked"
}
