package tlsfp

import (
	"encoding/binary"
	"errors"
	"io"
)

// ParseClientHello reads a TLS record from r and extracts fingerprint fields.
// It reads exactly one TLS record (the ClientHello) and returns both the parsed
// ClientHello and the raw bytes consumed, so the caller can replay them to
// the real TLS stack.
func ParseClientHello(r io.Reader) (*ClientHello, []byte, error) {
	// TLS record header: 5 bytes.
	// 0: content type (must be 0x16 = handshake)
	// 1-2: legacy record version
	// 3-4: record length
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, nil, err
	}
	if hdr[0] != 0x16 {
		return nil, hdr, errors.New("not a TLS handshake record")
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 4 || recLen > 65535 {
		return nil, hdr, errors.New("invalid TLS record length")
	}

	// Handshake message: 4-byte header + payload
	payload := make([]byte, recLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, append(hdr, payload[:0]...), err
	}
	raw := append(hdr, payload...)

	if payload[0] != 0x01 {
		return nil, raw, errors.New("not a ClientHello handshake message")
	}

	// Handshake body starts after 4 bytes: 1 type + 3 length
	if len(payload) < 4 {
		return nil, raw, errors.New("handshake too short")
	}
	body := payload[4:]

	ch := &ClientHello{}
	p := 0

	// client version (2 bytes)
	if len(body) < p+2 {
		return nil, raw, errors.New("short: client version")
	}
	ch.Version = binary.BigEndian.Uint16(body[p:])
	p += 2

	// random (32 bytes) — skip
	if len(body) < p+32 {
		return nil, raw, errors.New("short: random")
	}
	p += 32

	// session id (u8 length + bytes)
	if len(body) < p+1 {
		return nil, raw, errors.New("short: sid length")
	}
	sidLen := int(body[p])
	p += 1
	if len(body) < p+sidLen {
		return nil, raw, errors.New("short: sid")
	}
	p += sidLen

	// cipher suites (u16 length + u16 values)
	if len(body) < p+2 {
		return nil, raw, errors.New("short: ciphers length")
	}
	cLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if cLen%2 != 0 || len(body) < p+cLen {
		return nil, raw, errors.New("bad: ciphers")
	}
	ch.CipherSuites = readUint16s(body[p : p+cLen])
	p += cLen

	// compression methods (u8 length + bytes) — skip
	if len(body) < p+1 {
		return nil, raw, errors.New("short: compression length")
	}
	compLen := int(body[p])
	p += 1 + compLen
	if len(body) < p {
		return nil, raw, errors.New("short: compression")
	}

	// Extensions are optional in TLS 1.0 but present in ~all real clients.
	if len(body) < p+2 {
		return ch, raw, nil
	}
	extLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if len(body) < p+extLen {
		return ch, raw, errors.New("short: extensions")
	}
	extBytes := body[p : p+extLen]

	if err := parseExtensions(extBytes, ch); err != nil {
		return ch, raw, err
	}
	return ch, raw, nil
}

func parseExtensions(b []byte, ch *ClientHello) error {
	p := 0
	for p+4 <= len(b) {
		extType := binary.BigEndian.Uint16(b[p:])
		extLen := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+extLen > len(b) {
			return errors.New("extension overruns")
		}
		data := b[p : p+extLen]
		ch.Extensions = append(ch.Extensions, extType)

		switch extType {
		case 0x0000: // server_name
			if len(data) >= 5 {
				// server_name_list length (2), name_type (1), name_length (2), name
				nameLen := int(binary.BigEndian.Uint16(data[3:5]))
				if 5+nameLen <= len(data) {
					ch.SNI = string(data[5 : 5+nameLen])
				}
			}
		case 0x000a: // supported_groups (elliptic curves)
			if len(data) >= 2 {
				l := int(binary.BigEndian.Uint16(data[:2]))
				if 2+l <= len(data) {
					ch.EllipticCurves = readUint16s(data[2 : 2+l])
				}
			}
		case 0x000b: // ec_point_formats
			if len(data) >= 1 {
				l := int(data[0])
				if 1+l <= len(data) {
					ch.ECPointFormats = append(ch.ECPointFormats, data[1:1+l]...)
				}
			}
		case 0x000d: // signature_algorithms
			if len(data) >= 2 {
				l := int(binary.BigEndian.Uint16(data[:2]))
				if 2+l <= len(data) {
					ch.SignatureAlgos = readUint16s(data[2 : 2+l])
				}
			}
		case 0x0010: // application_layer_protocol_negotiation (ALPN)
			if len(data) >= 2 {
				l := int(binary.BigEndian.Uint16(data[:2]))
				if 2+l <= len(data) {
					inner := data[2 : 2+l]
					q := 0
					for q < len(inner) {
						pl := int(inner[q])
						q += 1
						if q+pl > len(inner) {
							break
						}
						ch.ALPNProtocols = append(ch.ALPNProtocols, string(inner[q:q+pl]))
						q += pl
					}
				}
			}
		case 0x002b: // supported_versions
			if len(data) >= 1 {
				l := int(data[0])
				if 1+l <= len(data) && l%2 == 0 {
					ch.SupportedVers = readUint16s(data[1 : 1+l])
				}
			}
		}
		p += extLen
	}
	return nil
}

func readUint16s(b []byte) []uint16 {
	out := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		out = append(out, binary.BigEndian.Uint16(b[i:]))
	}
	return out
}
