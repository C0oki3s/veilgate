// Package tlsfp computes JA3 and JA4 TLS fingerprints from raw ClientHello bytes.
//
// JA4 spec: https://github.com/FoxIO-LLC/ja4
// JA3 spec: https://github.com/salesforce/ja3
//
// We parse the ClientHello ourselves rather than depending on Go's internal
// tls types because the stdlib strips too much by the time a handler runs.
package tlsfp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ClientHello is the minimal set of fields we need to compute fingerprints.
type ClientHello struct {
	Version         uint16   // e.g. 0x0303 = TLS 1.2 record version
	CipherSuites    []uint16
	Extensions      []uint16 // in the order they appeared
	EllipticCurves  []uint16
	ECPointFormats  []uint8
	SignatureAlgos  []uint16
	ALPNProtocols   []string // e.g. ["h2", "http/1.1"]
	SNI             string   // server name indication
	SupportedVers   []uint16 // from supported_versions extension (TLS 1.3)
}

// GREASE values per RFC 8701. These are decoy values clients inject to prevent
// middleboxes from ossifying protocol parsing. JA4 strips them; so do we.
var greaseSet = map[uint16]struct{}{
	0x0a0a: {}, 0x1a1a: {}, 0x2a2a: {}, 0x3a3a: {}, 0x4a4a: {}, 0x5a5a: {},
	0x6a6a: {}, 0x7a7a: {}, 0x8a8a: {}, 0x9a9a: {}, 0xaaaa: {}, 0xbaba: {},
	0xcaca: {}, 0xdada: {}, 0xeaea: {}, 0xfafa: {},
}

func isGREASE(v uint16) bool {
	_, ok := greaseSet[v]
	return ok
}

// JA3 returns the MD5-equivalent of the Salesforce JA3 fingerprint.
// We use SHA-256 truncated to 16 bytes hex to avoid pulling in md5 explicitly,
// but conventional JA3 is MD5. Swap to md5 if you want canonical compatibility.
// For our detection purposes a deterministic hash is all that matters.
func JA3(ch *ClientHello) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d,", ch.Version)

	b.WriteString(joinUint16(filterGREASE16(ch.CipherSuites), "-"))
	b.WriteString(",")
	b.WriteString(joinUint16(filterGREASE16(ch.Extensions), "-"))
	b.WriteString(",")
	b.WriteString(joinUint16(filterGREASE16(ch.EllipticCurves), "-"))
	b.WriteString(",")
	b.WriteString(joinUint8(ch.ECPointFormats, "-"))

	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:16])
}

// JA4 returns the FoxIO JA4 fingerprint: e.g. t13d1516h2_8daaf6152771_b186095e22b6
//
// Format: <protocol><tls_ver><sni><cipher_count><ext_count><alpn>_<cipher_hash>_<ext_sig_hash>
//   protocol:     "t" = tcp (TLS), "q" = QUIC
//   tls_ver:      highest negotiated version, 2 digits (10/11/12/13)
//   sni:          "d" if SNI present, "i" if not
//   cipher_count: 2-digit count of non-GREASE ciphers
//   ext_count:    2-digit count of non-GREASE extensions
//   alpn:         first and last char of first ALPN value, or "00" if none
func JA4(ch *ClientHello) string {
	ciphers := filterGREASE16(ch.CipherSuites)
	extensions := filterGREASE16(ch.Extensions)

	// Highest TLS version: prefer supported_versions (TLS 1.3), fallback to legacy.
	tlsVer := highestVersion(ch)

	sniFlag := "i"
	if ch.SNI != "" {
		sniFlag = "d"
	}

	alpn := "00"
	if len(ch.ALPNProtocols) > 0 {
		p := ch.ALPNProtocols[0]
		if len(p) >= 2 {
			alpn = string(p[0]) + string(p[len(p)-1])
		} else if len(p) == 1 {
			alpn = p + "0"
		}
	}

	cc := clamp2(len(ciphers))
	ec := clamp2(len(extensions))

	// JA4 prefix format: t<ver><sni><cc><ec><alpn>
	prefix := fmt.Sprintf("t%s%s%s%s%s", tlsVer, sniFlag, cc, ec, alpn)

	// _b: sorted, hex-joined ciphers -> truncated SHA-256 (12 hex chars)
	sortedCiphers := append([]uint16(nil), ciphers...)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	bHash := hash12(hexJoin16(sortedCiphers, ","))

	// _c: sorted extensions (excluding SNI=0 and ALPN=16 per JA4 spec)
	//     + "_" + signature algorithms in original order, joined with ","
	filtered := make([]uint16, 0, len(extensions))
	for _, e := range extensions {
		if e == 0x0000 || e == 0x0010 { // SNI, ALPN excluded from ext list
			continue
		}
		filtered = append(filtered, e)
	}
	sort.Slice(filtered, func(i, j int) bool { return filtered[i] < filtered[j] })
	cInput := hexJoin16(filtered, ",") + "_" + hexJoin16(ch.SignatureAlgos, ",")
	cHash := hash12(cInput)

	return prefix + "_" + bHash + "_" + cHash
}

// highestVersion returns the 2-char JA4 version code.
func highestVersion(ch *ClientHello) string {
	// supported_versions carries TLS 1.3.
	best := ch.Version
	for _, v := range ch.SupportedVers {
		if isGREASE(v) {
			continue
		}
		if v > best {
			best = v
		}
	}
	switch best {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3" // SSL 3.0
	}
	return "00"
}

func filterGREASE16(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func joinUint16(vs []uint16, sep string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func joinUint8(vs []uint8, sep string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%d", v)
	}
	return strings.Join(parts, sep)
}

func hexJoin16(vs []uint16, sep string) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, sep)
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6]) // 12 hex chars
}

func clamp2(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}
