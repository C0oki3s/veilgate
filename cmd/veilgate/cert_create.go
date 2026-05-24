package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runCertCreate is the handler for `veilgate cert-create`. It generates a
// self-signed TLS certificate suitable for enabling JA3/JA4 fingerprinting in
// veilgate (requires tls.enabled=true in veilgate.yaml), and optionally
// exports Cloudflare-compatible PEM files or prints PKCS#12 conversion
// instructions for importing into other servers.
//
// Why this exists: TLS fingerprinting (JA3/JA4) is the single strongest signal
// for distinguishing real browsers from browser-automation agents (Playwright,
// Puppeteer, Selenium). It requires veilgate to terminate TLS itself so it can
// inspect the ClientHello. This command makes cert generation a one-step
// operation with the correct SAN extensions rather than requiring manual
// openssl incantations.
func runCertCreate(args []string) {
	fs := flag.NewFlagSet("cert-create", flag.ExitOnError)
	domains := fs.String("domains", "", "comma-separated hostnames and IPs for the SAN (required)")
	outDir := fs.String("out", ".", "output directory for cert.pem and key.pem")
	keyType := fs.String("key-type", "ecdsa256", "key algorithm: ecdsa256 | ecdsa384 | rsa4096")
	days := fs.Int("days", 365, "certificate validity in days")
	certFile := fs.String("cert-file", "cert.pem", "output certificate filename")
	keyFile := fs.String("key-file", "key.pem", "output private key filename")
	cloudflare := fs.Bool("cloudflare", false, "also print Cloudflare import instructions and openssl PKCS#12 command")
	org := fs.String("org", "VeilGate", "organization name in the certificate subject")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `veilgate cert-create — generate a self-signed TLS certificate for JA3/JA4 fingerprinting

USAGE
  veilgate cert-create --domains <host>[,<host>...] [flags]

FLAGS
`)
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES
  # Single host, ECDSA-256
  veilgate cert-create --domains example.com

  # Multi-domain + IP SAN, RSA, custom validity
  veilgate cert-create --domains api.example.com,127.0.0.1 --key-type rsa4096 --days 730

  # With Cloudflare import instructions
  veilgate cert-create --domains example.com --cloudflare

PURPOSE
  Enables tls.enabled=true in veilgate.yaml so veilgate can terminate TLS
  and capture JA3/JA4 fingerprints from every ClientHello. This is the
  single highest-value detection signal for browser-automation agents
  (Playwright, Puppeteer, Selenium, Strix) that look browser-like at the
  HTTP layer.
`)
	}
	_ = fs.Parse(args)

	if *domains == "" {
		fmt.Fprintln(os.Stderr, "error: --domains is required")
		fs.Usage()
		os.Exit(1)
	}

	rawDomains := strings.Split(*domains, ",")
	var dnsNames []string
	var ipAddrs []net.IP
	for _, d := range rawDomains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if ip := net.ParseIP(d); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, d)
		}
	}
	if len(dnsNames) == 0 && len(ipAddrs) == 0 {
		fmt.Fprintln(os.Stderr, "error: --domains contains no valid hostnames or IPs")
		os.Exit(1)
	}

	// Generate the private key.
	privKey, pubKey, keyLabel, err := generateKey(*keyType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating key: %v\n", err)
		os.Exit(1)
	}

	// Build the certificate template.
	serialMax := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialMax)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error generating serial: %v\n", err)
		os.Exit(1)
	}

	now := time.Now().UTC()
	subjectCN := dnsNames[0]
	if len(dnsNames) == 0 && len(ipAddrs) > 0 {
		subjectCN = ipAddrs[0].String()
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization:       []string{*org},
			OrganizationalUnit: []string{"VeilGate TLS Fingerprinting"},
			CommonName:         subjectCN,
		},
		NotBefore: now.Add(-1 * time.Minute), // 1-min grace for clock skew
		NotAfter:  now.Add(time.Duration(*days) * 24 * time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		DNSNames:    dnsNames,
		IPAddresses: ipAddrs,
		// Basic constraints — mark as non-CA so browsers don't warn.
		IsCA:                  false,
		BasicConstraintsValid: true,
	}

	// Self-sign.
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pubKey, privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating certificate: %v\n", err)
		os.Exit(1)
	}

	// Marshal the private key.
	keyDER, keyPEMType, err := marshalPrivateKey(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling private key: %v\n", err)
		os.Exit(1)
	}

	// Write cert.pem
	certPath := filepath.Join(*outDir, *certFile)
	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", certPath, err)
		os.Exit(1)
	}
	fmt.Printf("cert:     %s\n", certPath)

	// Write key.pem
	keyPath := filepath.Join(*outDir, *keyFile)
	if err := writePEM(keyPath, keyPEMType, keyDER); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", keyPath, err)
		os.Exit(1)
	}
	// Restrict key file permissions so it's not world-readable.
	_ = os.Chmod(keyPath, 0600)
	fmt.Printf("key:      %s  (chmod 0600)\n", keyPath)

	fmt.Printf("key-type: %s\n", keyLabel)
	fmt.Printf("domains:  %s\n", strings.Join(append(dnsNames, func() []string {
		s := make([]string, len(ipAddrs))
		for i, ip := range ipAddrs {
			s[i] = ip.String()
		}
		return s
	}()...), ", "))
	fmt.Printf("valid:    %s → %s (%d days)\n",
		now.Format("2006-01-02"), now.Add(time.Duration(*days)*24*time.Hour).Format("2006-01-02"), *days)

	fmt.Println()
	fmt.Println("── veilgate.yaml TLS stanza ─────────────────────────────────────────")
	fmt.Printf("tls:\n")
	fmt.Printf("  enabled: true\n")
	fmt.Printf("  cert_file: %q\n", certPath)
	fmt.Printf("  key_file:  %q\n", keyPath)
	fmt.Println()
	fmt.Println("After enabling tls, restart veilgate. JA3/JA4 fingerprinting activates")
	fmt.Println("automatically — no other config change required. Scores for known agent")
	fmt.Println("libraries (python-requests, go-net-http, playwright, puppeteer) rise by")
	fmt.Println("30-45 pts per matched fingerprint → tarpit fires reliably.")

	if *cloudflare {
		printCloudflareInstructions(certPath, keyPath, dnsNames)
	}
}

// printCloudflareInstructions prints human-readable steps for importing
// the generated cert into Cloudflare and for exporting PKCS#12 bundles
// for other server types (nginx, Apache, IIS).
func printCloudflareInstructions(certPath, keyPath string, dnsNames []string) {
	fmt.Println()
	fmt.Println("── Cloudflare integration ───────────────────────────────────────────")
	fmt.Println()
	fmt.Println("OPTION A — Cloudflare in 'Full' SSL mode (recommended for veilgate)")
	fmt.Println("  veilgate terminates TLS at the origin. Cloudflare proxies HTTPS to")
	fmt.Println("  veilgate, accepting self-signed certs when mode is 'Full'.")
	fmt.Println()
	fmt.Println("  1. In Cloudflare dashboard → SSL/TLS → Overview → set mode to 'Full'")
	fmt.Println("  2. Point DNS A/AAAA → your veilgate server IP")
	fmt.Println("  3. Set veilgate to listen on :443 with the generated cert/key")
	fmt.Println("  4. Cloudflare will handle the publicly-trusted edge cert for clients;")
	fmt.Println("     veilgate uses this self-signed cert for the Cloudflare→origin leg")
	fmt.Println()
	fmt.Println("OPTION B — Cloudflare Origin CA certificate (stronger validation)")
	fmt.Println("  Replaces this self-signed cert with one Cloudflare signs and trusts.")
	fmt.Println("  1. Cloudflare dashboard → SSL/TLS → Origin Server → Create Certificate")
	fmt.Println("  2. Download the origin cert + key, place in veilgate config")
	fmt.Println("  3. Set SSL/TLS mode to 'Full (strict)' — Cloudflare validates the cert")
	fmt.Println()
	fmt.Println("OPTION C — Custom certificate on Cloudflare's edge")
	fmt.Println("  Requires a publicly-trusted cert (Let's Encrypt, DigiCert, etc.).")
	fmt.Println("  Self-signed certs cannot be uploaded to Cloudflare's edge.")
	fmt.Println()
	fmt.Println("── PKCS#12 export (for nginx / Apache / IIS / Java keystores) ───────")
	fmt.Println()
	fmt.Println("  Export PEM → PKCS#12 bundle:")
	fmt.Printf("    openssl pkcs12 -export -in %s -inkey %s -out bundle.p12 -name veilgate\n", certPath, keyPath)
	fmt.Println()
	fmt.Println("  Import into Java keystore (JKS):")
	fmt.Println("    keytool -importkeystore -srckeystore bundle.p12 -srcstoretype PKCS12 \\")
	fmt.Println("            -destkeystore veilgate.jks -deststoretype JKS")
	fmt.Println()
	fmt.Println("  Verify the generated cert:")
	fmt.Printf("    openssl x509 -in %s -text -noout\n", certPath)
	fmt.Println()
	fmt.Println("── JA3/JA4 capture after deployment ─────────────────────────────────")
	fmt.Println()
	fmt.Println("  Once veilgate is running with TLS enabled, capture live fingerprints")
	fmt.Println("  and add them to veilgate-rules/tls_fingerprints/:")
	fmt.Println()
	fmt.Println("    # Tail the veilgate log for JA4 values")
	fmt.Println("    veilgate --config configs/veilgate.yaml 2>&1 | grep X-Veilgate-JA4")
	fmt.Println()
	fmt.Println("    # Or query captured events from the SQLite store")
	fmt.Println("    sqlite3 data/events.db 'SELECT ja4, ua, COUNT(*) c")
	fmt.Println("                             FROM events GROUP BY ja4, ua ORDER BY c DESC'")
	if len(dnsNames) > 0 {
		fmt.Printf("\n  Test TLS from the CLI (check for JA4 in veilgate logs):\n")
		fmt.Printf("    curl -vk https://%s/_g/config\n", dnsNames[0])
	}
}

// generateKey returns (privKey, pubKey, label, err) for the chosen key type.
func generateKey(keyType string) (privKey, pubKey interface{}, label string, err error) {
	switch strings.ToLower(keyType) {
	case "ecdsa256", "ecdsa":
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return k, &k.PublicKey, "ECDSA-P256", e
	case "ecdsa384":
		k, e := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return k, &k.PublicKey, "ECDSA-P384", e
	case "rsa4096", "rsa":
		k, e := rsa.GenerateKey(rand.Reader, 4096)
		return k, &k.PublicKey, "RSA-4096", e
	case "rsa2048":
		k, e := rsa.GenerateKey(rand.Reader, 2048)
		return k, &k.PublicKey, "RSA-2048", e
	default:
		return nil, nil, "", fmt.Errorf("unknown key type %q — use ecdsa256, ecdsa384, rsa4096, or rsa2048", keyType)
	}
}

// marshalPrivateKey returns (DER bytes, PEM type header, error).
func marshalPrivateKey(key interface{}) ([]byte, string, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		return b, "EC PRIVATE KEY", err
	case *rsa.PrivateKey:
		return x509.MarshalPKCS1PrivateKey(k), "RSA PRIVATE KEY", nil
	default:
		return nil, "", fmt.Errorf("unsupported key type %T", key)
	}
}

// writePEM creates or overwrites path with a single PEM block.
func writePEM(path, blockType string, der []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: der})
}
