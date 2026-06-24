// Command admin runs the VeilGate configuration web UI.
//
// Usage:
//
//	admin --config /path/to/veilgate.yaml [--addr :8888] [--user admin --pass s3cr3t]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/C0oki3s/veilgate/internal/admin"
)

const version = "v1.1.8"

func main() {
	// Parse config path first so the data-file defaults can be derived from it.
	cfg := defaultConfig()
	for i, arg := range os.Args[1:] {
		if (arg == "--config" || arg == "-config") && i+1 < len(os.Args)-1 {
			cfg = os.Args[i+2]
		}
		if len(arg) > 9 && (arg[:9] == "--config=" || arg[:8] == "-config=") {
			if arg[:2] == "--" {
				cfg = arg[9:]
			} else {
				cfg = arg[8:]
			}
		}
	}

	var (
		configPath = flag.String("config", cfg, "path to veilgate.yaml")
		addr       = flag.String("addr", ":8888", "admin UI listen address")
		user       = flag.String("user", "", "admin username — seeds DB on first run or updates password")
		pass       = flag.String("pass", "", "admin password")
		dbPath     = flag.String("db", defaultDataPath(cfg, "admin.db"), "SQLite database for users + audit log")
		auditLog   = flag.String("audit-log", defaultDataPath(cfg, "audit.log"), "JSONL audit backup alongside DB")
	)
	flag.Parse()

	srv, err := admin.New(admin.AdminConfig{
		ConfigPath: *configPath,
		Version:    version,
		AdminUser:  *user,
		AdminPass:  *pass,
		DBPath:     *dbPath,
		AuditPath:  *auditLog,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "admin: %v\n", err)
		os.Exit(1)
	}

	log.Printf("VeilGate admin UI  addr=%s  config=%s  db=%s  auth=%v",
		*addr, *configPath, *dbPath, *user != "")
	if err := http.ListenAndServe(*addr, srv); err != nil {
		log.Fatal(err)
	}
}

func defaultConfig() string {
	if _, err := os.Stat("veilgate.yaml"); err == nil {
		return "veilgate.yaml"
	}
	home, _ := os.UserHomeDir()
	return home + "/.veilgate/veilgate.yaml"
}

// defaultDataPath returns a path inside the same directory as the config file.
// This keeps admin.db, audit.log and decoys.yaml co-located with veilgate.yaml
// so every user-visible file lives under one directory (typically ~/.veilgate/).
func defaultDataPath(configPath, filename string) string {
	dir := filepath.Dir(configPath)
	// filepath.Dir of a bare filename like "veilgate.yaml" returns ".".
	// Expand that to the real working directory so the path is absolute.
	if dir == "." {
		if wd, err := os.Getwd(); err == nil {
			dir = wd
		}
	}
	return filepath.Join(dir, filename)
}
