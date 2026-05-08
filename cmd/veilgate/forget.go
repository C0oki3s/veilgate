package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/C0oki3s/veilgate/internal/audit"
	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/persist"
)

// runForget implements `veilgate forget --ip <addr> [--config path]`.
// One-shot subcommand that opens the existing event store, deletes
// every row tied to the given client identifier, writes an audit-log
// entry, and exits. Use it for GDPR right-to-erasure requests.
//
// The function deliberately does not touch in-memory state of a running
// proxy — operators are expected to schedule a process restart (or rely
// on the burn-in / window eviction) so any RAM-resident traces of the
// IP fade naturally. SQLite is the durable surface and it is what we
// scrub here.
func runForget(args []string) {
	fs := flag.NewFlagSet("forget", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/veilgate.yaml", "path to config file (used to find the persist DB)")
	clientID := fs.String("ip", "", "client identifier to forget (typically an IP address)")
	actor := fs.String("actor", "", "actor to record in the audit log (defaults to $USER or 'cli')")
	dryRun := fs.Bool("dry-run", false, "report what would be deleted without committing")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *clientID == "" {
		fmt.Fprintln(os.Stderr, "forget: --ip is required")
		fs.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forget: load config: %v\n", err)
		os.Exit(1)
	}
	if !cfg.Persist.Enabled || cfg.Persist.Path == "" {
		fmt.Fprintln(os.Stderr, "forget: persistence is disabled in this config — nothing to scrub")
		os.Exit(1)
	}

	store, err := persist.Open(persist.Config{Path: cfg.Persist.Path, QueueSize: 64})
	if err != nil {
		fmt.Fprintf(os.Stderr, "forget: open store: %v\n", err)
		os.Exit(1)
	}
	defer store.Close()

	if *dryRun {
		fmt.Printf("DRY RUN — would forget client %q from %s\n", *clientID, cfg.Persist.Path)
		return
	}

	rows, err := store.ForgetClient(*clientID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "forget: %v\n", err)
		os.Exit(1)
	}

	// Best-effort audit. We use a SQL backend rooted on the same store
	// so the deletion event itself becomes part of the tamper-evident
	// log even though we just deleted other rows for this client.
	logger := audit.NewLogger(&audit.SQLBackend{DB: store})
	logger.SetSeedHash(store.LastAuditHash())
	who := *actor
	if who == "" {
		who = os.Getenv("USER")
		if who == "" {
			who = "cli"
		}
	}
	_ = logger.Log(audit.Entry{
		Time:    time.Now().UTC(),
		Actor:   who,
		Action:  "data.forget",
		Target:  *clientID,
		Outcome: "ok",
		Detail:  fmt.Sprintf("deleted %d rows from persist store", rows),
		Meta:    audit.FmtMeta("config", *cfgPath, "db", cfg.Persist.Path),
	})

	fmt.Printf("forget: deleted %d rows tied to %q\n", rows, *clientID)
	fmt.Println("forget: restart the proxy to flush in-memory Bayes/IF state for this client")
	_ = context.Background() // imported for future ctx-aware forgets
}
