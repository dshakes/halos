package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/server"
)

func (a *app) cmdAudit() *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "Inspect halo-server's hash-chained audit log"}
	var dataDir, dbURLFile string
	var insecureTLS bool
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit hash chain across every segment (exit 2 if broken)",
		Long: "Reads <data-dir>/audit-*.jsonl (rotated segments, oldest first) and then audit.jsonl, and checks\n" +
			"that sequence numbers run from 1 without gaps, every entry links to the one before it (across\n" +
			"segment boundaries too) and every hash matches. Read-only: safe against a live halo-server's data dir.\n" +
			"With --database-url-file it reads the Postgres backend's audit table instead (HA, ADR-0021), uncached.\n" +
			"Entries cut from the end leave a valid chain; compare the head with the newest hash your SIEM holds.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r, err := verifyAudit(cmd.Context(), dataDir, dbURLFile, insecureTLS)
			if err != nil {
				return err
			}
			if err := a.emit(map[string]any{"ok": r.Error == "", "entries": r.Entries, "segments": r.Segments, "head": r.Head, "error": r.Error}, func() {
				if r.Error != "" {
					fmt.Fprintf(a.out, "%s: %s (%d entries in %d segments)\n", a.red("BROKEN"), r.Error, r.Entries, r.Segments)
					return
				}
				fmt.Fprintf(a.out, "%s: %d entries in %d segments, head %s\n", a.green("OK"), r.Entries, r.Segments, r.Head)
			}); err != nil {
				return err
			}
			if r.Error != "" {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	verify.Flags().StringVar(&dataDir, "data-dir", "", "halo-server --data-dir holding audit.jsonl")
	verify.Flags().StringVar(&dbURLFile, "database-url-file", "", "file holding the Postgres URL of an HA halo-server (instead of --data-dir)")
	verify.Flags().BoolVar(&insecureTLS, "database-insecure-tls", false, "accept a database URL that does not verify the server certificate and host name (sslmode below verify-full) to a non-loopback host")
	verify.MarkFlagsOneRequired("data-dir", "database-url-file")
	verify.MarkFlagsMutuallyExclusive("data-dir", "database-url-file")
	c.AddCommand(verify)
	return c
}

func verifyAudit(ctx context.Context, dataDir, dbURLFile string, insecureTLS bool) (server.AuditVerifyResult, error) {
	if dbURLFile == "" {
		return server.VerifyAuditDir(dataDir)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	b, err := os.ReadFile(dbURLFile)
	if err != nil {
		return server.AuditVerifyResult{}, fmt.Errorf("--database-url-file: %w", err)
	}
	db, err := pgstore.OpenWith(ctx, strings.TrimSpace(string(b)), pgstore.Options{InsecureTLS: insecureTLS, MaxConns: 2})
	if err != nil {
		return server.AuditVerifyResult{}, err // never echo the URL: it carries the password
	}
	defer func() { _ = db.Close() }()
	if err := db.CheckSchema(ctx); err != nil {
		return server.AuditVerifyResult{}, err
	}
	return server.VerifyAuditBackend(ctx, server.NewPGBackend(db))
}
