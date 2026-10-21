package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/server"
)

func (a *app) cmdAudit() *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "Inspect halo-server's hash-chained audit log"}
	var dataDir string
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit hash chain across every segment (exit 2 if broken)",
		Long: "Reads <data-dir>/audit-*.jsonl (rotated segments, oldest first) and then audit.jsonl, and checks\n" +
			"that sequence numbers run from 1 without gaps, every entry links to the one before it (across\n" +
			"segment boundaries too) and every hash matches. Read-only: safe against a live halo-server's data dir.\n" +
			"Entries cut from the end leave a valid chain; compare the head with the newest hash your SIEM holds.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			r, err := server.VerifyAuditDir(dataDir)
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
	verify.Flags().StringVar(&dataDir, "data-dir", "", "halo-server --data-dir holding audit.jsonl (required)")
	_ = verify.MarkFlagRequired("data-dir")
	c.AddCommand(verify)
	return c
}
