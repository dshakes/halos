package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/pgstore"
	"github.com/dshakes/halos/internal/server"
)

func (a *app) cmdAudit() *cobra.Command {
	c := &cobra.Command{Use: "audit", Short: "Inspect halo-server's hash-chained audit log"}
	var dataDir, dbURLFile, exportFile, anchorFile, compareFile string
	var pubKeyFiles []string
	var insecureTLS bool
	var maxUnsigned int
	var strict, allowRotation bool
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Verify the audit hash chain, its signed checkpoints and an external anchor (exit 2 if broken)",
		Long: "Reads <data-dir>/audit-*.jsonl (rotated segments, oldest first) and then audit.jsonl, and checks\n" +
			"that sequence numbers run without gaps, every entry links to the one before it (across\n" +
			"segment boundaries too) and every hash matches. Read-only: safe against a live halo-server's data dir.\n" +
			"With --database-url-file it reads the Postgres backend's audit table instead (HA, ADR-0021), uncached;\n" +
			"with --file it reads an export as your SIEM received it (native lines, or OCSF events).\n" +
			"Entries an erasure pseudonymised must each be vouched for by a later subject.erase entry, and a\n" +
			"chain that retention shortened must start where an audit.retention entry says (ADR-0040).\n" +
			"--public-key checks every signed checkpoint (ADR-0041): a chain recomputed after an edit fails at\n" +
			"the first checkpoint after it. With it, only a subject.erase or audit.retention entry signed by the\n" +
			"same key may vouch for a redaction or a cut, and a log with no signed checkpoint fails.\n" +
			"--anchor takes the newest checkpoint from a file your SIEM holds and requires the log to still\n" +
			"contain it unchanged, so entries cut from the end are caught; it compares that one entry only.\n" +
			"--compare-export compares content: every seq the log and the SIEM export both hold.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := auditVerifyOptions(pubKeyFiles, anchorFile)
			if err != nil {
				return err
			}
			if compareFile != "" {
				if o.Export, err = server.LoadExport(compareFile); err != nil {
					return fmt.Errorf("--compare-export: %w", err)
				}
			}
			o.RequireCurrentKey = len(pubKeyFiles) > 1 && !allowRotation
			anchored := o.Anchor != nil || o.Export != nil
			r, err := verifyAudit(cmd.Context(), dataDir, dbURLFile, exportFile, insecureTLS, o)
			if err != nil {
				return err
			}
			switch {
			case r.Error != "":
			case strict && (o.Verifier == nil || !anchored):
				r.Error = "--strict needs --public-key and an external anchor (--anchor or --compare-export): without one, a storage writer can delete the tail, or everything, undetected"
			case o.Verifier != nil && r.Checkpoints == 0:
				r.Error = "no signed checkpoint verified: with --public-key the log must carry checkpoints (is --audit-signing-key-uri set on halo-server?)"
			case maxUnsigned >= 0 && o.Verifier != nil && r.UnsignedTail > uint64(maxUnsigned):
				r.Error = fmt.Sprintf("%d entries after the last signed checkpoint, more than --max-unsigned-tail %d", r.UnsignedTail, maxUnsigned)
			}
			out := map[string]any{"ok": r.Error == "", "entries": r.Entries, "segments": r.Segments, "head": r.Head, "error": r.Error}
			if o.Verifier != nil {
				out["checkpoints"], out["lastCheckpoint"], out["unsignedTail"] = r.Checkpoints, r.LastCheckpoint, r.UnsignedTail
			}
			if o.Anchor != nil {
				out["anchor"], out["anchored"] = o.Anchor.Seq, r.Anchored
			}
			if r.First > 0 {
				out["first"] = r.First
			}
			if o.Export != nil {
				out["redactedSinceExport"] = r.RedactedSinceExport
			}
			out["authenticated"] = o.Verifier != nil // without a key, redactions and retention cuts are not authenticated
			if err := a.emit(out, func() {
				if r.Error != "" {
					fmt.Fprintf(a.out, "%s: %s (%d entries in %d segments)\n", a.red("BROKEN"), r.Error, r.Entries, r.Segments)
					return
				}
				fmt.Fprintf(a.out, "%s: %d entries in %d segments, head %s\n", a.green("OK"), r.Entries, r.Segments, r.Head)
				if o.Verifier != nil {
					fmt.Fprintf(a.out, "  %d signed checkpoints, last at seq %d; %d entries after it are not yet signed\n", r.Checkpoints, r.LastCheckpoint, r.UnsignedTail)
				} else {
					fmt.Fprintln(a.out, "  unsigned: links checked, but redactions and retention cuts are not authenticated (pass --public-key)")
				}
				if o.Anchor != nil {
					fmt.Fprintf(a.out, "  anchored: the log still holds the checkpoint at seq %d\n", o.Anchor.Seq)
				}
				if o.Verifier != nil && !anchored {
					fmt.Fprintln(a.out, "  warning: no external anchor. Signatures prove who wrote the checkpoints, vouches and cuts and catch edits, but not deletion: a storage writer can cut the tail, or delete everything with the signing record and start over, undetected. Verify against your SIEM copy with --compare-export (or --anchor); --strict fails without one")
				}
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
	verify.Flags().StringVar(&exportFile, "file", "", "an audit export as a SIEM received it, one entry (or OCSF event) per line (instead of --data-dir)")
	verify.Flags().StringArrayVar(&pubKeyFiles, "public-key", nil, "PEM public key of halo-server's --audit-signing-key-uri: check every checkpoint signature (ADR-0041); repeat it for keys the current one replaced, the current key first")
	verify.Flags().StringVar(&anchorFile, "anchor", "", "file of exported entries (your SIEM's copy); its newest checkpoint must still be in the log, unchanged")
	verify.Flags().StringVar(&compareFile, "compare-export", "", "file of exported entries (your SIEM's copy): every seq both hold must match in hash and content, unless the log's entry is a vouched-for redaction, and the log must reach the export's newest seq")
	verify.Flags().BoolVar(&strict, "strict", false, "fail unless --public-key and an external anchor (--anchor or --compare-export) are given: the only combination that also catches deletion (recommended on a schedule)")
	verify.Flags().BoolVar(&allowRotation, "allow-rotation-window", false, "with several --public-key: accept a newest checkpoint signed by a previous key (while replicas are switching keys)")
	verify.Flags().IntVar(&maxUnsigned, "max-unsigned-tail", -1, "with --public-key: fail when more entries than this follow the last signed checkpoint (-1: no limit)")
	verify.Flags().BoolVar(&insecureTLS, "database-insecure-tls", false, "accept a database URL that does not verify the server certificate and host name (sslmode below verify-full) to a non-loopback host")
	verify.MarkFlagsOneRequired("data-dir", "database-url-file", "file")
	verify.MarkFlagsMutuallyExclusive("data-dir", "database-url-file", "file")
	c.AddCommand(verify)
	return c
}

// auditVerifyOptions loads --public-key (one or more: the audit key and the
// keys it replaced) and --anchor.
func auditVerifyOptions(pubKeyFiles []string, anchorFile string) (server.AuditVerifyOptions, error) {
	var o server.AuditVerifyOptions
	keys, err := readPublicKeys("--public-key", pubKeyFiles)
	if err != nil {
		return o, err
	}
	if len(keys) > 0 {
		o.Verifier = keys
	}
	if anchorFile != "" {
		e, ok, err := server.LastCheckpoint(anchorFile, o.Verifier)
		if err != nil {
			return o, fmt.Errorf("--anchor: %w", err)
		}
		if !ok {
			return o, errors.New("--anchor: the file holds no audit.checkpoint entry (is --audit-signing-key-uri set on halo-server?)")
		}
		o.Anchor = &e
	}
	return o, nil
}

// readPublicKeys parses PEM public keys into a key set.
func readPublicKeys(flag string, files []string) (bundle.Keyring, error) {
	var ring bundle.Keyring
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", flag, err)
		}
		v, err := bundle.ParseVerifier(b)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", flag, f, err)
		}
		ring = append(ring, v)
	}
	return ring, nil
}

func verifyAudit(ctx context.Context, dataDir, dbURLFile, exportFile string, insecureTLS bool, o server.AuditVerifyOptions) (server.AuditVerifyResult, error) {
	switch {
	case exportFile != "":
		return server.VerifyAuditExport(exportFile, o)
	case dbURLFile == "":
		return server.VerifyAuditDir(dataDir, o)
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
	return server.VerifyAuditBackend(ctx, server.NewPGBackend(db), o)
}
