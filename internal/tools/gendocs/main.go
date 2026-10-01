// Command gendocs regenerates the CLI and policy reference pages:
//
//	go run ./internal/tools/gendocs --out docs/src/content/docs/reference
//
// Run it from the repo root. The CLI pages come from the hidden
// `halo docs gen-cli` command because the cobra tree lives in package main.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/dshakes/halos/internal/docgen"
)

func main() {
	out := flag.String("out", "docs/src/content/docs/reference", "reference docs directory")
	schemas := flag.String("schemas", "schemas", "JSON Schema directory")
	flag.Parse()
	if err := run(*out, *schemas); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}

func run(out, schemas string) error {
	n, err := docgen.Policy(schemas, filepath.Join(out, "policy"))
	if err != nil {
		return fmt.Errorf("policy docs: %w", err)
	}
	fmt.Printf("policy: %d pages\n", n)
	cmd := exec.Command("go", "run", "./cmd/halo", "docs", "gen-cli", "--out", filepath.Join(out, "cli"))
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cli docs: %w", err)
	}
	return nil
}
