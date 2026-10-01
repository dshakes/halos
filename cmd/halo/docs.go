package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/docgen"
)

// cmdDocs is hidden: it exists for internal/tools/gendocs (`make docs-gen`).
func (a *app) cmdDocs() *cobra.Command {
	docs := &cobra.Command{Use: "docs", Short: "Documentation generators", Hidden: true}
	var out string
	gen := &cobra.Command{
		Use:   "gen-cli",
		Short: "Write one markdown page per command into --out",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			root := newRoot(a.out, a.errw)
			n, err := docgen.CLI(root, out)
			if err != nil {
				return fmt.Errorf("generate cli docs: %w", err)
			}
			fmt.Fprintf(a.out, "cli: %d pages\n", n)
			return nil
		},
	}
	gen.Flags().StringVar(&out, "out", "", "output directory")
	_ = gen.MarkFlagRequired("out")
	docs.AddCommand(gen)
	return docs
}
