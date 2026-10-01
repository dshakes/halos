package main

import (
	"fmt"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/halos-dev/halos/internal/mcpserver"
)

func (a *app) cmdMCP() *cobra.Command {
	c := &cobra.Command{Use: "mcp", Short: "Model Context Protocol server for agents"}
	var dir, schemaDir string
	var writes bool
	var ch clickhouseFlags
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Serve Halos tools, resources and prompts over stdio MCP",
		Long: "Serve Halos over stdio MCP. Read-only tools are always on. --allow-writes adds experiment " +
			"and proposal tools (dry_run by default, reason required). No tool publishes releases, retags rings, merges or pushes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o := mcpserver.Options{PolicyDir: dir, AllowWrites: writes, SchemaDir: schemaDir, Version: version}
			if ch.url != "" {
				o.ClickHouse = ch.client()
			}
			s, err := mcpserver.New(o)
			if err != nil {
				return err
			}
			// stdout is the protocol channel; all logging goes to stderr.
			fmt.Fprintf(os.Stderr, "halo mcp: serving %s (writes=%t)\n", dir, writes)
			return s.Run(cmd.Context(), &mcp.StdioTransport{})
		},
	}
	serve.Flags().StringVar(&dir, "policy-dir", ".", "policy repo directory")
	serve.Flags().BoolVar(&writes, "allow-writes", false, "expose write tools (experiment status, promotion/rollback proposals)")
	serve.Flags().StringVar(&schemaDir, "schema-dir", "", "JSON Schema directory (default: auto-detect)")
	serve.Flags().StringVar(&ch.url, "clickhouse", "", "ClickHouse HTTP URL; enables analyze_experiment")
	serve.Flags().StringVar(&ch.db, "database", "", "ClickHouse database")
	serve.Flags().StringVar(&ch.user, "user", "", "ClickHouse user (password from HALO_CLICKHOUSE_PASSWORD)")
	c.AddCommand(serve)
	return c
}
