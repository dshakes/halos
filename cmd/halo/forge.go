package main

import (
	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/promote"
)

// forgeFlags selects where PRs/MRs are opened (GitHub via gh or REST, GitLab
// via REST). The zero value autodetects from the origin remote and keeps gh
// for everything but a GitLab host.
type forgeFlags struct {
	kind, baseURL string
}

func (f *forgeFlags) add(c *cobra.Command) {
	c.Flags().StringVar(&f.kind, "forge", "", "where to open the change request: "+promote.ForgeKinds+"; github/gitlab use the REST API with GITHUB_TOKEN/GH_TOKEN or GITLAB_TOKEN")
	c.Flags().StringVar(&f.baseURL, "forge-base-url", "", "REST API root for GitHub Enterprise Server (https://ghe.example.com/api/v3) or self-managed GitLab (https://gitlab.example.com/api/v4); default derived from the origin remote")
}

func (f *forgeFlags) forge() (*promote.ForgeOpener, error) {
	return promote.NewForge(promote.ForgeConfig{Kind: f.kind, BaseURL: f.baseURL})
}
