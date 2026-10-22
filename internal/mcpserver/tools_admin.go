package mcpserver

import (
	"context"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/vendoradmin"
)

type adminPlanIn struct {
	Offline bool `json:"offline,omitempty" jsonschema:"render only; do not read the live consoles"`
}

type adminPlanOut struct {
	Drift     bool                `json:"drift"`
	Report    *vendoradmin.Report `json:"report"`
	NextSteps []string            `json:"next_steps"`
}

// adminPlan is `halo admin plan` over MCP. Read-only: there is deliberately
// no apply tool (AGENTS.md: a human owns every irreversible step). Credentials
// come only from the server's HALO_ADMIN_<VENDOR>_TOKEN environment, never a
// tool argument, and the API base URLs are not arguments either, so a caller
// cannot send a credential elsewhere.
func (s *srv) adminPlan(ctx context.Context, _ *mcp.CallToolRequest, in adminPlanIn) (*mcp.CallToolResult, adminPlanOut, error) {
	org, err := s.loadValid()
	if err != nil {
		return nil, adminPlanOut{}, err
	}
	rep, err := vendoradmin.Render(org)
	if err != nil {
		return nil, adminPlanOut{}, err
	}
	out := adminPlanOut{Report: rep, NextSteps: []string{}}
	if !in.Offline {
		creds := map[string]vendoradmin.Cred{}
		for _, v := range vendoradmin.Vendors() {
			creds[v] = vendoradmin.Cred{Token: os.Getenv(vendoradmin.TokenEnv(v)), BaseURL: s.AdminBaseURLs[v]}
		}
		rep.ReadLive(ctx, rep.Clients(vendoradmin.Targets(org.VendorAdmin), creds))
	}
	out.Drift = rep.Drift()
	for _, e := range rep.Errors() {
		out.NextSteps = append(out.NextSteps, "could not read "+e+" (the human sets the variable in this server's environment; never pass a credential to a tool)")
	}
	if out.Drift {
		out.NextSteps = append(out.NextSteps, "drift: fix the policy (propose a PR) or have a human run `halo admin apply` after reviewing `halo admin plan`; read-only and manual settings are changed in the console")
	}
	for _, p := range rep.Vendors {
		if len(p.Artifacts) > 0 {
			out.NextSteps = append(out.NextSteps, "human: `halo admin export` and follow "+p.Vendor+"/STEPS.md (no write API for "+p.Vendor+")")
		}
	}
	return nil, out, nil
}

func (s *srv) addAdminTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "admin_plan", Annotations: readOnly,
		Description: "Vendor admin sync (ADR-0025): render halos.yaml vendorAdmin's console settings from the GA ring's profile and diff the vendors with a public read API (gemini, copilot) against their live consoles, using credentials from HALO_ADMIN_<VENDOR>_TOKEN in the server's environment. Read-only; applying is the human's `halo admin apply`."}, s.adminPlan)
}
