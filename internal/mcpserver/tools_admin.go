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
	// Checked is true when the live consoles were read and diffed; Drift
	// means nothing when it is false.
	Checked   bool                `json:"checked"`
	Drift     bool                `json:"drift"`
	Report    *vendoradmin.Report `json:"report"`
	NextSteps []string            `json:"next_steps"`
}

// adminPlan is `halo admin plan` over MCP. Read-only: there is deliberately
// no apply tool (AGENTS.md: a human owns every irreversible step). It reads
// live consoles only when the server was started with --admin-read, and then
// only with HALO_MCP_ADMIN_<VENDOR>_TOKEN from the server's environment: not
// the CLI's HALO_ADMIN_* variables (a token in a shell profile is never used
// silently), never a tool argument. API base URLs are not arguments either,
// so a caller cannot send a credential elsewhere.
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
	switch {
	case !s.AdminRead:
		out.NextSteps = append(out.NextSteps, "rendered from policy only: live console reads are off on this server; a human starts `halo mcp serve --admin-read` with HALO_MCP_ADMIN_<VENDOR>_TOKEN set, or runs `halo admin plan`")
	case in.Offline:
		out.NextSteps = append(out.NextSteps, "rendered from policy only (offline): no drift was checked")
	default:
		creds := map[string]vendoradmin.Cred{}
		for _, v := range vendoradmin.Vendors() {
			creds[v] = vendoradmin.Cred{Token: os.Getenv(vendoradmin.MCPTokenEnv(v)), BaseURL: s.AdminBaseURLs[v]}
		}
		clients, err := rep.Clients(vendoradmin.Targets(org.VendorAdmin), creds)
		if err != nil {
			return nil, adminPlanOut{}, err
		}
		rep.ReadLive(ctx, clients, func(v string) string {
			return vendoradmin.MCPTokenEnv(v) + " is not set in this server's environment"
		})
		out.Checked = len(rep.Errors()) == 0
		out.Drift = rep.Drift()
	}
	for _, e := range rep.Errors() {
		out.NextSteps = append(out.NextSteps, "could not read "+vendoradmin.Sanitize(e)+" (a human sets the variable in this server's environment; never pass a credential to a tool)")
	}
	if out.Drift {
		out.NextSteps = append(out.NextSteps, "drift: fix the policy (propose a PR) or have a human run `halo admin apply` after reviewing `halo admin plan`; read-only and manual settings are changed in the console")
	}
	for _, p := range rep.Vendors {
		if len(p.Artifacts) > 0 {
			out.NextSteps = append(out.NextSteps, "not checked (manual): human runs `halo admin export` and follows "+p.Vendor+"/STEPS.md (no API for "+p.Vendor+")")
		}
	}
	return nil, out, nil
}

func (s *srv) addAdminTools(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "admin_plan", Annotations: readOnly,
		Description: "Vendor admin sync (ADR-0025): render halos.yaml vendorAdmin's console settings from the GA ring's profile. Only on a server started with --admin-read does it also diff the vendors with a public read API (gemini, copilot) against their live consoles, using HALO_MCP_ADMIN_<VENDOR>_TOKEN from the server's environment. Read-only; applying is the human's `halo admin apply`."}, s.adminPlan)
}
