package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/policytest"
)

type policyTestIn struct {
	Ring      string   `json:"ring,omitempty" jsonschema:"limit the render, release and invariant checks to this ring (default: every ring)"`
	Against   string   `json:"against,omitempty" jsonschema:"git ref of the policy to compare with (e.g. main): adds the impact check, which fails when more than max_impact percent of the sampled users of all users or of any ring change ring, variant or settings"`
	Strict    bool     `json:"strict,omitempty" jsonschema:"fail on warnings too: policy validation warnings and adapter warnings"`
	MaxImpact *float64 `json:"max_impact,omitempty" jsonschema:"impact check threshold in percent, 0 to 100 (default 25; 100 never trips)"`
}

func (s *srv) addPolicyTestTool(m *mcp.Server) {
	mcp.AddTool(m, &mcp.Tool{Name: "policy_test", Annotations: readOnly,
		Description: "Test a policy change offline in seconds, with no network or credentials (`halo test`): validate; render every ring x harness x OS and surface adapter warnings; build each ring's release and check its manifest and reproducibility; assert no permission-bypass setting anywhere (invariant 1); with against, preview who changes ring, variant or settings and flag a high blast radius; run the PolicyTest cases under tests/; simulate every rollout. Returns ok, a result per check (suite, name, status pass|fail|skip, details, warnings) and next_steps. Writes nothing in the policy repo. Run it after every edit and before eval_run, which spends credentials."}, s.policyTest)
}

func (s *srv) policyTest(ctx context.Context, _ *mcp.CallToolRequest, in policyTestIn) (*mcp.CallToolResult, *policytest.Report, error) {
	opt := policytest.Options{Dir: s.dir, Ring: in.Ring, Against: in.Against, Strict: in.Strict, MaxImpact: policytest.DefaultMaxImpact}
	if in.MaxImpact != nil {
		opt.MaxImpact = *in.MaxImpact
	}
	rep, err := policytest.Run(ctx, opt)
	if err != nil {
		return nil, nil, err
	}
	return nil, rep, nil
}
