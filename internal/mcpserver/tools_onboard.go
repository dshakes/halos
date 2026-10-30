package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dshakes/halos/internal/intent"
	"github.com/dshakes/halos/internal/onboard"
)

// Onboarding tools mirror `halo doctor` and `halo onboard`. They are always
// registered so an agent can preview every step, but each one that writes
// files or runs a CLI does so only with dry_run false AND the server started
// with --allow-writes; otherwise it returns the preview plus the CLI command a
// human runs. None publishes, enrolls, pushes or merges.

type initPolicyIn struct {
	Org      string            `json:"org,omitempty" jsonschema:"organization name (default local)"`
	Tools    map[string]string `json:"tools,omitempty" jsonschema:"tool -> pinned version (default: every CLI on PATH at its installed version)"`
	Provider string            `json:"provider,omitempty" jsonschema:"anthropic | bedrock | vertex | openai | gemini | multi (default: the one whose key is exported)"`
	Models   map[string]string `json:"models,omitempty" jsonschema:"alias -> provider model id (default: the provider's current model)"`
	Project  string            `json:"project,omitempty" jsonschema:"Google Cloud project (provider vertex)"`
	Gateway  string            `json:"gateway,omitempty" jsonschema:"gateway base URL the CLIs call (default: a local halo-proxy on http://127.0.0.1:8088)"`
	// GatewayEngine marks a company's own API gateway (external).
	GatewayEngine string `json:"gateway_engine,omitempty" jsonschema:"what serves gateway: halo-proxy (default), kong, or external (the company's own API gateway; CLIs get provider model ids)"`
	Safety        string `json:"safety,omitempty" jsonschema:"strict | standard | relaxed (default standard)"`
	Rollout       string `json:"rollout,omitempty" jsonschema:"fast | standard | careful (default standard)"`
	Ring          string `json:"ring,omitempty" jsonschema:"ring this machine follows (default: the GA ring)"`
	DryRun        *bool  `json:"dry_run,omitempty" jsonschema:"default true: return halos.yaml, validation and the install plan; write nothing"`
}

type installIn struct {
	Ring   string `json:"ring,omitempty" jsonschema:"ring to install (default: the GA ring)"`
	Root   string `json:"root,omitempty" jsonschema:"stage under this directory instead of the real admin-owned paths"`
	Show   bool   `json:"show,omitempty" jsonschema:"include each file's contents"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"default true: return what lands where; write nothing"`
}

type installOut struct {
	DryRun  bool                 `json:"dry_run"`
	Plan    *onboard.InstallPlan `json:"plan"`
	Written []string             `json:"written"`
	Note    string               `json:"note,omitempty"`
}

type proxyIn struct {
	Listen string `json:"listen,omitempty" jsonschema:"loopback address (default 127.0.0.1:8088)"`
	DryRun *bool  `json:"dry_run,omitempty" jsonschema:"default true: list the files; write nothing"`
}

type verifyIn struct {
	Harness    string `json:"harness" jsonschema:"claude-code | codex | gemini-cli | copilot-cli | cursor-agent | opencode"`
	AssumeAuth bool   `json:"assume_auth,omitempty" jsonschema:"run even with no credential variable set (the CLI is logged in)"`
	DryRun     *bool  `json:"dry_run,omitempty" jsonschema:"default true: return the command; false runs one short model call"`
}

type companyIn struct {
	initPolicyIn
	GatewayKind string   `json:"gateway_kind,omitempty" jsonschema:"halo-proxy | kong | external (the company's own API gateway) (default halo-proxy)"`
	Issuer      string   `json:"issuer,omitempty" jsonschema:"OIDC issuer URL of the IdP (default https://login.<org>.example.com, a placeholder: dry run only)"`
	ClientID    string   `json:"client_id,omitempty" jsonschema:"OIDC client id (default halos)"`
	AdminGroups []string `json:"admin_groups,omitempty" jsonschema:"IdP groups of platform admins"`
	AuthHelper  string   `json:"auth_helper,omitempty" jsonschema:"command printing a short-lived gateway token on each laptop"`
	Delivery    []string `json:"delivery,omitempty" jsonschema:"devcontainer | mdm | halod; a list, or one string (default halod)"`
	Registry    string   `json:"registry,omitempty" jsonschema:"OCI repository releases are published to (default ghcr.io/<org>/halos-releases, a placeholder: dry run only)"`
	PolicyRepo  string   `json:"policy_repo,omitempty" jsonschema:"git URL of the policy repo, Helm git-sync (default https://github.com/<org>/halos-policy.git, a placeholder: dry run only)"`
	PortalURL   string   `json:"portal_url,omitempty" jsonschema:"https URL of the halo-server console (default https://halos.<org>.example.com, a placeholder: dry run only)"`
}

func (s *srv) env() onboard.Env {
	if s.Onboard != nil {
		return *s.Onboard
	}
	return onboard.System()
}

// mayWrite reports whether a call writes; it errors when the caller asked to
// write but the server is read-only.
func (s *srv) mayWrite(dry *bool, cli string) (bool, error) {
	if isDry(dry) {
		return false, nil
	}
	if !s.AllowWrites {
		return false, fmt.Errorf("writes are disabled on this server: ask the human to run `%s`, or to restart it with halo mcp serve --allow-writes", cli)
	}
	return true, nil
}

func (s *srv) addOnboardTools(m *mcp.Server) {
	write := &mcp.ToolAnnotations{DestructiveHint: boolp(false), IdempotentHint: true}
	mcp.AddTool(m, &mcp.Tool{Name: "doctor", Annotations: readOnly,
		Description: "Check this machine and the policy repo: CLIs and versions, tools, credential variables (set or not, never values), policy validity, gateway reachability. Each problem carries the exact fix."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, onboard.Report, error) {
			return nil, onboard.Doctor(ctx, s.env(), s.dir), nil
		})
	mcp.AddTool(m, &mcp.Tool{Name: "detect_harnesses", Annotations: readOnly,
		Description: "List the AI CLIs on PATH with versions, which credential variables are set (never values) and the suggested provider."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ empty) (*mcp.CallToolResult, map[string]any, error) {
			e := s.env()
			return nil, map[string]any{"harnesses": onboard.Detect(ctx, e), "credentials": onboard.Credentials(e), "suggested_provider": onboard.SuggestProvider(e)}, nil
		})
	mcp.AddTool(m, &mcp.Tool{Name: "init_policy", Annotations: write,
		Description: "My-machine step 1: the halos.yaml for these answers, validated, plus the managed-config install plan. Never overwrites an existing halos.yaml. dry_run (default true) writes nothing; dry_run false writes halos.yaml only, and only with --allow-writes."},
		s.initPolicy)
	mcp.AddTool(m, &mcp.Tool{Name: "local_install", Annotations: write,
		Description: "Render the ring's managed config for this OS and return exactly which files land where (create/update/unchanged, backups). dry_run false writes them (admin paths need a root process: use root to stage, or ask the human to run the sudo command)."},
		s.localInstall)
	mcp.AddTool(m, &mcp.Tool{Name: "local_proxy", Annotations: write,
		Description: "Write a loopback-only halo-proxy config into <policy>/.halos/local (provider keys come from the environment at startup, never files) and return the command that starts it."},
		func(_ context.Context, _ *mcp.CallToolRequest, in proxyIn) (*mcp.CallToolResult, *onboard.ProxyResult, error) {
			w, err := s.mayWrite(in.DryRun, shJoin("halo", "onboard", "proxy", "--policy-dir", s.dir, "--apply"))
			if err != nil {
				return nil, nil, err
			}
			r, err := onboard.Proxy(s.env(), s.dir, in.Listen, w)
			return nil, r, err
		})
	mcp.AddTool(m, &mcp.Tool{Name: "verify_harness", Annotations: &mcp.ToolAnnotations{DestructiveHint: boolp(false), OpenWorldHint: boolp(true)},
		Description: "Run one CLI headless (claude -p, codex exec, gemini -p, copilot -p, cursor-agent -p, opencode run) with a fixed prompt and check the reply. dry_run (default true) returns the command; false makes one short model call and, like every write, needs --allow-writes. Output is redacted."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in verifyIn) (*mcp.CallToolResult, onboard.VerifyResult, error) {
			// Spawning a CLI that spends the human's credentials is a side effect: same gate as the writes.
			run, err := s.mayWrite(in.DryRun, shJoin("halo", "onboard", "verify", in.Harness))
			if err != nil {
				return nil, onboard.VerifyResult{}, err
			}
			return nil, onboard.Verify(ctx, s.env(), in.Harness, in.AssumeAuth, !run, 2*time.Minute), nil
		})
	mcp.AddTool(m, &mcp.Tool{Name: "onboard_company", Annotations: write,
		Description: "My-company path: generate the policy repo (halos.yaml, Helm values, IdP client, enrollment per delivery channel, CI, smoke eval, README of human steps) into the policy dir, validated. Only org is required: every other answer has a documented default (schema `default`), the dry run echoes what it assumed in `assumed`, and a real write is refused while any example.com placeholder (`placeholders`) is still assumed. tools, delivery and admin_groups also accept one string or name@version items. Refuses to overwrite differing files. Writes only with dry_run false and --allow-writes; never publishes, enrolls or pushes."},
		s.onboardCompany)
}

func (in initPolicyIn) options() intent.InitOptions {
	return intent.InitOptions{Org: or(in.Org, "local"), Tools: in.Tools, Provider: in.Provider, Models: in.Models, Project: in.Project,
		Gateway: in.Gateway, GatewayEngine: in.GatewayEngine, Safety: or(in.Safety, "standard"), Rollout: or(in.Rollout, "standard")}
}

func or(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func (s *srv) initPolicy(ctx context.Context, _ *mcp.CallToolRequest, in initPolicyIn) (*mcp.CallToolResult, *onboard.LocalResult, error) {
	w, err := s.mayWrite(in.DryRun, shJoin("halo", "onboard", "local", "--policy-dir", s.dir, "--apply")+" (with the same answers as flags)")
	if err != nil {
		return nil, nil, err
	}
	e := s.env()
	o := onboard.LocalOptions{Dir: s.dir, Init: in.options(), Ring: in.Ring, GOOS: or(e.GOOS, runtime.GOOS), Apply: w}
	if len(o.Init.Tools) == 0 {
		if o.Init.Tools = onboard.SuggestTools(onboard.Detect(ctx, e)); len(o.Init.Tools) == 0 {
			o.Init.Tools = onboard.FallbackTools
		}
	}
	if o.Init.Provider == "" {
		o.Init.Provider = onboard.SuggestProvider(e)
	}
	r, err := onboard.Local(o)
	if r != nil && r.Install != nil {
		for i := range r.Install.Files {
			r.Install.Files[i].Content = "" // the policy is in r.Policy; local_install show=true has the files
		}
	}
	return nil, r, err
}

func (s *srv) localInstall(_ context.Context, _ *mcp.CallToolRequest, in installIn) (*mcp.CallToolResult, installOut, error) {
	argv := []string{"halo", "onboard", "install", "--policy-dir", s.dir, "--apply"}
	if in.Root != "" {
		argv = append(argv, "--root", in.Root)
	}
	cli := shJoin(argv...)
	w, err := s.mayWrite(in.DryRun, cli)
	if err != nil {
		return nil, installOut{}, err
	}
	p, written, err := onboard.Install(s.dir, in.Ring, or(s.env().GOOS, runtime.GOOS), in.Root, w, false) // ponytail: replacing a foreign file is a human CLI decision (--replace-existing)
	var refused string
	switch {
	case errors.Is(err, onboard.ErrForeign) && p != nil:
		refused = err.Error() // keep the plan: it shows which files are foreign
	case err != nil:
		return nil, installOut{}, err
	}
	if !in.Show {
		for i := range p.Files {
			p.Files[i].Content = ""
		}
	}
	out := installOut{DryRun: !w, Plan: p, Written: written}
	if refused != "" {
		out.Note = "refused, nothing written: " + refused + ". Stop and ask the human; only they may run the CLI with --replace-existing."
		return nil, out, nil
	}
	if !w && in.Root == "" {
		out.Note = "to write: the human runs `sudo " + cli + "` (admin-owned paths), or stage with root"
	}
	return nil, out, nil
}

// companyOut is the onboard_company result plus the answers the server filled
// in, so the agent sees exactly what was assumed.
type companyOut struct {
	onboard.CompanyResult
	// Assumed maps each defaulted answer to the value used.
	Assumed map[string]any `json:"assumed"`
	// Placeholders lists assumed answers that are example.com stand-ins: a
	// real write (dry_run false) is refused until they are given.
	Placeholders []string `json:"placeholders"`
}

// slug turns an org name into a DNS/registry-safe label.
func slug(org string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(org) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	if out := strings.Trim(b.String(), "-"); out != "" {
		return out
	}
	return "example"
}

func (s *srv) onboardCompany(ctx context.Context, _ *mcp.CallToolRequest, in companyIn) (*mcp.CallToolResult, *companyOut, error) {
	w, err := s.mayWrite(in.DryRun, "halo onboard company --policy-dir "+s.dir+" --apply (with the same answers as flags)")
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(in.Org) == "" {
		return nil, nil, fmt.Errorf(`org is required (e.g. {"org": "acme"}); every other answer has a default`)
	}
	ini := in.options()
	ini.Org, ini.Issuer, ini.ClientID, ini.Admins = strings.TrimSpace(in.Org), in.Issuer, in.ClientID, in.AdminGroups
	assumed, placeholders := map[string]any{}, []string{}
	def := func(field string, cur *string, v string, placeholder bool) {
		if strings.TrimSpace(*cur) != "" {
			return
		}
		*cur, assumed[field] = v, v
		if placeholder {
			placeholders = append(placeholders, field)
		}
	}
	sl := slug(ini.Org)
	if len(ini.Tools) == 0 {
		if ini.Tools = onboard.SuggestTools(onboard.Detect(ctx, s.env())); len(ini.Tools) == 0 {
			ini.Tools = onboard.FallbackTools
		}
		assumed["tools"] = ini.Tools
	}
	def("provider", &ini.Provider, "anthropic", false)
	def("client_id", &ini.ClientID, "halos", false)
	def("gateway", &ini.Gateway, "https://ai."+sl+".example.com", true)
	def("issuer", &ini.Issuer, "https://login."+sl+".example.com", true)
	gk, reg, repo, portal := in.GatewayKind, in.Registry, in.PolicyRepo, in.PortalURL
	def("gateway_kind", &gk, "halo-proxy", false)
	def("registry", &reg, "ghcr.io/"+sl+"/halos-releases", true)
	def("policy_repo", &repo, "https://github.com/"+sl+"/halos-policy.git", true)
	def("portal_url", &portal, "https://halos."+sl+".example.com", true)
	delivery := in.Delivery
	if len(delivery) == 0 {
		delivery = []string{"halod"}
		assumed["delivery"] = delivery
	}
	if in.Safety == "" {
		assumed["safety"] = ini.Safety
	}
	if in.Rollout == "" {
		assumed["rollout"] = ini.Rollout
	}
	if w && len(placeholders) > 0 {
		return nil, nil, fmt.Errorf("refusing to write example.com placeholders for %s: pass real values for them (dry_run true shows the full set), e.g. {\"org\": %q, \"issuer\": \"https://login.%s\"}",
			strings.Join(placeholders, ", "), ini.Org, "yourco.com")
	}
	o := onboard.CompanyOptions{Init: ini, GatewayKind: gk, AuthHelper: in.AuthHelper, Delivery: delivery,
		Registry: reg, PolicyRepo: repo, PortalURL: portal, HaloVersion: s.Version}
	r, err := onboard.WriteCompany(s.dir, o, w)
	if err != nil || r == nil {
		return nil, nil, err
	}
	return nil, &companyOut{CompanyResult: *r, Assumed: assumed, Placeholders: placeholders}, nil
}
