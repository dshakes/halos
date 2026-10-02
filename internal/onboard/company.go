package onboard

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/intent"
	"github.com/dshakes/halos/internal/policy"
)

// Company gateways and delivery channels.
var (
	Gateways   = []string{"halo-proxy", "kong"}
	Deliveries = []string{"devcontainer", "mdm", "halod"}
)

// CompanyOptions are an admin's interview answers.
type CompanyOptions struct {
	Init        intent.InitOptions // org, tools, provider, models, gateway, issuer, client id, admins, presets
	GatewayKind string             // halo-proxy | kong
	AuthHelper  string             // command printing a short-lived gateway token on each laptop (optional)
	Delivery    []string           // devcontainer | mdm | halod
	Registry    string             // OCI repository releases are published to
	PolicyRepo  string             // git URL of this policy repo (Helm git-sync)
	PortalURL   string             // halo-server base URL
	HaloVersion string             // halo the CI workflow installs ("" or "dev" = latest)
}

func (o *CompanyOptions) check() error {
	if !slices.Contains(Gateways, o.GatewayKind) {
		return fmt.Errorf("gateway kind %q: want %s", o.GatewayKind, strings.Join(Gateways, " or "))
	}
	if len(o.Delivery) == 0 {
		return fmt.Errorf("delivery: pick at least one of %s", strings.Join(Deliveries, ", "))
	}
	for _, d := range o.Delivery {
		if !slices.Contains(Deliveries, d) {
			return fmt.Errorf("delivery %q: want %s", d, strings.Join(Deliveries, ", "))
		}
	}
	for name, v := range map[string]string{"issuer": o.Init.Issuer, "portal URL": o.PortalURL, "gateway URL": o.Init.Gateway} {
		if u, err := url.Parse(v); err != nil || u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("%s %q: want an https URL", name, v)
		}
	}
	if o.Registry == "" || strings.Contains(o.Registry, "://") {
		return fmt.Errorf("registry %q: want an OCI repository like ghcr.io/acme/halos-releases", o.Registry)
	}
	if o.PolicyRepo == "" {
		return fmt.Errorf("policy repo: want the git URL Helm's git-sync clones (e.g. https://github.com/acme/halos-policy.git)")
	}
	return nil
}

// Company generates a policy repo for an organisation: halos.yaml, an
// optional Gateway overlay for the token helper, Helm values, the IdP client
// registration, enrollment config per delivery channel, a CI workflow, a smoke
// eval suite and a README of next steps. Keys are paths relative to the repo.
// Nothing here is secret: every credential is a reference to a Secret or env var.
// Everything but halos.yaml and gateway.yaml lives under .halos/: the policy
// loader reads every other YAML file in the repo as a policy document.
func Company(o CompanyOptions) (map[string][]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	in := o.Init
	if in.ClientID == "" {
		in.ClientID = "halos"
	}
	if _, err := in.Complete(nil); err != nil {
		return nil, err
	}
	portal := strings.TrimRight(o.PortalURL, "/")
	files := map[string][]byte{policy.RootFile: intent.InitFile(in)}

	if o.AuthHelper != "" {
		files["gateway.yaml"] = fmt.Appendf(nil, "# Overlay on the gateway halos.yaml generates: the command each laptop runs for a\n"+
			"# short-lived gateway token (Claude Code apiKeyHelper, Codex env_key source).\n"+
			"apiVersion: %s\nkind: Gateway\nname: %s\nauth: {helperCommand: %q, ttlSeconds: 900}\n",
			policy.APIVersion, policy.SimpleGatewayName(in.Org), o.AuthHelper)
	}

	files[".halos/helm-values.yaml"] = helmValues(o, in, portal)
	files[".halos/oidc-client.yaml"] = fmt.Appendf(nil, `# Register ONE OIDC client for Halos in your IdP (%[1]s), then create the
# Secret at the bottom. Nothing in this file is secret.
issuer: %[1]s
clientID: %[2]s
redirectURIs: [%[3]s/auth/callback]   # halo-server portal login
grantTypes: [authorization_code]
scopes: [openid, profile, email]
claims:
  user: email      # policy identity.userClaim default
  groups: groups   # policy identity.groupsClaim default; add a groups claim to the ID and access tokens
audience: halos    # the gateway accepts bearer tokens for this audience (identity.audience)
adminGroups: [%[4]s]
# A human creates the client secret Secret (never commit it):
#   kubectl -n halos create secret generic halos-oidc --from-literal=client-secret='<from your IdP>'
`, in.Issuer, in.ClientID, portal, strings.Join(in.Admins, ", "))

	for _, d := range o.Delivery {
		switch d {
		case "halod", "mdm":
			files[".halos/enroll/halod.yaml"] = fmt.Appendf(nil, `# halod config for managed laptops and CI runners (%[1]s). Install it root-owned:
#   macOS: /Library/Halos/etc/halod.yaml   Linux: /etc/halos/halod.yaml
registry: %[2]s
org: %[3]s
ringEndpoint: %[4]s/api/v1/fleet/ring   # the server picks the ring from the device's identity
pubkey: /etc/halos/release.pub          # macOS: /Library/Halos/etc/release.pub
interval: 15m
reportURL: %[4]s/api/v1/fleet/report
deviceTokenFile: /etc/halos/device.token   # mode 0600; issued by portal enrollment
`, d, o.Registry, in.Org, portal)
		case "devcontainer":
			files[".halos/enroll/devcontainer.json"] = fmt.Appendf(nil, `{
  "name": "%[1]s-dev",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
  "features": {
    "REPLACE_WITH_YOUR_FEATURE_REF/halos:0": {
      "registry": "%[2]s",
      "org": "%[1]s",
      "ring": "%[3]s",
      "pubkeyPem": "REPLACE_WITH_RELEASE_PUBLIC_KEY_PEM",
      "halodUrl": "REPLACE_WITH_HALOD_URL/{os}-{arch}/halod",
      "halodSha256": "amd64=REPLACE,arm64=REPLACE",
      "gatewayHost": "%[4]s",
      "firewall": true
    }
  },
  "runArgs": ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"]
}
`, in.Org, o.Registry, lastRing(in.Rollout), hostOf(in.Gateway))
		}
	}

	files[".github/workflows/halos.yml"] = ciWorkflow(o.HaloVersion, lastRing(in.Rollout))
	tools := sortedTools(in.Tools)
	if suite := smokeSuite(in, tools); suite != nil { // copilot-cli alone has no eval driver
		files[".halos/evals/suites/onboarding-smoke.yaml"] = suite
		files[".halos/evals/tasks/hello-halos/task.yaml"] = []byte(`id: hello-halos
repo: repo
prompt: Create a file named HELLO.txt whose only content is the word halos.
check: test "$(tr -d '[:space:]' < HELLO.txt)" = halos
timeout: 5m
budget_usd: 0.25
max_turns: 5
tags: [smoke, onboarding]
`)
		files[".halos/evals/tasks/hello-halos/repo/README.md"] = []byte("Smoke-test workspace for the onboarding eval.\n")
	}
	files["README.md"] = companyReadme(o, in, tools)
	return files, nil
}

func helmValues(o CompanyOptions, in intent.InitOptions, portal string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# Values for deploy/helm/halos, generated by `halo onboard company`. Review every line.\n"+
		"# Secrets are references to Secrets a human creates; this file holds none.\n"+
		"policy:\n  gitSync:\n    repo: %s\n    ref: main\n"+
		"server:\n  portal:\n    baseURL: %s\n  oidcClientSecret: {existingSecret: halos-oidc, key: client-secret}\n", o.PolicyRepo, portal)
	if o.GatewayKind == "kong" {
		fmt.Fprintf(&b, "proxy:\n  enabled: false\nkong:\n  enabled: true\n  config:\n    policy_path: /policy/gateway.compiled.json\n"+
			"    identity_mode: jwt\n    issuer: %s\n    audience: halos\n", in.Issuer)
	} else {
		fmt.Fprintf(&b, "proxy:\n  enabled: true\n  config:\n    identity:\n      mode: jwt\n      issuer: %s\n      audience: halos\n", in.Issuer)
		if in.Provider == "bedrock" {
			b.WriteString("  # Bedrock is SigV4-signed with the AWS credential chain: bind an IAM role to the proxy (IRSA shown).\n" +
				"  serviceAccount: {create: true, annotations: {eks.amazonaws.com/role-arn: REPLACE_WITH_ROLE_ARN}}\n")
		}
		if in.Provider == "anthropic" || in.Provider == "openai" || in.Provider == "gemini" {
			b.WriteString("  # The provider key comes from a Secret you create, injected as an env var halo-proxy expands.\n" +
				"  extraEnv: [{name: " + providerEnvs[in.Provider][0] + ", valueFrom: {secretKeyRef: {name: halos-provider, key: api-key}}}]\n")
		}
	}
	return []byte(b.String())
}

func lastRing(preset string) string {
	rp, err := policy.LookupRolloutPreset(preset)
	if err != nil || len(rp.Rings) == 0 {
		return ""
	}
	return rp.Rings[len(rp.Rings)-1].Name
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return p.Hostname()
}

func sortedTools(m map[string]string) []string {
	var out []string
	for t := range m {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

func ciWorkflow(haloVersion, ring string) []byte {
	ver := ""
	if haloVersion != "" && haloVersion != "dev" {
		ver = " --version " + haloVersion
	}
	return fmt.Appendf(nil, `# Validate and plan every policy change. Publishing a release is a separate,
# human-approved job (halo release publish); this workflow never publishes.
name: halos
on:
  pull_request:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  validate-plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install halo
        run: |
          curl -fsSL https://raw.githubusercontent.com/dshakes/halos/main/install/install.sh | sh -s --%[1]s
          echo "$HOME/.local/bin" >> "$GITHUB_PATH"
      - run: halo validate --policy-dir .
      - run: halo plan --policy-dir . --ring %[2]s
`, ver, ring)
}

// evalDriver maps a tool to its `halo eval run` driver.
var evalDriver = map[string]string{"claude-code": "claude", "codex": "codex", "gemini-cli": "gemini"}

func smokeSuite(in intent.InitOptions, tools []string) []byte {
	var b strings.Builder
	b.WriteString("# One tiny task per CLI: proves each pinned CLI + model completes work end to end.\n" +
		"# Run: halo eval run .halos/evals/suites/onboarding-smoke.yaml --network bridge --pass-env <KEY_VAR>\n" +
		"name: onboarding-smoke\ntasks: [hello-halos]\nrepeats: 1\nvariants:\n")
	n := 0
	for _, t := range tools {
		d, ok := evalDriver[t]
		if !ok {
			continue
		}
		alias := "default"
		if a := in.ToolModels[t]; a != "" {
			alias = a
		}
		_, model := policy.SplitModel(in.Models[alias], in.Provider)
		fmt.Fprintf(&b, "  - {name: %s, harness: %s, version: %q, model: %q}\n", t, d, in.Tools[t], model)
		n++
	}
	if n == 0 {
		return nil
	}
	return []byte(b.String())
}

func companyReadme(o CompanyOptions, in intent.InitOptions, tools []string) []byte {
	ring := lastRing(in.Rollout)
	var b strings.Builder
	fmt.Fprintf(&b, "# %s AI coding CLI policy (Halos)\n\nGenerated by `halo onboard company`. Tools: %s. Provider: %s. Gateway: %s (%s).\n\n",
		in.Org, strings.Join(tools, ", "), in.Provider, in.Gateway, o.GatewayKind)
	b.WriteString("## Check it (safe, local)\n\n```sh\nhalo validate --policy-dir .\nhalo plan --policy-dir . --ring " + ring + "\nhalo explain --policy-dir .\n```\n\n")
	b.WriteString("## Human steps, in order (each is outward-facing: an admin runs it)\n\n")
	b.WriteString("1. Review and merge this repo's PR. CI (`.github/workflows/halos.yml`) validates and plans; it never publishes.\n")
	fmt.Fprintf(&b, "2. Register the OIDC client in `.halos/oidc-client.yaml` with your IdP and create the `halos-oidc` Secret it describes.\n")
	b.WriteString("3. Generate the release signing key and keep the private half in CI secrets or KMS: `halo keys generate --name release`.\n")
	fmt.Fprintf(&b, "4. Deploy the control plane: `helm upgrade --install halo deploy/helm/halos -n halos -f .halos/helm-values.yaml` (from a Halos checkout).\n")
	fmt.Fprintf(&b, "5. Publish the first release per ring: `halo release publish --ring %s --release-version 0.1.0 --registry %s --key release.key`.\n", ring, o.Registry)
	for _, d := range o.Delivery {
		switch d {
		case "halod":
			b.WriteString("6. Enroll laptops and CI runners with halod using `.halos/enroll/halod.yaml` (or the portal's enroll script).\n")
		case "mdm":
			fmt.Fprintf(&b, "6. Export MDM payloads: `halo export jamf --registry %s --pubkey release.pub --ring %s --org %s --download-url <halod URL> --halod-sha256 <os/arch=hex> --out dist/jamf` (or `halo export intune`).\n", o.Registry, ring, in.Org)
		case "devcontainer":
			b.WriteString("6. Fill in the REPLACE_ placeholders in `.halos/enroll/devcontainer.json` and add it to your repos' `.devcontainer/`.\n")
		}
	}
	b.WriteString("\nThen roll changes ring by ring with `halo upgrade start` / `halo model switch` and the halos-rollout skill.\n")
	return []byte(b.String())
}
