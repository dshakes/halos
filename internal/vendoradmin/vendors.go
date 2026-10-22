package vendoradmin

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // the claude-code and codex adapters render the exported artifacts
	"github.com/dshakes/halos/internal/harness/hutil"
	"github.com/dshakes/halos/internal/policy"
)

type input struct {
	org     *policy.Org
	ring    string
	profile *policy.Profile
	target  policy.VendorTarget
}

type vendor struct {
	name   string
	target func(*policy.VendorAdmin) *policy.VendorTarget
	render func(input) (*Plan, error)
}

// registry is in render order. Sources for every mapping are in ADR-0025.
var registry = []vendor{
	{"claude", func(v *policy.VendorAdmin) *policy.VendorTarget { return v.Claude }, renderClaude},
	{"codex", func(v *policy.VendorAdmin) *policy.VendorTarget { return v.Codex }, renderCodex},
	{"gemini", func(v *policy.VendorAdmin) *policy.VendorTarget { return v.Gemini }, renderGemini},
	{"copilot", func(v *policy.VendorAdmin) *policy.VendorTarget { return v.Copilot }, renderCopilot},
	{"cursor", func(v *policy.VendorAdmin) *policy.VendorTarget { return v.Cursor }, renderCursor},
}

// adapterArtifact renders the harness adapter for in and returns the files
// named in want (base name -> artifact name) as artifacts, with the adapter's
// warnings and one warning per other rendered file (those reach machines
// only, through halod).
func adapterArtifact(in input, adapter string, want map[string]string) (*Plan, error) {
	ad, ok := harness.Get(adapter)
	if !ok {
		return nil, fmt.Errorf("adapter %s is not registered", adapter)
	}
	files, warns, err := ad.Render(in.profile, harness.Context{Gateway: in.org.Gateway, Ring: in.ring, Release: "console", OS: harness.Linux})
	if err != nil {
		return nil, err
	}
	p := &Plan{Warnings: append([]string{}, warns...)}
	for _, f := range files {
		if name, ok := want[path.Base(f.Path)]; ok {
			p.Artifacts = append(p.Artifacts, Artifact{Name: name, Content: string(f.Data)})
			continue
		}
		p.Warnings = append(p.Warnings, fmt.Sprintf("%s has no console equivalent; it reaches machines only through halod", f.Path))
	}
	if len(p.Artifacts) == 0 {
		return nil, fmt.Errorf("adapter %s rendered none of %v", adapter, hutil.SortedKeys(want))
	}
	return p, nil
}

// renderClaude: Claude Code server-managed settings take the same JSON as
// managed-settings.json, and there is no API for them (console only).
func renderClaude(in input) (*Plan, error) {
	p, err := adapterArtifact(in, "claude-code", map[string]string{"managed-settings.json": "claude-managed-settings.json"})
	if err != nil {
		return nil, err
	}
	p.Warnings = append(p.Warnings,
		"claude: server-managed settings and halod's managed-settings.json do not merge; a session that fetches server-managed settings uses them instead of the file (apart from the documented per-key exceptions), so paste this artifact unchanged",
		"claude: sessions that authenticate with apiKeyHelper or a custom ANTHROPIC_BASE_URL (the Halos gateway) do not fetch server-managed settings; the console reaches claude.ai Team/Enterprise logins only")
	p.Manual = []string{
		"Sign in to claude.ai as an organization Owner; open Organization settings > Claude Code > Managed settings (https://claude.ai/admin-settings/claude-code).",
		"Replace the JSON with claude-managed-settings.json and save. If the editor reports schema warnings, stop and fix the policy rather than saving with errors.",
		"Re-run `halo admin export` after every policy change that touches this ring's profile: there is no read API, so drift cannot be detected.",
	}
	return p, nil
}

// renderCodex: ChatGPT workspace "Agent security" takes enforced
// requirements (requirements.toml) and defaults (config.toml) as TOML; no
// public write API is documented.
func renderCodex(in input) (*Plan, error) {
	p, err := adapterArtifact(in, "codex", map[string]string{"requirements.toml": "codex-requirements.toml", "managed_config.toml": "codex-config.toml"})
	if err != nil {
		return nil, err
	}
	if len(in.profile.Telemetry.Attributes) > 0 {
		p.Warnings = append(p.Warnings, "codex: telemetry.attributes ride on halod's OTEL wrapper script; the console cannot carry them")
	}
	p.Warnings = append(p.Warnings,
		"codex: Agent Security requirements rank above halod's /etc/codex/requirements.toml but below the legacy managed_config.toml halod also writes and below MDM (scalars and lists override, tables merge); paste these artifacts unchanged so the layers agree",
		"codex: authentication fields in cloud-managed requirements are ignored; login restrictions reach machines only through halod")
	p.Manual = []string{
		"Sign in to ChatGPT as a workspace owner, admin or Codex admin; open Admin Console > Agent security > Workspace default.",
		"Choose Edit as TOML, paste codex-requirements.toml as the requirements and codex-config.toml as the defaults, and save. Do not add overrides that grant more than the workspace default.",
		"There is no documented read API: re-run `halo admin export` after policy changes.",
	}
	return p, nil
}

// Gemini for Google Cloud settings resources Halos owns, all named halos.
const settingID = "halos"

func geminiKey(kind, field string) string { return kind + "/" + settingID + "." + field }

// renderGemini: Gemini Code Assist logging and release channel through the
// cloudaicompanion settings API, each bound to the target project.
func renderGemini(in input) (*Plan, error) {
	p, t := &Plan{}, in.target
	bind := "projects/" + t.Project
	tel := in.profile.Telemetry
	p.Desired = []Setting{
		{Key: geminiKey("loggingSettings", "logMetadata"), Value: tel.Enabled, From: "telemetry.enabled", Access: AccessWrite, Strict: true},
		{Key: geminiKey("loggingSettings", "logPromptsAndResponses"), Value: tel.Enabled && tel.LogPrompts, From: "telemetry.logPrompts", Access: AccessWrite, Strict: true},
		{Key: geminiKey("loggingSettings", "binding"), Value: bind, From: "vendorAdmin.gemini.project", Access: AccessWrite},
	}
	if t.ReleaseChannel != "" {
		p.Desired = append(p.Desired,
			Setting{Key: geminiKey("releaseChannelSettings", "releaseChannel"), Value: strings.ToUpper(t.ReleaseChannel), From: "vendorAdmin.gemini.releaseChannel", Access: AccessWrite, Strict: "STABLE"},
			Setting{Key: geminiKey("releaseChannelSettings", "binding"), Value: bind, From: "vendorAdmin.gemini.project", Access: AccessWrite})
	}
	if tel.LogPrompts && !tel.Enabled {
		p.Warnings = append(p.Warnings, "gemini: telemetry.logPrompts without telemetry.enabled renders logPromptsAndResponses false")
	}
	p.Warnings = append(p.Warnings,
		"gemini: Gemini Code Assist logging records IDE interactions only, not Gemini CLI; the CLI's telemetry comes from halod's system settings")
	p.Warnings = append(p.Warnings, hutil.WarnUnsupported("gemini console", in.profile, "telemetry.enabled", "telemetry.logPrompts")...)
	return p, nil
}

// copilotHarness is the adapter whose presence in the profile enables Copilot CLI org-wide.
const copilotHarness = "copilot-cli"

// renderCopilot: org content exclusion (read and write) from Read() denies,
// and the Copilot CLI policy (read only, through the billing summary).
func renderCopilot(in input) (*Plan, error) {
	p := &Plan{}
	var globs []string
	other := 0
	for _, d := range in.profile.Permissions.Deny {
		g, ok := readDenyGlob(d)
		switch {
		case !ok:
			other++
		case g == "":
			p.Warnings = append(p.Warnings, fmt.Sprintf("copilot: deny %q is relative to the home directory; content exclusion has no home-relative form, not rendered", d))
		default:
			globs = append(globs, g)
		}
	}
	slices.Sort(globs)
	globs = slices.Compact(globs)
	if len(globs) > 0 {
		p.Desired = append(p.Desired, Setting{Key: "content_exclusion.*", Value: globs, From: "permissions.deny", Access: AccessWrite})
		p.Warnings = append(p.Warnings, "copilot: content exclusion is not enforced by Copilot CLI or agent mode in IDE chat, and org rules cover only seats that org assigns; halod's rendered denies still apply on machines")
	}
	if other > 0 {
		p.Warnings = append(p.Warnings, fmt.Sprintf("copilot: %d permissions.deny entries are not Read() rules and have no console equivalent", other))
	}
	cli := "disabled"
	if _, ok := in.profile.Harnesses[copilotHarness]; ok {
		cli = "enabled"
	}
	p.Desired = append(p.Desired, Setting{Key: "billing.cli", Value: cli, From: "harnesses." + copilotHarness, Access: AccessRead, Strict: "disabled"})
	p.Manual = []string{
		fmt.Sprintf("Organization settings > Copilot > Policies (https://github.com/organizations/%s/settings/copilot/policies): set Copilot CLI to %s. GitHub publishes no write API for policies; `halo admin plan` reads it back.", in.target.Org, cli),
	}
	p.Warnings = append(p.Warnings, hutil.WarnUnsupported("copilot console", in.profile, "permissions.deny")...)
	return p, nil
}

// readDenyGlob turns a Claude-style Read(...) deny into a content exclusion
// path ("" when it cannot be expressed). ok is false for any other rule.
func readDenyGlob(rule string) (string, bool) {
	inner, ok := strings.CutPrefix(rule, "Read(")
	if !ok || !strings.HasSuffix(inner, ")") {
		return "", false
	}
	g := strings.TrimSuffix(inner, ")")
	switch {
	case strings.HasPrefix(g, "~"):
		return "", true
	case strings.HasPrefix(g, "//"):
		return g[1:], true
	case strings.HasPrefix(g, "./"):
		return "/" + g[2:], true
	}
	return g, true
}

// renderCursor: the Cursor Admin API's model-access endpoints are a preview
// keyed by Cursor's own model ids, which policy aliases do not name; the
// allowlist is exported for an admin to set in the dashboard.
func renderCursor(in input) (*Plan, error) {
	p := &Plan{}
	m := in.profile.Models
	var lines []string
	if m.Enforce && len(m.Allowed) > 0 {
		for _, alias := range m.Allowed {
			var ids []string
			if in.org.Gateway != nil {
				for _, t := range in.org.Gateway.Models[alias].Candidates() {
					ids = append(ids, t.Model)
				}
			}
			lines = append(lines, fmt.Sprintf("- %s (provider model ids: %s)", alias, strings.Join(ids, ", ")))
		}
		p.Artifacts = []Artifact{{Name: "cursor-models.md", Content: "# Cursor team model allowlist\n\nEnable only the Cursor models that correspond to these policy aliases:\n\n" + strings.Join(lines, "\n") + "\n"}}
		p.Manual = []string{
			"As a Cursor team admin, restrict the team's models in the dashboard to the ones listed in cursor-models.md.",
			"Cursor's traffic does not pass the Halos gateway, so the dashboard is the only enforcement for Cursor's model choice.",
		}
	} else if len(m.Allowed) > 0 {
		p.Warnings = append(p.Warnings, "cursor: models.allowed is not enforced (models.enforce false); no Cursor model allowlist exported")
	}
	p.Warnings = append(p.Warnings, hutil.WarnUnsupported("cursor console", in.profile, "models.allowed", "models.enforce")...)
	return p, nil
}
