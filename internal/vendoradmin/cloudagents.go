package vendoradmin

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/dshakes/halos/internal/policy"
)

// Cloud agent console settings (ADR-0034). Only the Copilot cloud agent's
// per-repository firewall has a public API, and it is read-only (public
// preview); everything else is a manual step. Sources in ADR-0034.

// cloudKeyPrefix starts the Copilot cloud agent settings' keys:
// cloud_agent.<owner>/<repo>.<field>, in the API's own field names.
const cloudKeyPrefix = "cloud_agent."

// addCloudAgents adds vendor's cloudAgents console settings and steps to p.
func addCloudAgents(vendor string, org *policy.Org, p *Plan) {
	a := org.CloudAgents.Vendor(vendor)
	if a == nil {
		return
	}
	state := "on"
	if !a.Enabled {
		state = "off"
	}
	repos := "every repository"
	if len(a.Repos) > 0 {
		repos = strings.Join(a.Repos, ", ")
	}
	switch vendor {
	case policy.CloudClaude:
		p.Manual = append(p.Manual, fmt.Sprintf("Cloud sessions: at claude.ai Organization settings > Claude Code, turn remote (cloud) sessions %s (the allow_remote_sessions policy). No public API.", state))
		if n := a.Network; n != nil && a.Enabled {
			p.Manual = append(p.Manual, "Cloud sessions: create an organization-shared cloud environment with network access "+claudeNetwork(n)+" and ask members to use it; each environment sets its own level, and no organization-wide allowlist exists.")
		}
		p.Warnings = append(p.Warnings, "claude: cloud sessions cannot be listed or cancelled through a public API; halo-server sees the Claude Code GitHub Action through webhooks only")
	case policy.CloudCodex:
		p.Manual = append(p.Manual, fmt.Sprintf("Codex cloud: in ChatGPT workspace settings, set Codex cloud access (the \"Use Codex in the cloud\" permission) %s for members.", state))
		if n := a.Network; n != nil && a.Enabled {
			p.Manual = append(p.Manual, "Codex cloud environments: set agent internet access to "+codexNetwork(n)+".")
		}
		p.Warnings = append(p.Warnings, "codex: Codex cloud publishes no task API; its tasks are invisible to inventory and kill (cancel them in ChatGPT)")
	case policy.CloudCursor:
		p.Manual = append(p.Manual, fmt.Sprintf("Cursor cloud agents: in the team dashboard, turn cloud agents %s for the team (repositories: %s).", state, Sanitize(repos)))
		if a.Network != nil {
			p.Warnings = append(p.Warnings, "cursor: cloud agents expose no egress setting Halos can verify; network is not rendered")
		}
	case policy.CloudCopilot:
		access := "Selected repositories: " + repos
		if len(a.Repos) == 0 {
			access = "All repositories"
		}
		if !a.Enabled {
			access = "No repositories"
		}
		p.Manual = append(p.Manual, fmt.Sprintf("Copilot cloud agent: Organization settings > Copilot > Cloud agent, set Repository access to %s. GitHub publishes no write API for it.", Sanitize(access)))
		if n := a.Network; n != nil && a.Enabled {
			for _, r := range a.Repos {
				if strings.HasSuffix(r, "/*") {
					continue
				}
				k := cloudKeyPrefix + r + "."
				p.Desired = append(p.Desired,
					Setting{Key: k + "is_firewall_enabled", Value: n.Mode != policy.NetworkFull, From: "cloudAgents.copilot.network.mode", Access: AccessRead, Strict: true},
					Setting{Key: k + "is_firewall_recommended_allowlist_enabled", Value: n.Recommended, From: "cloudAgents.copilot.network.recommended", Access: AccessRead, Strict: false},
					// A joined string, not a list: for an allowlist an extra live entry
					// loosens, the opposite of Diff's list rule (content exclusion).
					Setting{Key: k + "custom_allowlist", Value: joinSorted(n.Allow), From: "cloudAgents.copilot.network.allow", Access: AccessRead})
			}
			p.Manual = append(p.Manual, "Copilot cloud agent: Organization settings > Copilot > Internet access: firewall Enabled, recommended allowlist "+onOff(n.Recommended)+
				", custom allowlist "+Sanitize(orNone(n.Allow))+". `halo admin plan` reads each listed repository's effective setting back.")
		}
	}
}

func joinSorted(l []string) string {
	l = slices.Clone(l)
	slices.Sort(l)
	return strings.Join(slices.Compact(l), ",")
}

func onOff(b bool) string {
	if b {
		return "Enabled"
	}
	return "Disabled"
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "(none)"
	}
	return strings.Join(l, ", ")
}

// claudeNetwork maps a network policy to a Claude cloud environment access
// level: None, Trusted (the default package registries), Custom or Full.
func claudeNetwork(n *policy.CloudNetwork) string {
	switch {
	case n.Mode == policy.NetworkNone:
		return "None"
	case n.Mode == policy.NetworkFull:
		return "Full"
	case len(n.Allow) == 0:
		return "Trusted"
	case n.Recommended:
		return "Custom, allowed domains " + Sanitize(strings.Join(n.Allow, ", ")) + ", with \"Also include default list of common package managers\""
	}
	return "Custom, allowed domains " + Sanitize(strings.Join(n.Allow, ", ")) + " only"
}

// codexNetwork maps a network policy to Codex cloud's agent internet access.
func codexNetwork(n *policy.CloudNetwork) string {
	switch {
	case n.Mode == policy.NetworkNone:
		return "Off"
	case n.Mode == policy.NetworkFull:
		return "On, allowlist All (unrestricted)"
	case n.Recommended:
		return "On, allowlist Common dependencies plus " + Sanitize(orNone(n.Allow)) + ", HTTP methods GET, HEAD and OPTIONS only"
	}
	return "On, allowlist None plus " + Sanitize(orNone(n.Allow)) + ", HTTP methods GET, HEAD and OPTIONS only"
}

// copilotCloudRead reads GET /repos/{owner}/{repo}/copilot/cloud-agent/configuration
// (public preview) for every repository p has cloud agent settings for.
func (c *Client) copilotCloudRead(ctx context.Context, p *Plan, cur map[string]any) error {
	var repos []string
	for _, s := range p.Desired {
		if rest, ok := strings.CutPrefix(s.Key, cloudKeyPrefix); ok {
			if r := rest[:strings.LastIndex(rest, ".")]; !slices.Contains(repos, r) {
				repos = append(repos, r)
			}
		}
	}
	for _, r := range repos {
		owner, name, _ := strings.Cut(r, "/")
		var cfg struct {
			Firewall    *bool    `json:"is_firewall_enabled"`
			Recommended *bool    `json:"is_firewall_recommended_allowlist_enabled"`
			Custom      []string `json:"custom_allowlist"`
		}
		if _, err := c.do(ctx, http.MethodGet, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(name)+"/copilot/cloud-agent/configuration", nil, &cfg); err != nil {
			return fmt.Errorf("copilot cloud agent %s: %w", r, err)
		}
		k := cloudKeyPrefix + r + "."
		if cfg.Firewall != nil {
			cur[k+"is_firewall_enabled"] = *cfg.Firewall
		}
		if cfg.Recommended != nil {
			cur[k+"is_firewall_recommended_allowlist_enabled"] = *cfg.Recommended
		}
		cur[k+"custom_allowlist"] = joinSorted(cfg.Custom)
	}
	return nil
}
