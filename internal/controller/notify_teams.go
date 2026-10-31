package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dshakes/halos/internal/promote"
)

// Teams posts an Adaptive Card to a Microsoft Teams Workflows (Power
// Automate) webhook: the "When a Teams webhook request is received" trigger
// (the "Send webhook alerts to a channel" template). It expects a
// {"type":"message","attachments":[{"contentType":
// "application/vnd.microsoft.card.adaptive","content":<card>}]} body, which is
// what this sends.
//
// This is deliberately not the legacy Office 365 connector ("Incoming
// Webhook", MessageCard JSON): Microsoft retired Office 365 connectors in
// Teams, and a legacy URL no longer delivers. NewTeams refuses those hosts so
// the failure is loud at startup instead of silent at 3 a.m.
type Teams struct {
	URL    string
	Client *http.Client
	Retry  RetryPolicy // zero: one attempt
}

// Name implements Named.
func (Teams) Name() string { return "teams" }

// teamsEscaper backslash-escapes the Markdown Teams renders in TextBlocks, so
// a free-text reason cannot inject formatting or a link.
var teamsEscaper = strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "[", `\[`, "]", `\]`, "`", "\\`", "~", `\~`, "<", `\<`, ">", `\>`)

// teamsColor is the Adaptive Card TextBlock color of the title.
func teamsColor(e Event) string {
	switch {
	case e.Resolved:
		return "Good"
	case e.Verdict == promote.Rollback:
		return "Attention"
	case e.Verdict == promote.Promote, e.Verdict == "advance", e.Verdict == "complete":
		return "Good"
	}
	return "Warning"
}

func (t Teams) Notify(ctx context.Context, e Event) error {
	scope, name := "experiment", e.Experiment
	if e.Rollout != "" {
		scope, name = "rollout", e.Rollout
	}
	title := fmt.Sprintf("Halos %s %s: %s", scope, teamsEscaper.Replace(name), strings.ToUpper(string(e.Verdict)))
	facts := []map[string]string{{"title": "Verdict", "value": string(e.Verdict)}}
	if e.Rollout != "" && e.Experiment != "" {
		facts = append(facts, map[string]string{"title": "Experiment", "value": teamsEscaper.Replace(e.Experiment)})
	}
	if e.Axis != "" {
		facts = append(facts, map[string]string{"title": "Axis", "value": e.Axis})
	}
	if e.KillOutcome != "" {
		facts = append(facts, map[string]string{"title": "Kill switch", "value": string(e.KillOutcome)})
	}
	if !e.At.IsZero() {
		facts = append(facts, map[string]string{"title": "At", "value": e.At.UTC().Format("2006-01-02 15:04:05 MST")})
	}
	body := []any{
		map[string]any{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "color": teamsColor(e), "wrap": true},
		map[string]any{"type": "TextBlock", "text": teamsEscaper.Replace(e.Text()), "wrap": true},
		map[string]any{"type": "FactSet", "facts": facts},
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard",
		"version": "1.4",
		"body":    body,
		"msteams": map[string]string{"width": "Full"},
	}
	if httpsURL(e.PRURL) {
		card["actions"] = []any{map[string]any{"type": "Action.OpenUrl", "title": "Open pull request", "url": e.PRURL}}
	}
	payload, err := json.Marshal(map[string]any{
		"type": "message",
		"attachments": []any{map[string]any{
			"contentType": "application/vnd.microsoft.card.adaptive",
			"contentUrl":  nil,
			"content":     card,
		}},
	})
	if err != nil {
		return fmt.Errorf("teams notify: encode: %w", err)
	}
	return deliver(ctx, t.Retry, t.Client, "teams", t.URL, payload, http.Header{})
}

// httpsURL reports whether v is an https URL worth linking.
func httpsURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

// legacyTeamsHost reports whether h is a retired Office 365 connector host.
func legacyTeamsHost(h string) bool {
	h = strings.ToLower(h)
	for _, s := range []string{"webhook.office.com", "outlook.office.com", "outlook.office365.com"} {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}
