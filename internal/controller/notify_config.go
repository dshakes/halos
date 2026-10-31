package controller

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"unicode"
)

// NotifyConfig is the notification setup shared by `halo controller run` and
// `halo-server --controller`. Every secret (a webhook URL embeds a token; a
// routing key is one) is read from a file, never from a flag value, and no
// error echoes one. A sink is on when its URL/key file is set.
type NotifyConfig struct {
	SlackURLFile, SlackEvents string
	TeamsURLFile, TeamsEvents string

	WebhookURLFile, WebhookSecretFile, WebhookEvents string

	PagerDutyRoutingKeyFile, PagerDutyEvents string
	PagerDutyURL                             string // "" = PagerDutyEventsURL (EU region, or a test double)

	Retry RetryPolicy // applied to every sink
}

// Build returns one Sink per configured channel, in a stable order.
func (c NotifyConfig) Build() (Notifiers, error) {
	var ns Notifiers
	add := func(name string, n Notifier, flag, spec string, allowResolved bool, def EventFilter) error {
		f, err := ParseEventFilter(flag, spec, allowResolved)
		if err != nil {
			return err
		}
		if f == nil {
			f = def
		}
		ns = append(ns, &Sink{SinkName: name, Notifier: n, Events: f})
		return nil
	}

	slack, err := readSecretFile("--notify-slack-url-file", c.SlackURLFile)
	if err != nil {
		return nil, err
	}
	if slack != "" {
		if err := checkHTTPURL("--notify-slack-url-file", slack); err != nil {
			return nil, err
		}
		if err := add("slack", Slack{URL: slack, Retry: c.Retry}, "--notify-slack-events", c.SlackEvents, false, nil); err != nil {
			return nil, err
		}
	} else if strings.TrimSpace(c.SlackEvents) != "" {
		return nil, errors.New("--notify-slack-events set without --notify-slack-url-file")
	}

	teams, err := readSecretFile("--notify-teams-url-file", c.TeamsURLFile)
	if err != nil {
		return nil, err
	}
	if teams != "" {
		if err := checkHTTPURL("--notify-teams-url-file", teams); err != nil {
			return nil, err
		}
		if u, _ := url.Parse(teams); legacyTeamsHost(u.Hostname()) {
			return nil, errors.New("--notify-teams-url-file: this is a retired Office 365 connector webhook; create a Teams Workflows (Power Automate) webhook instead")
		}
		if err := add("teams", Teams{URL: teams, Retry: c.Retry}, "--notify-teams-events", c.TeamsEvents, false, nil); err != nil {
			return nil, err
		}
	} else if strings.TrimSpace(c.TeamsEvents) != "" {
		return nil, errors.New("--notify-teams-events set without --notify-teams-url-file")
	}

	hook, err := readSecretFile("--notify-webhook-url-file", c.WebhookURLFile)
	if err != nil {
		return nil, err
	}
	secret, err := readSecretFile("--notify-webhook-secret-file", c.WebhookSecretFile)
	if err != nil {
		return nil, err
	}
	switch {
	case hook != "":
		if err := checkHTTPURL("--notify-webhook-url-file", hook); err != nil {
			return nil, err
		}
		if err := add("webhook", Webhook{URL: hook, Secret: []byte(secret), Retry: c.Retry}, "--notify-webhook-events", c.WebhookEvents, true, nil); err != nil {
			return nil, err
		}
	case secret != "":
		return nil, errors.New("--notify-webhook-secret-file set without --notify-webhook-url-file")
	case strings.TrimSpace(c.WebhookEvents) != "":
		return nil, errors.New("--notify-webhook-events set without --notify-webhook-url-file")
	}

	key, err := readSecretFile("--notify-pagerduty-routing-key-file", c.PagerDutyRoutingKeyFile)
	if err != nil {
		return nil, err
	}
	if key != "" {
		if strings.IndexFunc(key, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, errors.New("--notify-pagerduty-routing-key-file: not a routing key (contains whitespace)") // never echo it
		}
		if err := checkPagerDutyURL(c.PagerDutyURL); err != nil {
			return nil, err
		}
		if err := add("pagerduty", PagerDuty{RoutingKey: key, URL: c.PagerDutyURL, Retry: c.Retry}, "--notify-pagerduty-events", c.PagerDutyEvents, true, pagerDutyDefaultFilter()); err != nil {
			return nil, err
		}
	} else if strings.TrimSpace(c.PagerDutyEvents) != "" || c.PagerDutyURL != "" {
		return nil, errors.New("--notify-pagerduty-events/--notify-pagerduty-url set without --notify-pagerduty-routing-key-file")
	}
	return ns, nil
}

// NotifiersFromFiles builds the Slack and generic-webhook notifiers from
// secret files (any path may be ""), with no retries. NotifyConfig is the
// full form.
func NotifiersFromFiles(slackURLFile, webhookURLFile, webhookSecretFile string) (Notifiers, error) {
	return NotifyConfig{SlackURLFile: slackURLFile, WebhookURLFile: webhookURLFile, WebhookSecretFile: webhookSecretFile}.Build()
}

// readSecretFile returns the trimmed contents of p ("" for p == ""); the
// error names the flag and file, never the contents.
func readSecretFile(flag, p string) (string, error) {
	if p == "" {
		return "", nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", flag, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s: %s is empty", flag, p)
	}
	return v, nil
}

func checkHTTPURL(flag, v string) error {
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("%s: not an http(s) URL", flag) // never echo the URL
	}
	return nil
}

// checkPagerDutyURL: "" is the default; an override must be https, or http to
// a loopback address (a local test double), since the routing key is in the body.
func checkPagerDutyURL(v string) error {
	if v == "" {
		return nil
	}
	const flag = "--notify-pagerduty-url"
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%s: not an http(s) URL", flag)
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (ip != nil && ip.IsLoopback() || u.Hostname() == "localhost") {
		return nil
	}
	return fmt.Errorf("%s: must be https (the routing key is sent in the request body)", flag)
}

// FlagSet is the part of flag.FlagSet and pflag.FlagSet NotifyFlags needs, so
// halo-server and `halo controller run` register identical flags.
type FlagSet interface {
	StringVar(p *string, name, value, usage string)
}

// NotifyFlags registers the --notify-* flags on fs, filling c.
func NotifyFlags(fs FlagSet, c *NotifyConfig) {
	const events = "comma-separated event kinds to deliver (see the notifications guide; \"all\" = every kind)"
	fs.StringVar(&c.SlackURLFile, "notify-slack-url-file", "", "file holding a Slack incoming-webhook URL")
	fs.StringVar(&c.SlackEvents, "notify-slack-events", "", "Slack: "+events+"; default every event")
	fs.StringVar(&c.TeamsURLFile, "notify-teams-url-file", "", "file holding a Microsoft Teams Workflows (Power Automate) webhook URL; posts an Adaptive Card")
	fs.StringVar(&c.TeamsEvents, "notify-teams-events", "", "Teams: "+events+"; default every event")
	fs.StringVar(&c.WebhookURLFile, "notify-webhook-url-file", "", "file holding a generic webhook URL (JSON event, signed with X-Halo-Signature when a secret is set)")
	fs.StringVar(&c.WebhookSecretFile, "notify-webhook-secret-file", "", "file holding the webhook HMAC-SHA256 secret (X-Halo-Timestamp, X-Halo-Signature)")
	fs.StringVar(&c.WebhookEvents, "notify-webhook-events", "", "webhook: "+events+", plus resolved; default every event except resolved")
	fs.StringVar(&c.PagerDutyRoutingKeyFile, "notify-pagerduty-routing-key-file", "", "file holding a PagerDuty Events API v2 routing (integration) key")
	fs.StringVar(&c.PagerDutyURL, "notify-pagerduty-url", "", "PagerDuty Events API URL (default "+PagerDutyEventsURL+"; EU region: https://events.eu.pagerduty.com/v2/enqueue)")
	fs.StringVar(&c.PagerDutyEvents, "notify-pagerduty-events", "", "PagerDuty: "+events+", plus resolved; default "+strings.Join(PagerDutyPagingKinds, ","))
}
