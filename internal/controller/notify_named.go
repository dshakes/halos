package controller

import "strconv"

// Named is implemented by notifiers with a stable channel name. The controller
// records each channel's delivery separately (ActionNotify + ":" + name), so a
// failing webhook is retried without re-posting to Slack.
type Named interface {
	Name() string
}

// Name implements Named.
func (Slack) Name() string { return "slack" }

// Name implements Named.
func (Webhook) Name() string { return "webhook" }

// channels flattens n into per-channel notifiers keyed by a name that is
// unique within the list (unnamed or repeated ones get their index appended).
func channels(n Notifier) (names []string, ns []Notifier) {
	if n == nil {
		return nil, nil
	}
	ns, ok := n.(Notifiers)
	if !ok {
		ns = Notifiers{n}
	}
	seen := map[string]bool{}
	for i, x := range ns {
		name := strconv.Itoa(i)
		if nm, ok := x.(Named); ok {
			name = nm.Name()
		}
		if seen[name] {
			name += "#" + strconv.Itoa(i)
		}
		seen[name] = true
		names = append(names, name)
	}
	return names, ns
}
