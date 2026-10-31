package controller

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
)

// Event kinds: what per-sink filters (--notify-<sink>-events) select on. An
// experiment's events are "experiment.<verdict>", a rollout's are
// "rollout.<verdict or action>", and an all-clear is "resolved".
const (
	KindResolved = "resolved"

	KindExperimentRollback = "experiment.rollback"
	KindExperimentPromote  = "experiment.promote"
	KindExperimentExpired  = "experiment.expired"
	KindExperimentKilled   = "experiment.killed"

	KindRolloutRollback         = "rollout.rollback"
	KindRolloutPause            = "rollout.pause"
	KindRolloutAdvance          = "rollout.advance"
	KindRolloutComplete         = "rollout.complete"
	KindRolloutKilled           = "rollout.killed"
	KindRolloutFrozen           = "rollout.frozen"
	KindRolloutAwaitingApproval = "rollout.awaiting_approval"
)

// EventKinds lists every kind the controller emits (resolved last).
var EventKinds = []string{
	KindExperimentRollback, KindExperimentPromote, KindExperimentExpired, KindExperimentKilled,
	KindRolloutRollback, KindRolloutPause, KindRolloutAdvance, KindRolloutComplete,
	KindRolloutKilled, KindRolloutFrozen, KindRolloutAwaitingApproval,
	KindResolved,
}

// Kind is the event's filter kind.
func (e Event) Kind() string {
	switch {
	case e.Resolved:
		return KindResolved
	case e.Rollout != "":
		return "rollout." + string(e.Verdict)
	}
	return "experiment." + string(e.Verdict)
}

// EventFilter is the set of kinds a sink delivers. nil means every event
// except resolved (what Slack and the webhook always received); a non-nil set
// is exact. A resolved event needs "resolved" in the set.
type EventFilter map[string]bool

// Allows reports whether the sink delivers e.
func (f EventFilter) Allows(e Event) bool {
	if f == nil {
		return !e.Resolved
	}
	return f[e.Kind()]
}

// ParseEventFilter parses a comma-separated kind list ("" = nil, the default;
// "all" = every trigger kind). allowResolved is false for sinks that cannot
// carry an all-clear (Slack, Teams).
func ParseEventFilter(flag, spec string, allowResolved bool) (EventFilter, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	f := EventFilter{}
	for _, k := range strings.Split(spec, ",") {
		k = strings.TrimSpace(k)
		switch {
		case k == "":
			continue
		case k == "all":
			for _, kk := range EventKinds {
				if kk != KindResolved {
					f[kk] = true
				}
			}
		case k == KindResolved && !allowResolved:
			return nil, fmt.Errorf("%s: this sink cannot deliver %q events", flag, k)
		case !slices.Contains(EventKinds, k):
			return nil, fmt.Errorf("%s: unknown event kind %q (valid: all, %s)", flag, k, strings.Join(EventKinds, ", "))
		default:
			f[k] = true
		}
	}
	if len(f) == 0 {
		return nil, fmt.Errorf("%s: no event kinds in %q", flag, spec)
	}
	return f, nil
}

// Sink is one named delivery channel: a Notifier behind an event filter, with
// delivery counters. The name is the channel key in the controller's state
// (ActionNotify + ":" + name), so a failing sink is retried without
// re-posting to the others.
type Sink struct {
	SinkName string
	Notifier Notifier
	Events   EventFilter

	ok, failed, filtered atomic.Uint64
}

// Name implements Named.
func (s *Sink) Name() string { return s.SinkName }

// Notify delivers e unless the filter drops it (a dropped event reports
// success: it is not an error and must not be retried).
func (s *Sink) Notify(ctx context.Context, e Event) error {
	if !s.Events.Allows(e) {
		s.filtered.Add(1)
		return nil
	}
	if err := s.Notifier.Notify(ctx, e); err != nil {
		s.failed.Add(1)
		return err
	}
	s.ok.Add(1)
	return nil
}

// ResolvesFor reports whether this sink wants the all-clear for trigger: it
// opted into "resolved" and also receives trigger's kind (so a resolve is
// never sent for an incident the sink never opened).
func (s *Sink) ResolvesFor(trigger Event) bool {
	if s.Events == nil || !s.Events[KindResolved] {
		return false
	}
	trigger.Resolved = false
	return s.Events.Allows(trigger)
}

// resolver is implemented by notifiers that deliver all-clears.
type resolver interface {
	ResolvesFor(trigger Event) bool
}

// WriteMetrics writes halo_controller_notifications_total per sink.
func (ns Notifiers) WriteMetrics(w io.Writer) {
	var sinks []*Sink
	for _, n := range ns {
		if s, ok := n.(*Sink); ok {
			sinks = append(sinks, s)
		}
	}
	if len(sinks) == 0 {
		return
	}
	sort.Slice(sinks, func(i, j int) bool { return sinks[i].SinkName < sinks[j].SinkName })
	fmt.Fprint(w, "# TYPE halo_controller_notifications_total counter\n")
	for _, s := range sinks {
		fmt.Fprintf(w, "halo_controller_notifications_total{sink=%q,result=\"ok\"} %d\n", s.SinkName, s.ok.Load())
		fmt.Fprintf(w, "halo_controller_notifications_total{sink=%q,result=\"error\"} %d\n", s.SinkName, s.failed.Load())
		fmt.Fprintf(w, "halo_controller_notifications_total{sink=%q,result=\"filtered\"} %d\n", s.SinkName, s.filtered.Load())
	}
}
