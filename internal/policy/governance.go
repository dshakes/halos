package policy

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	// Freeze windows name IANA zones. Embedding the zone database makes every
	// binary (distroless images, Windows) agree on DST edges instead of
	// depending on the host's tzdata. ponytail: ~450 KB per binary; drop it
	// only if every deployment target ships tzdata.
	_ "time/tzdata"
)

// Governance is halos.yaml governance: (ADR-0030): when changes may go out
// (freeze windows) and who must approve them (approval rules).
type Governance struct {
	// Freezes are change-freeze windows. While one covers a change, the rollout
	// controller does not advance, and promotion and advance proposals are
	// refused. Rollbacks, pauses and the kill switch are always allowed.
	Freezes []FreezeWindow `yaml:"freezes,omitempty" json:"freezes,omitempty"`
	// Approvals are approver quorums. Every rule whose scope covers a change
	// must be met before it goes out.
	Approvals []ApprovalRule `yaml:"approvals,omitempty" json:"approvals,omitempty"`
}

// ChangeScope selects what a window or rule covers: changes to any listed
// ring or any listed unit's members. Empty is org-wide.
type ChangeScope struct {
	Rings []string `yaml:"rings,omitempty" json:"rings,omitempty"`
	Units []string `yaml:"units,omitempty" json:"units,omitempty"`
}

// FreezeWindow is one change-freeze window: one-off (start, end) or
// recurring every week (weekly), in Timezone.
type FreezeWindow struct {
	Name   string      `yaml:"name" json:"name"`
	Reason string      `yaml:"reason" json:"reason"`
	Scope  ChangeScope `yaml:"scope,omitempty" json:"scope,omitzero"`
	// Timezone is an IANA zone (America/New_York); default UTC. Start, End and
	// Weekly are wall-clock times there, so DST moves the instant, not the time.
	Timezone string `yaml:"timezone,omitempty" json:"timezone,omitempty"`
	// Start and End bound a one-off window [start, end): "2026-12-20T18:00",
	// "2026-12-20" (midnight) or RFC 3339 with an offset.
	Start string `yaml:"start,omitempty" json:"start,omitempty"`
	End   string `yaml:"end,omitempty" json:"end,omitempty"`
	// Weekly repeats every week from From to To.
	Weekly *WeeklyWindow `yaml:"weekly,omitempty" json:"weekly,omitempty"`
}

// WeeklyWindow is "Fri 18:00" to "Mon 06:00": a day (Mon..Sun) and a 24-hour
// time. A To at or before From in the week ends the following week.
type WeeklyWindow struct {
	From string `yaml:"from" json:"from"`
	To   string `yaml:"to" json:"to"`
}

// ApprovalRule requires Quorum approvals, from members of Groups, for every
// change its scope covers. The requester never counts.
type ApprovalRule struct {
	Name   string      `yaml:"name" json:"name"`
	Scope  ChangeScope `yaml:"scope,omitempty" json:"scope,omitzero"`
	Quorum int         `yaml:"quorum" json:"quorum"`
	// Groups are the IdP (or SCIM) groups an approver must hold one of.
	Groups []string `yaml:"groups" json:"groups"`
	// DistinctGroups: each counted approval must come from a different group.
	DistinctGroups bool `yaml:"distinctGroups,omitempty" json:"distinctGroups,omitempty"`
	// Ticket, when set, is a regular expression (matched whole) a change
	// ticket reference must match, e.g. ^(CHG|INC)[0-9]{7}$ or ^OPS-[0-9]+$.
	Ticket string `yaml:"ticket,omitempty" json:"ticket,omitempty"`
}

// ChangeTarget is what a change touches: rings and units.
type ChangeTarget struct {
	Rings []string `json:"rings,omitempty"`
	Units []string `json:"units,omitempty"`
}

func (s ChangeScope) covers(t ChangeTarget) bool {
	if len(s.Rings) == 0 && len(s.Units) == 0 {
		return true
	}
	return slices.ContainsFunc(s.Rings, func(r string) bool { return slices.Contains(t.Rings, r) }) ||
		slices.ContainsFunc(s.Units, func(u string) bool { return slices.Contains(t.Units, u) })
}

// RingTarget is a change to rings. A ring's members can come from any unit,
// so it touches every unit: a unit-scoped window or rule covers ring changes.
func (o *Org) RingTarget(rings ...string) ChangeTarget {
	t := ChangeTarget{Rings: rings}
	for _, u := range o.Units {
		t.Units = append(t.Units, u.Name)
	}
	return t
}

// SubjectTarget is a change for one subject (an access request): their ring
// and every unit of their unit chain.
func (o *Org) SubjectTarget(s Subject) ChangeTarget {
	var t ChangeTarget
	if r := o.ResolveRing(s); r != nil {
		t.Rings = []string{r.Name}
	}
	if u := o.ResolveUnit(s); u != nil {
		if chain, err := o.UnitChain(u.Name); err == nil {
			for _, c := range chain {
				t.Units = append(t.Units, c.Name)
			}
		}
	}
	return t
}

// ---- freezes ----

// IncidentFreezeName names the incident freeze halo-server toggles.
const IncidentFreezeName = "incident"

// ActiveFreeze is one window holding a change.
type ActiveFreeze struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
	// Until is the end of this occurrence; zero = until a human lifts it
	// (incident freeze) or never (a window that does not parse: fail closed).
	Until    time.Time `json:"until,omitzero"`
	Incident bool      `json:"incident,omitempty"`
	By       string    `json:"by,omitempty"`
}

// FreezeStatus is whether a change may go out now.
type FreezeStatus struct {
	Frozen bool           `json:"frozen"`
	Active []ActiveFreeze `json:"active,omitempty"`
	// NextOpen is the first instant no window covers the change. Zero while
	// an incident freeze holds, or when windows chain for over a year.
	NextOpen time.Time `json:"nextOpen,omitzero"`
}

// AddIncident adds the incident freeze (halo-server) to s.
func (s *FreezeStatus) AddIncident(by, reason string) {
	s.Frozen, s.NextOpen = true, time.Time{}
	s.Active = append(s.Active, ActiveFreeze{Name: IncidentFreezeName, Reason: reason, Incident: true, By: by})
}

// String is the refusal message: every active window and the next open time.
func (s FreezeStatus) String() string {
	if !s.Frozen {
		return "no change freeze"
	}
	var parts []string
	for _, a := range s.Active {
		p := fmt.Sprintf("%s (%s)", a.Name, a.Reason)
		switch {
		case a.Incident:
			p += " until lifted (halo freeze off)"
			if a.By != "" {
				p += ", set by " + a.By
			}
		case !a.Until.IsZero():
			p += " until " + a.Until.Format(time.RFC3339)
		}
		parts = append(parts, p)
	}
	msg := "change freeze: " + strings.Join(parts, "; ")
	if !s.NextOpen.IsZero() {
		msg += "; next open " + s.NextOpen.Format(time.RFC3339)
	}
	return msg + ". Rollbacks and the kill switch are always allowed"
}

// FreezeAt reports the policy windows covering target at t. The incident
// freeze lives on halo-server: callers add it (AddIncident).
func (o *Org) FreezeAt(t time.Time, target ChangeTarget) FreezeStatus {
	var ws []FreezeWindow
	if o.Governance != nil {
		for _, w := range o.Governance.Freezes {
			if w.Scope.covers(target) {
				ws = append(ws, w)
			}
		}
	}
	var st FreezeStatus
	for _, w := range ws {
		if end, on := w.activeAt(t); on {
			st.Frozen = true
			st.Active = append(st.Active, ActiveFreeze{Name: w.Name, Reason: w.Reason, Until: end})
		}
	}
	if !st.Frozen {
		return st
	}
	// Windows may overlap or abut: walk ends until none covers. A window that
	// never ends (unparseable) leaves NextOpen zero.
	cur := t
	for range 128 {
		latest, on := time.Time{}, false
		for _, w := range ws {
			end, active := w.activeAt(cur)
			if !active {
				continue
			}
			if end.IsZero() {
				return st
			}
			on = true
			if end.After(latest) {
				latest = end
			}
		}
		if !on {
			st.NextOpen = cur
			return st
		}
		cur = latest
	}
	return st
}

// activeAt reports whether w covers instant t and when that occurrence ends.
// A window that does not parse is active forever (fail closed); Validate
// reports it.
func (w FreezeWindow) activeAt(t time.Time) (end time.Time, active bool) {
	loc, err := zone(w.Timezone)
	if err != nil {
		return time.Time{}, true
	}
	if w.Weekly != nil {
		fd, fm, err1 := parseWeekly(w.Weekly.From)
		td, tm, err2 := parseWeekly(w.Weekly.To)
		if err1 != nil || err2 != nil {
			return time.Time{}, true
		}
		lt := t.In(loc)
		// The latest start at or before t is within the last 7 days.
		for k := 0; k <= 7; k++ {
			d := lt.AddDate(0, 0, -k)
			if d.Weekday() != fd {
				continue
			}
			s := wall(d.Year(), d.Month(), d.Day(), fm, loc)
			if s.After(t) {
				continue
			}
			delta := (int(td) - int(fd) + 7) % 7
			if delta == 0 && tm <= fm {
				delta = 7
			}
			e := wall(d.Year(), d.Month(), d.Day()+delta, tm, loc)
			return e, t.Before(e)
		}
		return time.Time{}, false
	}
	s, err1 := parseWhen(w.Start, loc)
	e, err2 := parseWhen(w.End, loc)
	if err1 != nil || err2 != nil {
		return time.Time{}, true
	}
	return e, !t.Before(s) && t.Before(e)
}

// wall is the instant the clock in loc reads minute (after midnight) on that
// day. A time a spring-forward gap skips maps to the same reading after the
// jump (02:30 -> 03:30), as java.time and Python's zoneinfo do; time.Date
// alone would move it an hour back. A repeated time maps to one of its
// instants (Go picks the first).
func wall(y int, mo time.Month, d, minute int, loc *time.Location) time.Time {
	t := time.Date(y, mo, d, minute/60, minute%60, 0, 0, loc)
	if got := t.Hour()*60 + t.Minute(); got != minute {
		t = t.Add(time.Duration((minute-got+24*60)%(24*60)) * time.Minute)
	}
	return t
}

func zone(tz string) (*time.Location, error) {
	if tz == "" {
		return time.UTC, nil
	}
	return time.LoadLocation(tz)
}

var weekdays = map[string]time.Weekday{"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday}

// parseWeekly parses "Fri 18:00" into a weekday and minutes after midnight.
func parseWeekly(s string) (time.Weekday, int, error) {
	day, hm, ok := strings.Cut(strings.TrimSpace(s), " ")
	d, known := weekdays[strings.ToLower(day)]
	if !ok || !known {
		return 0, 0, fmt.Errorf("%q: want a day (Mon..Sun) and a time, e.g. \"Fri 18:00\"", s)
	}
	m, err := parseHM(strings.TrimSpace(hm))
	if err != nil {
		return 0, 0, fmt.Errorf("%q: %w", s, err)
	}
	return d, m, nil
}

func parseHM(s string) (int, error) {
	h, m, ok := strings.Cut(s, ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || len(h) != 2 || len(m) != 2 || err1 != nil || err2 != nil || hh > 23 || mm > 59 || hh < 0 || mm < 0 {
		return 0, fmt.Errorf("time %q: want HH:MM (00:00-23:59)", s)
	}
	return hh*60 + mm, nil
}

// parseWhen parses a one-off bound: RFC 3339, or a wall-clock date-time or
// date in loc.
func parseWhen(s string, loc *time.Location) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	for _, l := range []string{"2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(l, s); err == nil {
			return wall(t.Year(), t.Month(), t.Day(), t.Hour()*60+t.Minute(), loc), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q: want 2006-01-02T15:04, 2006-01-02 or RFC 3339", s)
}

// ---- approvals ----

// Approval is one recorded approval of a change.
type Approval struct {
	By string `json:"by"`
	// Groups are the approver's groups when they approved (IdP or SCIM).
	Groups []string  `json:"groups,omitempty"`
	At     time.Time `json:"at"`
	Ticket string    `json:"ticket,omitempty"`
	// Scopes are the scopes of the approver's scoped approve bindings when
	// they approved (ADR-0037). nil means a global approver: every approval
	// recorded before ADR-0037 was global. A scoped approval counts only for
	// a change one of them covers (QuorumFor).
	Scopes []RoleScope `json:"scopes,omitempty"`
	// ScopedGroups replaces Groups on a scoped approval (ScopedApproval): a
	// binary from before ADR-0037 ignores Scopes, so it must see no groups
	// and count the approval for no rule, rather than count it as global.
	ScopedGroups []string `json:"scopedGroups,omitempty"`
}

// ScopedApproval is an approval by by, holding groups, under scoped approve
// bindings with scopes (nil scopes: a global approval).
func ScopedApproval(by string, groups []string, at time.Time, ticket string, scopes []RoleScope) Approval {
	a := Approval{By: by, At: at, Ticket: ticket}
	if scopes == nil {
		a.Groups = slices.Clone(groups)
		return a
	}
	a.Scopes, a.ScopedGroups = slices.Clone(scopes), slices.Clone(groups)
	if len(a.Scopes) == 0 {
		// Empty would be omitted from JSON and read back as global: record a
		// scope that covers nothing instead (ScopeCovers skips global entries).
		a.Scopes = []RoleScope{{}}
	}
	return a
}

// approverGroups is the groups a held when approving.
func (a Approval) approverGroups() []string {
	if a.Scopes != nil {
		return a.ScopedGroups
	}
	return a.Groups
}

// RuleResult is one approval rule's state for a change.
type RuleResult struct {
	Rule           string   `json:"rule"`
	Need           int      `json:"need"`
	Have           int      `json:"have"`
	Groups         []string `json:"groups"`
	DistinctGroups bool     `json:"distinctGroups,omitempty"`
	Approvers      []string `json:"approvers"`
	Ticket         string   `json:"ticket,omitempty"` // the pattern the change's ticket must match
	TicketOK       bool     `json:"ticketOK"`
	Met            bool     `json:"met"`
}

// QuorumResult is every covering rule's state; Met when all are.
type QuorumResult struct {
	Rules []RuleResult `json:"rules"`
	Met   bool         `json:"met"`
	// Ticket is the change's ticket reference ("" = none).
	Ticket string `json:"ticket,omitempty"`
	// Ignored explains approvals that did not count.
	Ignored []string `json:"ignored,omitempty"`
}

// String summarises what is missing, for refusals and gate details.
func (q *QuorumResult) String() string {
	var parts []string
	for _, r := range q.Rules {
		if r.Met {
			continue
		}
		p := fmt.Sprintf("rule %s: %d/%d approvals from %s", r.Rule, r.Have, r.Need, strings.Join(r.Groups, ", "))
		if r.DistinctGroups {
			p += " (each from a different group)"
		}
		if r.Ticket != "" && !r.TicketOK {
			p += fmt.Sprintf("; ticket matching %s required", r.Ticket)
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "approval quorum met"
	}
	return strings.Join(parts, "; ")
}

// ApprovalRules returns the rules covering target.
func (o *Org) ApprovalRules(target ChangeTarget) []ApprovalRule {
	if o.Governance == nil {
		return nil
	}
	var out []ApprovalRule
	for _, r := range o.Governance.Approvals {
		if r.Scope.covers(target) {
			out = append(out, r)
		}
	}
	return out
}

// CheckTicket validates a change's ticket against every rule covering target
// that requires one.
func (o *Org) CheckTicket(target ChangeTarget, ticket string) error {
	for _, r := range o.ApprovalRules(target) {
		if r.Ticket != "" && !ticketOK(r.Ticket, ticket) {
			if ticket == "" {
				return fmt.Errorf("approval rule %s requires a ticket reference matching %s", r.Name, r.Ticket)
			}
			return fmt.Errorf("ticket %q does not match %s (approval rule %s)", ticket, r.Ticket, r.Name)
		}
	}
	return nil
}

// ValidTicket checks a ticket reference's shape: it lands in audit records
// and PR bodies, so it is a short token, never free text.
func ValidTicket(t string) error {
	if t == "" || len(t) > 64 || strings.IndexFunc(t, func(c rune) bool {
		return (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("._:/#-", c)
	}) >= 0 {
		return fmt.Errorf("ticket %q: want 1-64 letters, digits or ._:/#- (e.g. CHG0012345, OPS-42)", t)
	}
	return nil
}

func ticketOK(pattern, ticket string) bool {
	re, err := regexp.Compile("^(?:" + pattern + ")$")
	return err == nil && ticket != "" && re.MatchString(ticket)
}

// Quorum evaluates approvals of a change requested by requester against
// every rule covering target; nil when none does. The requester's own
// approval and repeat approvals never count, and an approver counts for a
// rule only while holding one of its groups. ticket is the change's ticket
// reference ("" = none). Scoped approvals never count here: use QuorumFor
// with what the change touches.
func (o *Org) Quorum(target ChangeTarget, requester, ticket string, approvals []Approval) *QuorumResult {
	return o.QuorumFor(nil, target, requester, ticket, approvals)
}

// QuorumFor is Quorum for a change that touches res (ADR-0037): an approval
// made under scoped approve bindings counts only when one of its scopes
// covers res, and never when res is nil (unknown reach, fail closed).
func (o *Org) QuorumFor(res *Resource, target ChangeTarget, requester, ticket string, approvals []Approval) *QuorumResult {
	rules := o.ApprovalRules(target)
	if len(rules) == 0 {
		return nil
	}
	q := &QuorumResult{Met: true, Rules: []RuleResult{}, Ticket: ticket}
	seen := map[string]bool{}
	var valid []Approval
	for _, a := range approvals {
		id := CanonicalUser(a.By)
		switch {
		case requester != "" && id == CanonicalUser(requester):
			q.Ignored = append(q.Ignored, a.By+": requested the change (separation of duties)")
		case !a.ScopeCovers(res):
			q.Ignored = append(q.Ignored, a.By+": approve scope does not cover this change (ADR-0037)")
		case seen[id]:
			q.Ignored = append(q.Ignored, a.By+": already approved")
		default:
			seen[id] = true
			valid = append(valid, a)
		}
	}
	for _, r := range rules {
		rr := RuleResult{Rule: r.Name, Need: r.Quorum, Groups: r.Groups, DistinctGroups: r.DistinctGroups, Ticket: r.Ticket,
			TicketOK: r.Ticket == "" || ticketOK(r.Ticket, ticket), Approvers: []string{}}
		// eligible[i] are the rule's groups approver i holds.
		var eligible [][]string
		var who []string
		for _, a := range valid {
			var gs []string
			for _, g := range r.Groups {
				if slices.Contains(a.approverGroups(), g) {
					gs = append(gs, g)
				}
			}
			if len(gs) > 0 {
				eligible, who = append(eligible, gs), append(who, a.By)
			}
		}
		if r.DistinctGroups {
			rr.Have, rr.Approvers = distinctMatch(eligible, who)
		} else {
			rr.Have, rr.Approvers = len(who), append(rr.Approvers, who...)
		}
		rr.Met = rr.Have >= r.Quorum && rr.TicketOK
		q.Met = q.Met && rr.Met
		q.Rules = append(q.Rules, rr)
	}
	return q
}

// ScopeCovers reports whether a counts for a change touching res: a global
// approval (Scopes nil) always does, a scoped one when one of its scopes
// covers res.
func (a Approval) ScopeCovers(res *Resource) bool {
	if a.Scopes == nil {
		return true
	}
	return res != nil && slices.ContainsFunc(a.Scopes, func(s RoleScope) bool { return !s.Global() && s.Covers(*res) })
}

// distinctMatch is the largest set of approvers that can each stand for a
// different group (bipartite matching by augmenting paths; approvers and
// groups are a handful, so the cubic bound does not matter).
func distinctMatch(eligible [][]string, who []string) (int, []string) {
	owner := map[string]int{} // group -> approver index
	var try func(i int, seen map[string]bool) bool
	try = func(i int, seen map[string]bool) bool {
		for _, g := range eligible[i] {
			if seen[g] {
				continue
			}
			seen[g] = true
			if j, taken := owner[g]; !taken || try(j, seen) {
				owner[g] = i
				return true
			}
		}
		return false
	}
	for i := range eligible {
		try(i, map[string]bool{})
	}
	matched := map[int]bool{}
	for _, i := range owner {
		matched[i] = true
	}
	out := []string{}
	for i, w := range who {
		if matched[i] {
			out = append(out, w)
		}
	}
	return len(out), out
}

// governance validates halos.yaml governance.
func (v *validator) governance() {
	g := v.org.Governance
	if g == nil {
		return
	}
	rings := map[string]bool{}
	for _, r := range v.org.Rings {
		rings[r.Name] = true
	}
	scope := func(p string, s ChangeScope) {
		for i, r := range s.Rings {
			if !rings[r] {
				v.errf(fmt.Sprintf("%s.scope.rings[%d]", p, i), "ring %q not defined", r)
			}
		}
		for i, u := range s.Units {
			if v.org.Unit(u) == nil {
				v.errf(fmt.Sprintf("%s.scope.units[%d]", p, i), "unit %q not defined", u)
			}
		}
	}
	names := map[string]bool{}
	for i, w := range g.Freezes {
		p := fmt.Sprintf("governance.freezes[%d]", i)
		if !ValidName(w.Name) || names[w.Name] || w.Name == IncidentFreezeName {
			v.errf(p+".name", "%q must be a unique name matching %s (and not %q, which is halo-server's incident freeze)", w.Name, nameRe, IncidentFreezeName)
		}
		names[w.Name] = true
		if strings.TrimSpace(w.Reason) == "" {
			v.errf(p+".reason", "reason is required: it is shown to whoever the freeze stops")
		}
		scope(p, w.Scope)
		loc, err := zone(w.Timezone)
		if err != nil {
			v.errf(p+".timezone", "%q is not an IANA time zone (e.g. America/New_York): %v", w.Timezone, err)
			continue
		}
		oneOff := w.Start != "" || w.End != ""
		switch {
		case oneOff && w.Weekly != nil:
			v.errf(p, "set start and end (one-off) or weekly (recurring), not both")
		case w.Weekly != nil:
			fd, fm, err := parseWeekly(w.Weekly.From)
			if err != nil {
				v.errf(p+".weekly.from", "%v", err)
			}
			td, tm, err2 := parseWeekly(w.Weekly.To)
			if err2 != nil {
				v.errf(p+".weekly.to", "%v", err2)
			}
			if err == nil && err2 == nil && fd == td && fm == tm {
				v.errf(p+".weekly", "from and to are equal: a window cannot cover the whole week (use a one-off window or an incident freeze)")
			}
		case oneOff:
			s, err := parseWhen(w.Start, loc)
			if err != nil {
				v.errf(p+".start", "%v", err)
			}
			e, err2 := parseWhen(w.End, loc)
			if err2 != nil {
				v.errf(p+".end", "%v", err2)
			}
			if err == nil && err2 == nil && !e.After(s) {
				v.errf(p+".end", "end %s is not after start %s", w.End, w.Start)
			}
		default:
			v.errf(p, "set start and end (one-off) or weekly (recurring)")
		}
	}
	names = map[string]bool{}
	for i, r := range g.Approvals {
		p := fmt.Sprintf("governance.approvals[%d]", i)
		if !ValidName(r.Name) || names[r.Name] {
			v.errf(p+".name", "%q must be a unique name matching %s", r.Name, nameRe)
		}
		names[r.Name] = true
		scope(p, r.Scope)
		if len(r.Groups) == 0 {
			v.errf(p+".groups", "at least one approver group is required")
		}
		if r.Quorum < 1 {
			v.errf(p+".quorum", "must be >= 1")
		}
		if r.DistinctGroups && r.Quorum > len(r.Groups) {
			v.errf(p+".quorum", "%d distinct-group approvals need at least %d groups, have %d", r.Quorum, r.Quorum, len(r.Groups))
		}
		if r.Ticket != "" {
			if _, err := regexp.Compile(r.Ticket); err != nil {
				v.errf(p+".ticket", "not a regular expression: %v", err)
			}
		}
	}
}
