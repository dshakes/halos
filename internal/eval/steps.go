package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

// StepModel replays harvested steps against one model route: a gateway (the
// model is then a gateway alias) or an upstream (the model is its id). The
// request goes out on the case's own wire protocol, non-streaming, through
// the same rewrite halo-shadow uses (gateway.ForceNonStreaming,
// gateway.RewriteRequest).
type StepModel struct {
	URL    string // base URL; https, or http to loopback only
	Model  string
	APIKey string
	HTTP   *http.Client // default: 300s timeout
}

const stepRespCap = 8 << 20 // halo-shadow's body cap

// replayPath is the model-call path for protocol; the model segment is
// rewritten by gateway.RewriteRequest. Bedrock invoke bodies carry
// anthropic_version; anything else is Converse.
func replayPath(protocol string, body []byte) (string, error) {
	switch protocol {
	case gateway.ProtoAnthropic:
		return gateway.PathMessages, nil
	case gateway.ProtoResponses:
		return gateway.PathResponses, nil
	case gateway.ProtoGemini:
		return "/v1beta/models/m:generateContent", nil
	case gateway.ProtoBedrock:
		var b struct {
			V *string `json:"anthropic_version"`
		}
		if json.Unmarshal(body, &b) == nil && b.V != nil {
			return "/model/m/invoke", nil
		}
		return "/model/m/converse", nil
	}
	return "", fmt.Errorf("unknown protocol %q", protocol)
}

func (m *StepModel) validate() error {
	if m.Model == "" {
		return errors.New("steps: model is required")
	}
	if err := CheckSecureURL(m.URL); err != nil {
		return fmt.Errorf("steps: %w", err)
	}
	return nil
}

// Answer sends c's request to the model and returns the action it took and
// the raw response.
func (m *StepModel) Answer(ctx context.Context, c StepCase) (Action, []byte, error) {
	path, err := replayPath(c.Protocol, c.Request)
	if err != nil {
		return Action{}, nil, err
	}
	path, body, err := gateway.ForceNonStreaming(c.Protocol, path, c.Request)
	if err != nil {
		return Action{}, nil, err
	}
	path, body, err = gateway.RewriteRequest(c.Protocol, path, body, m.Model)
	if err != nil {
		return Action{}, nil, err
	}
	base, err := url.Parse(m.URL)
	if err != nil {
		return Action{}, nil, fmt.Errorf("model url: %w", err)
	}
	u := base.JoinPath(path).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return Action{}, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	switch c.Protocol {
	case gateway.ProtoAnthropic:
		req.Header.Set("anthropic-version", "2023-06-01")
		if m.APIKey != "" {
			req.Header.Set("x-api-key", m.APIKey)
		}
	case gateway.ProtoGemini:
		if m.APIKey != "" {
			req.Header.Set("x-goog-api-key", m.APIKey)
		}
	default:
		if m.APIKey != "" {
			req.Header.Set("Authorization", "Bearer "+m.APIKey)
		}
	}
	hc := m.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 300 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return Action{}, nil, fmt.Errorf("POST %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	raw, err := io.ReadAll(io.LimitReader(resp.Body, stepRespCap))
	if err != nil {
		return Action{}, nil, fmt.Errorf("read %s: %w", u, err)
	}
	if resp.StatusCode != http.StatusOK {
		return Action{}, raw, fmt.Errorf("POST %s: HTTP %d: %s", u, resp.StatusCode, tail(raw))
	}
	a, ok := parseResponse(c.Protocol, raw)
	if !ok {
		return Action{}, raw, fmt.Errorf("POST %s: response is not a %s model reply: %s", u, c.Protocol, tail(raw))
	}
	return a, raw, nil
}

// StepResult is one case's grade.
type StepResult struct {
	ID        string `json:"id"`
	Session   string `json:"session"`
	Depth     int    `json:"depth"`
	Pass      bool   `json:"pass"`
	SameTools bool   `json:"sameTools"`
	SameCalls bool   `json:"sameCalls"`
	Valid     bool   `json:"valid"`
	// PrematureStop: the expected action kept working and the model stopped.
	PrematureStop bool     `json:"prematureStop"`
	Actual        Action   `json:"actual"`
	Error         string   `json:"error,omitempty"`
	JudgeScore    *float64 `json:"judgeScore,omitempty"`
	JudgeError    string   `json:"judgeError,omitempty"`

	continued bool // the expected action kept working (premature-stop denominator)
}

// GradeStep is the deterministic action matcher: the answer matches when it
// is SameTools (MatchTools) or SameCalls (MatchCalls) with the expected
// action or any allowed alternative, and passes when it also calls only
// offered tools with their required arguments.
func GradeStep(c StepCase, a Action) StepResult {
	r := StepResult{ID: c.ID, Session: c.Provenance.Session, Depth: c.Provenance.Depth, Actual: a}
	for _, e := range append([]Action{c.Expected}, c.Alternatives...) {
		r.SameTools = r.SameTools || SameTools(a, e)
		r.SameCalls = r.SameCalls || SameCalls(a, e)
	}
	inv, sch := toolSpec(c.Tools).validity(a)
	r.Valid = !inv && !sch
	r.continued = !c.Expected.Stopped()
	r.PrematureStop = r.continued && a.Stopped()
	match := r.SameTools
	if c.Match == MatchCalls {
		match = r.SameCalls
	}
	r.Pass = r.Valid && match
	return r
}

// StepRunOptions configures RunSteps.
type StepRunOptions struct {
	Parallel int // concurrent model calls (default 4)
	Seed     uint64
	// Judge and Rubric, both or neither: a secondary rubric score per answered
	// case. It never changes Pass.
	Judge  *Judge
	Rubric *Rubric
}

// StepScorecard is a step suite's reading against one model. Every interval
// is a session-clustered bootstrap: steps of one session are correlated.
type StepScorecard struct {
	Suite    string `json:"suite"`
	Model    string `json:"model"`
	Cases    int    `json:"cases"`
	Sessions int    `json:"sessions"`
	Errors   int    `json:"errors"`
	// Pass counts an errored case as failed; the other rates are over
	// answered cases (PrematureStop: those whose expected action continued).
	Pass          Rate         `json:"pass"`
	SameTools     Rate         `json:"sameTools"`
	SameCalls     Rate         `json:"sameCalls"`
	Valid         Rate         `json:"valid"`
	PrematureStop Rate         `json:"prematureStop"`
	Rubric        string       `json:"rubric,omitempty"`
	Judge         *Rate        `json:"judge,omitempty"`
	JudgeErrors   int          `json:"judgeErrors,omitempty"`
	Results       []StepResult `json:"results"`
}

// RunSteps replays every case against m and scores the answers.
func RunSteps(ctx context.Context, suite string, cases []StepCase, m *StepModel, o StepRunOptions) (*StepScorecard, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	if (o.Judge == nil) != (o.Rubric == nil) {
		return nil, errors.New("steps: judge and rubric go together")
	}
	if o.Parallel <= 0 {
		o.Parallel = 4
	}
	res := make([]StepResult, len(cases))
	sem := make(chan struct{}, o.Parallel)
	var wg sync.WaitGroup
	for i, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				res[i] = StepResult{ID: c.ID, Session: c.Provenance.Session, Depth: c.Provenance.Depth, Error: ctx.Err().Error()}
				return
			}
			defer func() { <-sem }()
			res[i] = runStep(ctx, c, m, o)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return stepScorecard(suite, m.Model, res, o), nil
}

func runStep(ctx context.Context, c StepCase, m *StepModel, o StepRunOptions) StepResult {
	a, raw, err := m.Answer(ctx, c)
	if err != nil {
		return StepResult{ID: c.ID, Session: c.Provenance.Session, Depth: c.Provenance.Depth, Error: err.Error()}
	}
	r := GradeStep(c, a)
	if o.Judge != nil {
		exp, _ := json.Marshal(map[string]any{"expected": c.Expected, "alternatives": c.Alternatives})
		v, err := o.Judge.Grade(ctx, o.Rubric, []Part{
			{Title: "Request sent by the coding agent (JSON, redacted)", Body: clip(c.Request), Untrusted: true},
			{Title: "Action production took at this step (JSON)", Body: string(exp), Untrusted: true},
			{Title: "Model response to grade (JSON)", Body: clip(raw), Untrusted: true},
		})
		if err != nil {
			r.JudgeError = err.Error()
		} else {
			r.JudgeScore = &v.Score
		}
	}
	return r
}

func stepScorecard(suite, model string, res []StepResult, o StepRunOptions) *StepScorecard {
	sc := &StepScorecard{Suite: suite, Model: model, Cases: len(res), Results: res}
	var pass, tools, calls, valid, stop, judge []float64
	var all, ans, stopCl, judgeCl []string
	sessions := map[string]bool{}
	for _, r := range res {
		sessions[r.Session] = true
		all = append(all, r.Session)
		pass = append(pass, b2f(r.Pass))
		if r.Error != "" {
			sc.Errors++
			continue
		}
		ans = append(ans, r.Session)
		tools, calls, valid = append(tools, b2f(r.SameTools)), append(calls, b2f(r.SameCalls)), append(valid, b2f(r.Valid))
		if r.continued {
			stop, stopCl = append(stop, b2f(r.PrematureStop)), append(stopCl, r.Session)
		}
		switch {
		case r.JudgeScore != nil:
			judge, judgeCl = append(judge, *r.JudgeScore), append(judgeCl, r.Session)
		case r.JudgeError != "":
			sc.JudgeErrors++
		}
	}
	sc.Sessions = len(sessions)
	sc.Pass = rate(pass, all, o.Seed)
	sc.SameTools, sc.SameCalls, sc.Valid = rate(tools, ans, o.Seed), rate(calls, ans, o.Seed), rate(valid, ans, o.Seed)
	sc.PrematureStop = rate(stop, stopCl, o.Seed)
	if o.Rubric != nil {
		sc.Rubric = o.Rubric.Ref()
		j := rate(judge, judgeCl, o.Seed)
		sc.Judge = &j
	}
	return sc
}

// Table renders the scorecard for a terminal.
func (sc *StepScorecard) Table() string {
	var b strings.Builder
	pct := func(x Rate) string {
		return fmt.Sprintf("%.0f%% (%.0f..%.0f) n=%d", 100*x.Mean, 100*x.CILo, 100*x.CIHi, x.N)
	}
	fmt.Fprintf(&b, "suite %s  model %s  cases %d  sessions %d  errors %d\n\n", sc.Suite, sc.Model, sc.Cases, sc.Sessions, sc.Errors)
	fmt.Fprintf(&b, "%-16s  %s\n", "PASS", pct(sc.Pass))
	fmt.Fprintf(&b, "%-16s  %s\n", "SAME TOOLS", pct(sc.SameTools))
	fmt.Fprintf(&b, "%-16s  %s\n", "SAME CALLS", pct(sc.SameCalls))
	fmt.Fprintf(&b, "%-16s  %s\n", "VALID CALLS", pct(sc.Valid))
	fmt.Fprintf(&b, "%-16s  %s\n", "PREMATURE STOP", pct(sc.PrematureStop))
	if sc.Judge != nil {
		fmt.Fprintf(&b, "%-16s  %.2f (%.2f..%.2f) n=%d  %s  judge errors %d\n", "JUDGE", sc.Judge.Mean, sc.Judge.CILo, sc.Judge.CIHi, sc.Judge.N, sc.Rubric, sc.JudgeErrors)
	}
	b.WriteString("\n95% CIs resample sessions (cluster bootstrap).\n")
	var failed []string
	for _, r := range sc.Results {
		switch {
		case r.Error != "":
			failed = append(failed, fmt.Sprintf("  %s (step %d): error: %s", r.ID, r.Depth, r.Error))
		case !r.Pass:
			failed = append(failed, fmt.Sprintf("  %s (step %d): same tools %t, valid %t, called %v", r.ID, r.Depth, r.SameTools, r.Valid, r.Actual.names()))
		}
	}
	if len(failed) > 0 {
		b.WriteString("\nFAILED\n" + strings.Join(failed, "\n") + "\n")
	}
	return b.String()
}
