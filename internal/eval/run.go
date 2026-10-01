package eval

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Trial is the scored outcome of one (task x variant x repeat) run.
type Trial struct {
	Task       string  `json:"task"`
	Variant    string  `json:"variant"`
	Repeat     int     `json:"repeat"`
	Pass       bool    `json:"pass"`
	CostUSD    float64 `json:"costUSD"`
	Turns      int     `json:"turns"`
	WallMs     int64   `json:"wallMs"`
	Tokens     int64   `json:"tokens"`
	ToolErrors int     `json:"toolErrors"`
	ToolCalls  int     `json:"toolCalls"`
	// Seed is derived from the suite seed, task and repeat (identical across
	// variants, so arms stay paired). Recorded; no pinned CLI accepts one.
	Seed uint64 `json:"seed,omitempty"`
	// Grades are the task's graders' results (absent for check-only tasks).
	Grades []Grade `json:"grades,omitempty"`
	// GraderError is set when a grader could not produce a verdict (e.g. the
	// judge's reply failed schema validation). The trial does not pass.
	GraderError string `json:"graderError,omitempty"`
	// Error records setup/agent/parse problems. The trial is still scored by
	// the check command where possible; infra failures count as not passed.
	Error string `json:"error,omitempty"`
}

func sh(cmd string) Command { return Command{Args: []string{"sh", "-c", cmd}} }

func tail(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = "..." + s[len(s)-300:]
	}
	return s
}

// RunTrial provisions an environment, runs setup, the agent, then the task's
// success check, and returns the scored Trial. It never returns an error:
// failures are recorded in Trial.Error so one bad trial cannot sink a suite.
func RunTrial(ctx context.Context, r Runner, d Driver, t *Task, v Variant, repeat int) Trial {
	return runTrial(ctx, r, d, t, v, repeat, nil)
}

// trialSeed is stable per (suite seed, task, repeat): FNV-1a.
func trialSeed(seed uint64, task string, repeat int) uint64 {
	h := uint64(14695981039346656037) ^ seed
	for _, b := range []byte(fmt.Sprintf("%s\x00%d", task, repeat)) {
		h = (h ^ uint64(b)) * 1099511628211
	}
	return h
}

func runTrial(ctx context.Context, r Runner, d Driver, t *Task, v Variant, repeat int, j *Judge) (tr Trial) {
	tr = Trial{Task: t.ID, Variant: v.Name, Repeat: repeat}
	timeout := t.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	env, err := r.Start(ctx, Job{Task: t, Variant: v, Settings: v.Settings, SettingsDest: d.SettingsPath()})
	if err != nil {
		tr.Error = fmt.Sprintf("start: %v", err)
		return tr
	}
	defer func() {
		if err := env.Close(); err != nil && tr.Error == "" {
			tr.Error = fmt.Sprintf("cleanup: %v", err) // a leaked container is worth surfacing
		}
	}()

	for _, s := range t.Setup {
		sctx, cancel := context.WithTimeout(ctx, timeout)
		res, err := env.Exec(sctx, sh(s))
		cancel()
		if err != nil || res.ExitCode != 0 {
			tr.Error = fmt.Sprintf("setup %q failed (exit %d, err %v): %s", s, res.ExitCode, err, tail(res.Stderr))
			return tr
		}
	}

	var before map[string]string
	if t.needsSnapshot() {
		sctx, cancel := context.WithTimeout(ctx, timeout)
		before, err = snapshot(sctx, env)
		cancel()
		if err != nil {
			tr.GraderError = err.Error()
			return tr
		}
	}

	actx, cancel := context.WithTimeout(ctx, timeout)
	start := time.Now()
	// Secrets (--pass-env) go to the agent step only, never setup/check.
	agentExec := env.Exec
	if ae, ok := env.(interface {
		ExecAgent(context.Context, Command) (ExecResult, error)
	}); ok {
		agentExec = ae.ExecAgent
	}
	res, err := agentExec(actx, d.Command(t, v))
	tr.WallMs = time.Since(start).Milliseconds()
	cancel()
	switch {
	case err != nil:
		tr.Error = fmt.Sprintf("agent: %v", err)
	case res.ExitCode != 0:
		tr.Error = fmt.Sprintf("agent exit %d: %s", res.ExitCode, tail(res.Stderr))
	}
	u, perr := d.Parse(res.Stdout)
	tr.CostUSD, tr.Turns, tr.Tokens, tr.ToolErrors, tr.ToolCalls = u.CostUSD, u.Turns, u.Tokens, u.ToolErrors, u.ToolCalls
	if tr.Error == "" {
		switch {
		case perr != nil:
			tr.Error = fmt.Sprintf("parse: %v", perr)
		case u.Failed:
			tr.Error = "harness reported failure: " + u.Error
		}
	}

	// Score even after agent failure/timeout: partial work may still pass.
	cctx, ccancel := context.WithTimeout(ctx, timeout)
	defer ccancel()
	tr.Pass = true
	if strings.TrimSpace(t.Check) != "" {
		cres, cerr := env.Exec(cctx, sh(t.Check))
		tr.Pass = cerr == nil && cres.ExitCode == 0
	}
	if len(t.Graders) > 0 {
		tr.Grades = t.grade(cctx, env, j, before)
		for _, g := range tr.Grades {
			tr.Pass = tr.Pass && g.Pass
			if g.Error != "" && tr.GraderError == "" {
				tr.GraderError = g.Grader + ": " + g.Error
			}
		}
	}
	return tr
}

// RunSuite runs every task x variant x repeat with up to parallel concurrent
// trials and returns trials in deterministic order. It returns ctx.Err() if
// cancelled before finishing.
func RunSuite(ctx context.Context, s *Suite, tasks []*Task, r Runner, drivers map[string]Driver, parallel int) ([]Trial, error) {
	return RunSuiteWith(ctx, s, tasks, r, drivers, RunOptions{Parallel: parallel})
}

// RunOptions tunes RunSuiteWith.
type RunOptions struct {
	Parallel int
	// Judge grades tasks' judge graders; required if any task has one.
	Judge *Judge
}

// RunSuiteWith is RunSuite with a judge for rubric graders.
func RunSuiteWith(ctx context.Context, s *Suite, tasks []*Task, r Runner, drivers map[string]Driver, o RunOptions) ([]Trial, error) {
	parallel := o.Parallel
	for _, t := range tasks {
		if t.needsJudge() && o.Judge == nil {
			return nil, fmt.Errorf("suite %s: task %s has a judge grader but the suite configures no judge", s.Name, t.ID)
		}
	}
	for _, v := range s.Variants {
		if drivers[v.Harness] == nil {
			return nil, fmt.Errorf("suite %s: no driver for harness %q", s.Name, v.Harness)
		}
	}
	if parallel < 1 {
		parallel = 1
	}
	type job struct {
		t      *Task
		v      Variant
		repeat int
	}
	var jobs []job
	for _, t := range tasks {
		for _, v := range s.Variants {
			for i := 0; i < s.Repeats; i++ {
				jobs = append(jobs, job{t, v, i})
			}
		}
	}
	out := make([]Trial, len(jobs))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, j := range jobs {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			out[i] = runTrial(ctx, r, drivers[j.v.Harness], j.t, j.v, j.repeat, o.Judge)
			out[i].Seed = trialSeed(s.Seed, j.t.ID, j.repeat)
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("suite %s: %w", s.Name, err)
	}
	return out, nil
}
