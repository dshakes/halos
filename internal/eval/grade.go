package eval

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Grader types.
const (
	GraderCommand = "command" // run exits 0
	GraderFile    = "file"    // assertions on one file's existence/content
	GraderDiff    = "diff"    // assertions on which files the agent changed
	GraderJudge   = "judge"   // LLM-as-judge rubric over the prompt and the change
)

// GraderSpec is one entry of a task's `graders:`. Fields apply per type.
type GraderSpec struct {
	Type string `yaml:"type" json:"type"`
	// command
	Run string `yaml:"run,omitempty" json:"run,omitempty"`
	// file: Path relative to the work dir; Exists defaults to true.
	Path        string   `yaml:"path,omitempty" json:"path,omitempty"`
	Exists      *bool    `yaml:"exists,omitempty" json:"exists,omitempty"`
	Contains    []string `yaml:"contains,omitempty" json:"contains,omitempty"`
	NotContains []string `yaml:"not_contains,omitempty" json:"notContains,omitempty"`
	Matches     string   `yaml:"matches,omitempty" json:"matches,omitempty"` // RE2
	// diff: globs (path.Match, slash-separated) over changed paths.
	MaxFilesChanged int      `yaml:"max_files_changed,omitempty" json:"maxFilesChanged,omitempty"`
	MustChange      []string `yaml:"must_change,omitempty" json:"mustChange,omitempty"`
	MustNotChange   []string `yaml:"must_not_change,omitempty" json:"mustNotChange,omitempty"`
	// judge: rubric file relative to the declaring task or suite dir (e.g.
	// ../rubrics/x.yaml), never outside the evals root.
	Rubric string `yaml:"rubric,omitempty" json:"rubric,omitempty"`

	re     *regexp.Regexp
	rubric *Rubric
}

// Grade is one grader's outcome on one trial.
type Grade struct {
	Grader string   `json:"grader"` // type, plus path/rubric when useful
	Pass   bool     `json:"pass"`
	Score  *float64 `json:"score,omitempty"` // judge only
	Rubric string   `json:"rubric,omitempty"`
	Detail string   `json:"detail,omitempty"`
	// Error is a grader failure (e.g. judge schema violation): never a pass.
	Error string `json:"error,omitempty"`
}

func (t *Task) loadGraders() error {
	return loadGraders(t.Graders, filepath.Dir(filepath.Dir(t.Dir)), filepath.Join(filepath.Base(filepath.Dir(t.Dir)), filepath.Base(t.Dir)))
}

// loadGraders validates gs and loads their rubrics. Rubric paths are
// relative to root/base (the declaring task or suite dir) and must stay
// inside root, the evals root.
func loadGraders(gs []GraderSpec, root, base string) error {
	for i := range gs {
		g := &gs[i]
		switch g.Type {
		case GraderCommand:
			if strings.TrimSpace(g.Run) == "" {
				return fmt.Errorf("grader %d: command needs run", i)
			}
		case GraderFile:
			if g.Path == "" || filepath.IsAbs(g.Path) || strings.HasPrefix(path.Clean(filepath.ToSlash(g.Path)), "../") {
				return fmt.Errorf("grader %d: file needs a relative path inside the repo", i)
			}
			if g.Matches != "" {
				re, err := regexp.Compile(g.Matches)
				if err != nil {
					return fmt.Errorf("grader %d: matches: %w", i, err)
				}
				g.re = re
			}
		case GraderDiff:
			for _, p := range append(append([]string(nil), g.MustChange...), g.MustNotChange...) {
				if _, err := path.Match(p, ""); err != nil {
					return fmt.Errorf("grader %d: glob %q: %w", i, p, err)
				}
			}
		case GraderJudge:
			if g.Rubric == "" {
				return fmt.Errorf("grader %d: judge needs rubric", i)
			}
			p, err := resolveWithin(root, filepath.Join(base, g.Rubric))
			if err != nil {
				return fmt.Errorf("grader %d: rubric must be a file under the evals root: %w", i, err)
			}
			if g.rubric, err = LoadRubric(p); err != nil {
				return fmt.Errorf("grader %d: %w", i, err)
			}
		default:
			return fmt.Errorf("grader %d: unknown type %q (want command, file, diff or judge)", i, g.Type)
		}
	}
	return nil
}

func (t *Task) needsSnapshot() bool {
	for _, g := range t.Graders {
		if g.Type == GraderDiff || g.Type == GraderJudge {
			return true
		}
	}
	return false
}

func (t *Task) needsJudge() bool {
	for _, g := range t.Graders {
		if g.Type == GraderJudge {
			return true
		}
	}
	return false
}

// snapshotCmd lists "cksum size path" for every regular file outside .git.
// cksum is POSIX, so it exists in any eval image.
const snapshotCmd = `find . -path ./.git -prune -o -type f -exec cksum {} +`

func snapshot(ctx context.Context, env Env) (map[string]string, error) {
	res, err := env.Exec(ctx, sh(snapshotCmd))
	if err != nil || res.ExitCode != 0 {
		return nil, fmt.Errorf("snapshot (exit %d, err %v): %s", res.ExitCode, err, tail(res.Stderr))
	}
	out := map[string]string{}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		f := strings.SplitN(l, " ", 3)
		if len(f) == 3 {
			out[strings.TrimPrefix(f[2], "./")] = f[0] + " " + f[1]
		}
	}
	return out, nil
}

// changed lists added, modified and deleted paths, sorted.
func changed(before, after map[string]string) []string {
	var out []string
	for p, s := range after {
		if before[p] != s {
			out = append(out, p)
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func anyMatch(globs []string, p string) bool {
	for _, g := range globs {
		if ok, _ := path.Match(g, p); ok {
			return true
		}
		if ok, _ := path.Match(g, path.Base(p)); ok && !strings.Contains(g, "/") {
			return true
		}
	}
	return false
}

// judgeInputCap bounds what one judge call sees of the change.
const judgeInputCap = 64 << 10

// grade runs the task's graders after the agent step. before is the
// pre-agent snapshot (nil unless needed). It returns the per-grader results;
// the trial passes only if every grade passes with no error.
func (t *Task) grade(ctx context.Context, env Env, j *Judge, before map[string]string) []Grade {
	var after map[string]string
	var diffErr error
	if before != nil {
		after, diffErr = snapshot(ctx, env)
	}
	var out []Grade
	for _, g := range t.Graders {
		gr := Grade{Grader: g.Type}
		switch g.Type {
		case GraderCommand:
			res, err := env.Exec(ctx, sh(g.Run))
			gr.Pass = err == nil && res.ExitCode == 0
			if !gr.Pass {
				gr.Detail = fmt.Sprintf("exit %d: %s", res.ExitCode, tail(res.Stderr))
			}
		case GraderFile:
			gr.Grader += ":" + g.Path
			gr.Pass, gr.Detail, gr.Error = fileGrade(ctx, env, g)
		case GraderDiff:
			if diffErr != nil {
				gr.Error = diffErr.Error()
				break
			}
			gr.Pass, gr.Detail = diffGrade(g, changed(before, after))
		case GraderJudge:
			gr.Rubric = g.rubric.Ref()
			gr.Grader += ":" + gr.Rubric
			switch {
			case j == nil:
				gr.Error = "no judge configured (suite judge: block)"
			case diffErr != nil:
				gr.Error = diffErr.Error()
			default:
				v, err := j.Grade(ctx, g.rubric, t.judgeInput(ctx, env, changed(before, after)))
				if err != nil {
					gr.Error = err.Error()
					break
				}
				gr.Score = &v.Score
				gr.Pass = v.Score >= g.rubric.PassThreshold
				gr.Detail = v.Rationale
			}
		}
		if gr.Error != "" {
			gr.Pass = false
		}
		out = append(out, gr)
	}
	return out
}

func fileGrade(ctx context.Context, env Env, g GraderSpec) (pass bool, detail, gerr string) {
	res, err := env.Exec(ctx, Command{Args: []string{"cat", "--", g.Path}})
	if err != nil {
		return false, "", fmt.Sprintf("read %s: %v", g.Path, err)
	}
	exists := res.ExitCode == 0
	want := g.Exists == nil || *g.Exists
	if exists != want {
		return false, fmt.Sprintf("%s exists=%v, want %v", g.Path, exists, want), ""
	}
	if !exists {
		return true, "", ""
	}
	body := string(res.Stdout)
	for _, s := range g.Contains {
		if !strings.Contains(body, s) {
			return false, fmt.Sprintf("%s does not contain %q", g.Path, s), ""
		}
	}
	for _, s := range g.NotContains {
		if strings.Contains(body, s) {
			return false, fmt.Sprintf("%s contains %q", g.Path, s), ""
		}
	}
	if g.re != nil && !g.re.MatchString(body) {
		return false, fmt.Sprintf("%s does not match /%s/", g.Path, g.Matches), ""
	}
	return true, "", ""
}

func diffGrade(g GraderSpec, ch []string) (bool, string) {
	if g.MaxFilesChanged > 0 && len(ch) > g.MaxFilesChanged {
		return false, fmt.Sprintf("%d files changed, max %d: %s", len(ch), g.MaxFilesChanged, strings.Join(ch, ", "))
	}
	for _, p := range ch {
		if anyMatch(g.MustNotChange, p) {
			return false, fmt.Sprintf("changed protected path %s", p)
		}
	}
	for _, glob := range g.MustChange {
		hit := false
		for _, p := range ch {
			hit = hit || anyMatch([]string{glob}, p)
		}
		if !hit {
			return false, fmt.Sprintf("nothing matching %s changed", glob)
		}
	}
	return true, fmt.Sprintf("%d files changed", len(ch))
}

// judgeInput is the task prompt plus the changed paths and their new
// contents, capped at judgeInputCap.
func (t *Task) judgeInput(ctx context.Context, env Env, ch []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## Task given to the coding agent\n\n%s\n\n## Files changed (%d)\n\n", strings.TrimSpace(t.Prompt), len(ch))
	for _, p := range ch {
		if b.Len() >= judgeInputCap {
			fmt.Fprintf(&b, "\n[... truncated: remaining files omitted ...]\n")
			break
		}
		res, err := env.Exec(ctx, Command{Args: []string{"cat", "--", p}})
		switch {
		case err != nil || res.ExitCode != 0:
			fmt.Fprintf(&b, "### %s (deleted)\n\n", p)
		default:
			body := string(res.Stdout)
			if room := judgeInputCap - b.Len(); len(body) > room {
				body = body[:max(room, 0)] + "\n[... truncated ...]"
			}
			fmt.Fprintf(&b, "### %s\n\n```\n%s\n```\n\n", p, body)
		}
	}
	return b.String()
}
