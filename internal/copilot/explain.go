package copilot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/release"
)

// Fact is one keyed value Halos computed (a plan field, a diff, an
// experiment setting, a verdict). Explanations may cite only these.
type Fact struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Point is one claim of an explanation and the fact keys it rests on.
type Point struct {
	Text  string   `json:"text"`
	Cites []string `json:"cites"`
}

// Explanation is the outcome of `halo copilot explain`. Used lists the
// facts the points cite, so every claim can be checked against Halos output.
type Explanation struct {
	Subject string  `json:"subject"`
	Offline bool    `json:"offline"`
	Summary string  `json:"summary"`
	Points  []Point `json:"points"`
	Used    []Fact  `json:"factsUsed"`
	Stopped string  `json:"stopped,omitempty"`
	Spend   Spend   `json:"spend"`
}

const explainSchema = `{"type":"object","additionalProperties":false,"required":["summary","points"],
 "properties":{"summary":{"type":"string","minLength":1,"description":"two or three plain-language sentences"},
  "points":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["text","cites"],
   "properties":{"text":{"type":"string","minLength":1},"cites":{"type":"array","minItems":1,"items":{"type":"string","description":"a fact key exactly as given"}}}}}}}`

const explainSystem = `You are Halos Copilot. Explain a Halos change to an engineer in plain language, grounded ONLY in the facts given.
Every point must cite the keys of the facts it uses, exactly as given. Do not state anything the facts do not show; say what is unknown instead.
Reply with ONLY one JSON object matching this JSON Schema (no prose, no code fences):
`

type explainReply struct {
	Summary string  `json:"summary"`
	Points  []Point `json:"points"`
}

func (r *explainReply) check(keys map[string]bool) error {
	if strings.TrimSpace(r.Summary) == "" || len(r.Points) == 0 || len(r.Points) > 20 {
		return errors.New("want a summary and 1 to 20 points")
	}
	for i, p := range r.Points {
		if strings.TrimSpace(p.Text) == "" || len(p.Cites) == 0 {
			return fmt.Errorf("point %d needs text and at least one cited fact key", i+1)
		}
		for _, k := range p.Cites {
			if !keys[k] {
				return fmt.Errorf("point %d cites %q, which is not a fact key; cite only the keys given", i+1, k)
			}
		}
	}
	return nil
}

// Explain explains facts in plain language. A point citing a key that is
// not among facts is rejected and fed back. Offline, the explanation is a
// deterministic template over the same facts.
func (c *Client) Explain(ctx context.Context, subject string, facts []Fact) (*Explanation, error) {
	if len(facts) == 0 {
		return nil, errors.New("copilot: nothing to explain")
	}
	byKey := make(map[string]Fact, len(facts))
	keys := make(map[string]bool, len(facts))
	for _, f := range facts {
		byKey[f.Key], keys[f.Key] = f, true
	}
	ex := &Explanation{Subject: subject, Offline: c.Offline(), Points: []Point{}, Used: []Fact{}}
	if c.Offline() {
		ex.Summary, ex.Points = offlineExplain(subject, facts)
	} else {
		var b strings.Builder
		for _, f := range facts {
			fmt.Fprintf(&b, "[%s]\n%s\n\n", f.Key, f.Value)
		}
		var feedback string
		for i := 1; i <= c.Budget.withDefaults().MaxIterations; i++ {
			parts := []eval.Part{{Title: "Subject", Body: subject}, {Title: "Facts (key in brackets, then value)", Body: b.String(), Untrusted: true}}
			if feedback != "" {
				parts = append(parts, eval.Part{Title: "Halos rejected your previous reply; fix this", Body: feedback, Untrusted: true})
			}
			prompt, notice, err := fence(parts...)
			if err != nil {
				return nil, err
			}
			var r explainReply
			err = c.ask(ctx, explainSystem+explainSchema+"\n\n"+notice, prompt, &r, func() error { return r.check(keys) })
			ex.Spend = c.Spend()
			if errors.Is(err, ErrSchema) {
				feedback, ex.Stopped = err.Error(), "the last reply failed schema validation: "+err.Error()
				continue
			}
			if errors.Is(err, ErrBudget) {
				ex.Stopped = err.Error()
				return ex, nil
			}
			if err != nil {
				return nil, err
			}
			ex.Summary, ex.Points, ex.Stopped = r.Summary, r.Points, ""
			break
		}
		if ex.Summary == "" {
			return ex, nil
		}
	}
	seen := map[string]bool{}
	for _, p := range ex.Points {
		for _, k := range p.Cites {
			if !seen[k] {
				seen[k] = true
				ex.Used = append(ex.Used, byKey[k])
			}
		}
	}
	sort.Slice(ex.Used, func(i, j int) bool { return ex.Used[i].Key < ex.Used[j].Key })
	return ex, nil
}

// offlineExplain renders each fact as a point citing itself.
func offlineExplain(subject string, facts []Fact) (string, []Point) {
	var pts []Point
	for _, f := range facts[:min(len(facts), 30)] {
		v := f.Value
		if i := strings.IndexByte(v, '\n'); i >= 0 {
			v = v[:i] + fmt.Sprintf(" (+%d more lines)", strings.Count(f.Value, "\n"))
		}
		if len(v) > 200 {
			v = v[:200] + "..."
		}
		pts = append(pts, Point{Text: f.Key + ": " + v, Cites: []string{f.Key}})
	}
	sum := fmt.Sprintf("%s: %d facts from Halos outputs (offline template; no model was called).", subject, len(facts))
	if len(facts) > 30 {
		sum += " The first 30 are listed."
	}
	return sum, pts
}

// maxFactBytes caps one fact's value (a long diff is cut, not dropped).
const maxFactBytes = 8000

func fact(k, v string) Fact {
	if len(v) > maxFactBytes {
		v = v[:maxFactBytes] + fmt.Sprintf("\n... (%d more bytes)", len(v)-maxFactBytes)
	}
	return Fact{Key: k, Value: v}
}

// Flatten turns v (any JSON-encodable value) into facts keyed by prefix and
// the JSON path (prefix.a.b[0]); empty values are skipped.
func Flatten(prefix string, v any) ([]Fact, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	var out []Fact
	var walk func(k string, v any)
	walk = func(k string, v any) {
		switch t := v.(type) {
		case map[string]any:
			ks := make([]string, 0, len(t))
			for kk := range t {
				ks = append(ks, kk)
			}
			sort.Strings(ks)
			for _, kk := range ks {
				walk(k+"."+kk, t[kk])
			}
		case []any:
			for i, e := range t {
				walk(k+"["+strconv.Itoa(i)+"]", e)
			}
		case nil:
		case string:
			if t != "" {
				out = append(out, fact(k, t))
			}
		default:
			out = append(out, fact(k, fmt.Sprint(t)))
		}
	}
	walk(prefix, doc)
	return out, nil
}

// ReleaseFacts are ring's release as cand builds it, diffed against base's
// build (base nil: an empty release).
func ReleaseFacts(base, cand *policy.Org, ring string) ([]Fact, error) {
	cur, _, err := release.BuildRing(cand, ring, release.Options{Version: "0.0.0-dev", Org: cand.Name})
	if err != nil {
		return nil, fmt.Errorf("copilot: build ring %s: %w", ring, err)
	}
	prev := &release.Release{}
	if base != nil {
		if b, _, err := release.BuildRing(base, ring, release.Options{Version: "0.0.0-dev", Org: base.Name}); err == nil {
			prev = b
		}
	}
	d := release.Diff(prev, cur)
	facts := []Fact{
		fact("release.ring", ring),
		fact("release.digest", cur.Digest),
		fact("release.previous", short(prev.Digest)),
		fact("release.changed", strconv.FormatBool(d != "")),
	}
	if d != "" {
		facts = append(facts, fact("release.diff", d))
	}
	for i, w := range cur.Manifest.Warnings {
		facts = append(facts, fact(fmt.Sprintf("release.warnings[%d]", i), w))
	}
	return facts, nil
}

// DiffFacts are the policy change from baseDir to dir: the changed YAML
// files, each ring's plan and the impact preview.
func DiffFacts(baseDir, dir string) ([]Fact, error) {
	base, err := policy.Load(baseDir)
	if err != nil {
		return nil, fmt.Errorf("copilot: policy at the base: %w", err)
	}
	cand, err := policy.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("copilot: %w", err)
	}
	var facts []Fact
	files, err := yamlFiles(baseDir, dir)
	if err != nil {
		return nil, err
	}
	for _, rel := range files {
		a, _ := os.ReadFile(filepath.Join(baseDir, rel)) //nolint:gosec // operator-owned policy repo; missing = empty
		b, _ := os.ReadFile(filepath.Join(dir, rel))     //nolint:gosec // as above
		if d := promote.UnifiedDiff(filepath.ToSlash(rel), string(a), string(b)); d != "" {
			facts = append(facts, fact("files."+filepath.ToSlash(rel), d))
		}
	}
	plans, rep, errs := Compare(base, cand)
	for _, p := range plans {
		facts = append(facts, fact("plan."+p.Ring+".changed", strconv.FormatBool(p.Changed)))
		if p.Changed {
			facts = append(facts, fact("plan."+p.Ring+".from", short(p.From)), fact("plan."+p.Ring+".to", short(p.To)), fact("plan."+p.Ring+".diff", p.Diff))
		}
	}
	for i, e := range errs {
		facts = append(facts, fact(fmt.Sprintf("plan.errors[%d]", i), e))
	}
	kinds := make([]string, 0, len(rep.ByKind))
	for k := range rep.ByKind {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		n := rep.ByKind[k]
		facts = append(facts, fact("impact."+k, fmt.Sprintf("%d of %d change (ring %d, variant %d, settings %d; policy estimate)", n.Any, n.Total, n.Ring, n.Variant, n.Settings)))
	}
	return facts, nil
}

// yamlFiles is the union of YAML files (relative paths) under both dirs.
func yamlFiles(dirs ...string) ([]string, error) {
	set := map[string]bool{}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != dir && strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			if ext := filepath.Ext(p); d.Type().IsRegular() && (ext == ".yaml" || ext == ".yml") {
				rel, err := filepath.Rel(dir, p)
				if err != nil {
					return err
				}
				set[rel] = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("copilot: walk %s: %w", dir, err)
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}
