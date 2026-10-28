package copilot

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/yamledit"
)

// draftSchema is the Go-side schema of a draft reply (DraftReply), sent to
// the model verbatim and enforced by decodeStrict plus DraftReply.check.
const draftSchema = `{"type":"object","additionalProperties":false,"required":["files","summary","risks"],
 "properties":{
  "files":{"type":"array","minItems":1,"maxItems":20,"items":{"type":"object","additionalProperties":false,"required":["path","content"],
   "properties":{"path":{"type":"string","description":"policy-dir-relative .yaml/.yml path, no .. or hidden segments"},
                 "content":{"type":"string","description":"the WHOLE new file content"}}}},
  "summary":{"type":"string","minLength":1},
  "risks":{"type":"array","items":{"type":"string"}}}}`

// DraftReply is a model's draft.
type DraftReply struct {
	Files   []File   `json:"files"`
	Summary string   `json:"summary"`
	Risks   []string `json:"risks"`
}

func (d *DraftReply) check() error {
	if strings.TrimSpace(d.Summary) == "" {
		return errors.New("summary is required")
	}
	if d.Risks == nil {
		return errors.New("risks is required (an empty array when none)")
	}
	return checkFiles(d.Files)
}

// DraftResult is the outcome of `halo copilot draft`. OK means the last
// draft passed every check; Stopped says why a run ended without one.
type DraftResult struct {
	Intent     string   `json:"intent"`
	OK         bool     `json:"ok"`
	Offline    bool     `json:"offline"`
	Iterations int      `json:"iterations"`
	Summary    string   `json:"summary,omitempty"`
	Files      []File   `json:"files"`
	Check      *Check   `json:"check,omitempty"`
	ModelRisks []string `json:"modelRisks"`
	Stopped    string   `json:"stopped,omitempty"`
	Spend      Spend    `json:"spend"`
}

const draftSystem = `You are Halos Copilot. You edit a Halos policy repository (YAML, apiVersion halos.dev/v1) to carry out the operator's intent, and nothing else.
Rules:
- Return the WHOLE new content of every file you change; keep unrelated content, comments and formatting as they are.
- Change as few files and lines as possible. Only .yaml/.yml files inside the policy directory.
- Never write bypassPermissions, danger-full-access or any permission-bypass setting, not even in a comment.
- Halos checks your draft (validation, release plan, impact preview). If it reports errors, fix exactly those.
- New experiments start with status: draft. Never set an experiment to running or concluded, and never change ring release pins unless the intent asks for it.
Reply with ONLY one JSON object matching this JSON Schema (no prose, no code fences):
`

// Draft turns intent into a verified policy change: the model drafts whole
// files, Verify checks them, and errors go back to the model until the
// draft passes or a ceiling stops the run. Offline, a deterministic template
// drafts instead (see offlineDraft). It never writes to dir.
func (c *Client) Draft(ctx context.Context, dir, intent string) (*DraftResult, error) {
	intent = strings.TrimSpace(intent)
	if intent == "" {
		return nil, errors.New("copilot: intent is required")
	}
	res := &DraftResult{Intent: intent, Offline: c.Offline(), Files: []File{}, ModelRisks: []string{}}
	if c.Offline() {
		files, summary, err := offlineDraft(dir, intent)
		if err != nil {
			return nil, err
		}
		chk, err := Verify(dir, files)
		if err != nil {
			return nil, err
		}
		res.Iterations, res.Files, res.Summary, res.Check, res.OK = 1, files, summary, chk, chk.OK
		return res, nil
	}
	policyText, err := policyFiles(dir)
	if err != nil {
		return nil, err
	}
	var feedback string
	for i := 1; i <= c.Budget.withDefaults().MaxIterations; i++ {
		parts := []eval.Part{{Title: "Intent (from the operator)", Body: intent}, {Title: "Current policy files", Body: policyText, Untrusted: true}}
		if feedback != "" {
			parts = append(parts, eval.Part{Title: "Halos rejected your previous draft; fix these and return the complete draft again", Body: feedback, Untrusted: true})
		}
		prompt, notice, err := fence(parts...)
		if err != nil {
			return nil, err
		}
		var reply DraftReply
		err = c.ask(ctx, draftSystem+draftSchema+"\n\n"+notice, prompt, &reply, reply.check)
		res.Iterations, res.Spend = i, c.Spend()
		switch {
		case errors.Is(err, ErrBudget):
			res.Stopped = err.Error()
			return res, nil
		case errors.Is(err, ErrSchema):
			feedback = err.Error()
			res.Stopped = "the last reply failed schema validation: " + err.Error()
			continue
		case err != nil:
			return nil, err
		}
		chk, err := Verify(dir, reply.Files)
		if err != nil {
			return nil, err
		}
		res.Files, res.Summary, res.ModelRisks, res.Check, res.OK = reply.Files, reply.Summary, reply.Risks, chk, chk.OK
		if chk.OK {
			res.Stopped = ""
			return res, nil
		}
		res.Stopped = fmt.Sprintf("the draft still fails %d checks", len(chk.Errors))
		feedback = previous(reply.Files) + "Errors:\n- " + strings.Join(chk.Errors, "\n- ")
	}
	if res.Stopped != "" {
		res.Stopped += fmt.Sprintf(" after %d iterations (--max-iterations)", res.Iterations)
	}
	return res, nil
}

func previous(files []File) string {
	var b strings.Builder
	b.WriteString("Your previous draft:\n")
	for _, f := range files {
		fmt.Fprintf(&b, "--- %s\n%s\n", f.Path, f.Content)
	}
	return b.String()
}

// maxPolicyBytes caps the policy text sent to the model.
const maxPolicyBytes = 200 << 10

// policyFiles is every YAML file of the policy (hidden dirs skipped), each
// headed by its path, for the prompt.
func policyFiles(dir string) (string, error) {
	var names []string
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
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("copilot: read policy %s: %w", dir, err)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, p := range names {
		data, err := os.ReadFile(p) //nolint:gosec // operator-owned policy repo
		if err != nil {
			return "", fmt.Errorf("copilot: %w", err)
		}
		rel, _ := filepath.Rel(dir, p)
		fmt.Fprintf(&b, "=== %s\n%s\n", filepath.ToSlash(rel), data)
		if b.Len() > maxPolicyBytes {
			return "", fmt.Errorf("copilot: the policy is over %d KiB, too large to send; split the change or use --offline", maxPolicyBytes>>10)
		}
	}
	return b.String(), nil
}

// offlineIntent is the one draft template offline mode understands.
var offlineIntent = regexp.MustCompile(`(?i)^(?:set|pin|bump|change)\s+(\S+)\s+(version|model)\s+(?:to\s+)?(\S+)\s+(?:in|for|on)\s+profile\s+(\S+)$`)

// OfflineTemplates documents what offlineDraft understands.
const OfflineTemplates = `set <harness> version|model [to] <value> in profile <name>   e.g. "set claude-code version 2.1.300 in profile engineering"`

// offlineDraft is the deterministic, model-free draft: one template, edited
// in place with yamledit so comments and formatting are kept.
func offlineDraft(dir, intent string) ([]File, string, error) {
	m := offlineIntent.FindStringSubmatch(intent)
	if m == nil {
		return nil, "", fmt.Errorf("copilot: --offline understands only: %s", OfflineTemplates)
	}
	h, field, val, prof := m[1], strings.ToLower(m[2]), m[3], m[4]
	doc, err := yamledit.Find(dir, policy.KindProfile, prof)
	if err != nil {
		return nil, "", fmt.Errorf("copilot: %w", err)
	}
	data, err := doc.SetPath([]string{"harnesses", h, field}, yamledit.Quote(val, 0))
	if err != nil {
		return nil, "", fmt.Errorf("copilot: profile %s has no harnesses.%s.%s to set: %w", prof, h, field, err)
	}
	return []File{{Path: doc.Rel, Content: string(data)}}, fmt.Sprintf("set %s %s to %s in profile %s", h, field, val, prof), nil
}
