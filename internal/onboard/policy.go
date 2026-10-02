package onboard

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dshakes/halos/internal/intent"
	"github.com/dshakes/halos/internal/policy"
)

// Policy actions.
const (
	PolicyCreate    = "create"
	PolicyUnchanged = "unchanged"
	PolicyKept      = "kept" // exists and differs from the answers: never overwritten
)

// PolicyResult is what InitPolicy decided for halos.yaml.
type PolicyResult struct {
	Path    string   `json:"path"`
	Action  string   `json:"action"`
	Content string   `json:"content"`
	Notes   []string `json:"notes"`
}

// InitPolicy is the idempotent front half of `halo init`: the halos.yaml o
// describes, as a change on dir. An existing halos.yaml is never replaced:
// the change is then empty and the result says whether it already matches.
// The caller validates (Change.Validate) and applies.
func InitPolicy(dir string, o intent.InitOptions) (*intent.Change, PolicyResult, error) {
	p := filepath.Join(dir, policy.RootFile)
	res := PolicyResult{Path: p, Notes: []string{}}
	notes, err := o.Complete(nil)
	if err != nil {
		return nil, res, err
	}
	if o.Gateway == "" {
		o.Gateway = "https://ai." + o.Org + ".example"
	}
	want := intent.InitFile(o)
	ch := &intent.Change{Dir: dir, Files: map[string][]byte{}}
	if cur, err := os.ReadFile(p); err == nil {
		res.Content = string(cur)
		if bytes.Equal(cur, want) {
			res.Action = PolicyUnchanged
		} else {
			res.Action = PolicyKept
			res.Notes = append(res.Notes, fmt.Sprintf("%s already exists and differs from these answers; it was kept as is. Edit it, or use halo model switch / halo enable", p))
		}
		return ch, res, nil
	} else if !os.IsNotExist(err) {
		return nil, res, fmt.Errorf("read %s: %w", p, err)
	}
	ch.Files[policy.RootFile] = want
	res.Action, res.Content = PolicyCreate, string(want)
	res.Notes = append(res.Notes, notes...)
	return ch, res, nil
}

// Issues converts validation issues to plain strings; ok is false on any error.
func Issues(is []policy.Issue) (out []string, ok bool) {
	out = []string{}
	for _, i := range is {
		out = append(out, i.String())
	}
	return out, !policy.HasErrors(is)
}
