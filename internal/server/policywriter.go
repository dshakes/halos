package server

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/halos-dev/halos/internal/controller"
	"github.com/halos-dev/halos/internal/policy"
	"github.com/halos-dev/halos/internal/promote"
	"github.com/halos-dev/halos/internal/yamledit"
)

// GitPolicyWriter implements PolicyWriter by editing YAML in a dedicated clone
// of the policy repo and handing the files to a promote.PROpener (GHOpener
// shells `git` + `gh`). It only opens PRs; a human merges.
//
// RepoDir MUST be a separate clone from the served policy directory (ServedDir):
// each proposal hard-resets RepoDir to origin/<Base> and PROpener checks out a
// branch there, and the served policy must never show unmerged changes.
type GitPolicyWriter struct {
	RepoDir   string
	ServedDir string // the served policy dir; Propose refuses if it overlaps RepoDir
	Subdir    string // policy root inside the repo ("" = repo root)
	Base      string // base branch, default "main"
	Opener    promote.PROpener
	// Git runs git in RepoDir and returns trimmed stdout (default: os/exec); injectable for tests.
	Git func(ctx context.Context, args ...string) (string, error)

	mu sync.Mutex // one proposal at a time: they share a working tree
}

// run adapts the injectable Git hook (if any) to promote.RunFunc.
func (w *GitPolicyWriter) run(ctx context.Context, dir, name string, args ...string) ([]byte, error) {
	if w.Git != nil {
		out, err := w.Git(ctx, args...)
		return []byte(out), err
	}
	return promote.Run(ctx, dir, name, args...)
}

// CheckSeparateClone refuses a writer clone that is, contains, or sits inside
// the served policy directory (symlinks resolved): proposals reset and branch
// the clone, and the served policy must never show unmerged changes.
func CheckSeparateClone(repoDir, servedDir string) error {
	a, b := evalAbs(repoDir), evalAbs(servedDir)
	within := func(x, y string) bool {
		r, err := filepath.Rel(y, x)
		return err == nil && r != ".." && !strings.HasPrefix(r, ".."+string(filepath.Separator))
	}
	if within(a, b) || within(b, a) {
		return fmt.Errorf("policy writer clone %s must be a separate clone from the served policy dir %s (proposals reset and check out branches)", repoDir, servedDir)
	}
	return nil
}

// evalAbs makes p absolute with symlinks resolved on its longest existing prefix.
func evalAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	rest := ""
	for d := a; ; d = filepath.Dir(d) {
		if r, err := filepath.EvalSymlinks(d); err == nil {
			return filepath.Join(r, rest)
		}
		if filepath.Dir(d) == d {
			return a
		}
		rest = filepath.Join(filepath.Base(d), rest)
	}
}

func (w *GitPolicyWriter) Propose(ctx context.Context, org *policy.Org, req Request, approver string) (string, error) {
	var edit func(*yamledit.Doc) ([]byte, error)
	var kind policy.Kind
	var name, title, what string
	switch req.Kind {
	case experimentStatusKind:
		return w.ProposeStatus(ctx, req.Item, req.Note, fmt.Sprintf("Set experiment %s to %s", req.Item, req.Note),
			fmt.Sprintf("Status change for experiment `%s` to `%s`, requested by %s from the Halos console (request `%s`).", req.Item, req.Note, approver, req.ID))
	case "ring-opt-in":
		kind, name = policy.KindRing, req.Item
		if r := ringByName(org, req.Item); r == nil || !r.Membership.OptIn {
			return "", fmt.Errorf("ring %q does not allow opt-in", req.Item)
		}
		edit = func(d *yamledit.Doc) ([]byte, error) {
			if u := d.Get("membership", "users"); u != nil && slices.ContainsFunc(u.Content, func(n *yaml.Node) bool { return n.Value == req.User }) {
				return nil, fmt.Errorf("%s is already a member of ring %q", req.User, req.Item)
			}
			return d.AppendSeq([]string{"membership", "users"}, req.User)
		}
		title, what = fmt.Sprintf("Opt-in to ring %s: %s", req.Item, req.User), "Adds the requester to the ring's `membership.users`. No IdP change needed."
	case "mcp-server":
		i := indexMCP(org, req.Item)
		if i < 0 {
			return "", fmt.Errorf("mcp server %q not in catalog", req.Item)
		}
		ring := ringByName(org, req.Ring)
		if ring == nil {
			return "", errors.New("requester's ring is unknown; cannot pick a profile to overlay")
		}
		kind, name = policy.KindProfile, ring.Profile
		srv := org.SelfService.Catalog[i]
		edit = func(d *yamledit.Doc) ([]byte, error) {
			if s := d.Get("mcp", "servers"); s != nil && slices.ContainsFunc(s.Content, func(n *yaml.Node) bool { _, v := yamledit.Scalar(n, "name"); return v != nil && v.Value == srv.Name }) {
				return nil, fmt.Errorf("profile %q already has MCP server %q", ring.Profile, srv.Name)
			}
			return d.AppendSeq([]string{"mcp", "servers"}, srv)
		}
		title, what = fmt.Sprintf("Add MCP server %s to profile %s (requested by %s)", srv.Name, ring.Profile, req.User), "Adds the catalog MCP server to the profile. Note this applies to everyone on the profile, not only the requester."
	default:
		return "", ErrManual
	}

	base, release, err := w.lockSynced(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	doc, err := yamledit.Find(filepath.Join(w.RepoDir, w.Subdir), kind, name)
	if err != nil {
		return "", err
	}
	data, err := edit(doc)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(w.RepoDir, doc.Path)
	if err != nil {
		return "", err
	}
	body := fmt.Sprintf("Access request `%s` from **%s** (%s `%s`), approved by %s.\n\nJustification:\n\n%s\n\n%s\n\nOpened by Halos; a human must review and merge.\n",
		req.ID, req.User, req.Kind, req.Item, approver, fenceUntrusted(req.Justification), what)
	return w.Opener.OpenPR(ctx, promote.PRRequest{
		RepoDir: w.RepoDir, Base: base, Branch: "halos/request-" + req.ID,
		Title: title, Body: body, Files: map[string][]byte{filepath.ToSlash(rel): data},
	})
}

// lockSynced takes the clone lock and hard-resets the clone to a pristine
// origin/<base> (a failed earlier proposal may have left it on a branch or with
// stray files); release resets it again and unlocks.
func (w *GitPolicyWriter) lockSynced(ctx context.Context) (base string, release func(), err error) {
	if err := CheckSeparateClone(w.RepoDir, w.ServedDir); err != nil {
		return "", nil, err
	}
	base = w.Base
	if base == "" {
		base = "main"
	}
	w.mu.Lock()
	if err := promote.SyncClone(ctx, w.run, w.RepoDir, base); err != nil {
		w.mu.Unlock()
		return "", nil, err
	}
	return base, func() {
		_ = promote.ResetClone(context.WithoutCancel(ctx), w.run, w.RepoDir, base)
		w.mu.Unlock()
	}, nil
}

// ProposeStatus implements controller.Writer on this clone, so the console
// and halo-server's experiment controller share one clone, one lock and one
// status-PR implementation (controller.GitWriter / promote.PlanStatus).
func (w *GitPolicyWriter) ProposeStatus(ctx context.Context, experiment, status, title, body string) (string, error) {
	base, release, err := w.lockSynced(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	gw := controller.GitWriter{RepoDir: w.RepoDir, Subdir: w.Subdir, Base: base, Opener: w.Opener}
	return gw.ProposeStatus(ctx, experiment, status, title, body)
}

var htmlTag = regexp.MustCompile(`<[^>]*>`)

// fenceUntrusted renders requester text inertly in a PR body: HTML tags
// stripped, @mentions defused with a zero-width joiner, inside a code fence
// longer than any backtick run in the text (so it cannot close the fence).
func fenceUntrusted(s string) string {
	s = htmlTag.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "@", "@\u200d")
	longest, run := 0, 0
	for _, c := range s {
		if c == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", max(3, longest+1))
	return fence + "text\n" + s + "\n" + fence
}

func indexMCP(org *policy.Org, name string) int {
	for i, m := range org.SelfService.Catalog {
		if m.Name == name {
			return i
		}
	}
	return -1
}

func ringByName(org *policy.Org, n string) *policy.Ring {
	for _, r := range org.Rings {
		if r.Name == n {
			return r
		}
	}
	return nil
}
