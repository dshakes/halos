package onboard

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

// File actions in an install plan.
const (
	ActionCreate    = "create"
	ActionUpdate    = "update"
	ActionUnchanged = "unchanged"
	// ActionForeign is a differing file Halos did not write (e.g. one an MDM
	// pushed). Apply refuses to replace it unless asked to.
	ActionForeign = "foreign"
)

// ErrForeign is returned (wrapped) by Install when apply would replace files
// Halos did not write and replace was not set.
var ErrForeign = errors.New("refusing to replace files Halos did not write")

// FilePlan is one managed config file: where it lands and what happens to it.
type FilePlan struct {
	Harness string `json:"harness"`
	Path    string `json:"path"` // the path the CLI reads
	Dest    string `json:"dest"` // where it is written (Path, or under --root)
	Mode    uint32 `json:"mode"`
	Action  string `json:"action"`
	Backup  string `json:"backup,omitempty"` // an existing differing file is kept here first
	Content string `json:"content"`
	data    []byte
}

// InstallPlan is what installing a ring's release on this machine does.
type InstallPlan struct {
	Ring     string            `json:"ring"`
	OS       string            `json:"os"`
	Root     string            `json:"root,omitempty"`
	Gateway  string            `json:"gateway,omitempty"`
	Versions map[string]string `json:"versions"` // harness -> pinned CLI version ("" = unpinned)
	Files    []FilePlan        `json:"files"`
	Warnings []string          `json:"warnings"`
}

// DefaultRing is the ring a single machine follows: the last (GA) ring.
func DefaultRing(org *policy.Org) string {
	best := (*policy.Ring)(nil)
	for _, r := range org.Rings {
		if best == nil || r.Order > best.Order {
			best = r
		}
	}
	if best == nil {
		return ""
	}
	return best.Name
}

// PlanInstall renders ring's release for goos and compares each file with
// what is on disk under root ("" = the real paths). It writes nothing.
func PlanInstall(org *policy.Org, ring, goos, root string) (*InstallPlan, error) {
	if ring == "" {
		ring = DefaultRing(org)
	}
	var r *policy.Ring
	for _, x := range org.Rings {
		if x.Name == ring {
			r = x
		}
	}
	if r == nil {
		return nil, fmt.Errorf("unknown ring %q", ring)
	}
	rel, err := release.Build(org, r.Profile, ring, release.Options{Version: "0.0.0-local", Org: org.Name, OSes: []harness.OS{harness.OS(goos)}})
	if err != nil {
		return nil, fmt.Errorf("render ring %s: %w", ring, err)
	}
	p := &InstallPlan{Ring: ring, OS: goos, Root: root, Versions: map[string]string{}, Files: []FilePlan{}, Warnings: rel.Manifest.Warnings}
	if p.Warnings == nil {
		p.Warnings = []string{}
	}
	if org.Gateway != nil {
		p.Gateway = org.Gateway.BaseURL
	}
	var hs []string
	for h := range rel.Manifest.Harnesses {
		hs = append(hs, h)
	}
	sort.Strings(hs)
	for _, h := range hs {
		p.Versions[h] = rel.Manifest.Harnesses[h].Version
		for _, f := range rel.Manifest.Harnesses[h].Files[goos] {
			data, ok := rel.Content(f)
			if !ok {
				return nil, fmt.Errorf("release is missing blob for %s", f.Path)
			}
			fp := FilePlan{Harness: h, Path: f.Path, Dest: under(root, f.Path), Mode: f.Mode, Content: string(data), data: data}
			// Halos never manages a symlink: refusing one keeps a root apply from
			// following it (backup reads, ownership checks) somewhere else.
			if st, err := os.Lstat(fp.Dest); err == nil && st.Mode()&fs.ModeSymlink != 0 {
				return nil, fmt.Errorf("%s is a symlink; refusing to manage it (replace it with a regular file or remove it)", fp.Dest)
			}
			cur, err := os.ReadFile(fp.Dest)
			switch {
			case errors.Is(err, fs.ErrNotExist):
				fp.Action = ActionCreate
			case err != nil:
				return nil, fmt.Errorf("read %s: %w", fp.Dest, err)
			case bytes.Equal(cur, data):
				fp.Action = ActionUnchanged
			case ownedByHalos(fp.Dest, cur):
				fp.Action = ActionUpdate // Halos's own content: nothing to keep
			default:
				// Anyone else's content (an MDM push, a hand edit, a file from
				// before Halos recorded hashes) is foreign every time, and is
				// backed up when replaced without clobbering an earlier backup.
				fp.Action = ActionForeign
				fp.Backup = fp.Dest + backupSuffix
				if _, err := os.Lstat(fp.Backup); err == nil {
					fp.Backup += "." + time.Now().UTC().Format("20060102T150405Z")
				}
			}
			p.Files = append(p.Files, fp)
		}
	}
	return p, nil
}

const (
	backupSuffix = ".halos-backup"
	// ownerSuffix holds the sha256 of the content Halos last wrote, so a later
	// install can tell its own file from one someone else (re)wrote.
	// ponytail: a plain sidecar, so the check is only as strong as the managed
	// directory's permissions (root-owned, not group/world-writable, as every
	// CLI's managed dir is). Anyone who can write there can forge it, and could
	// overwrite the config directly anyway; sign it if that ever changes.
	ownerSuffix = ".halos-sha256"
)

func ownedByHalos(dest string, cur []byte) bool {
	want, err := os.ReadFile(dest + ownerSuffix)
	return err == nil && strings.TrimSpace(string(want)) == sha256Hex(cur)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// under joins an absolute (possibly Windows) path under root, neutralising
// drive letters and "..". root "" returns p unchanged.
func under(root, p string) string {
	if root == "" {
		return p
	}
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) > 1 && p[1] == ':' {
		p = p[2:]
	}
	return filepath.Join(root, filepath.FromSlash(path.Clean("/"+p)))
}

// ErrPermission is returned (wrapped) when a managed path is not writable.
var ErrPermission = errors.New("permission denied")

// Apply writes every create/update/foreign file (callers gate foreign ones).
// A replaced foreign file is kept at <dest>.halos-backup (timestamped if that
// exists), and each write records its hash at <dest>.halos-sha256.
// Idempotent: a second Apply finds every file unchanged and writes nothing.
func (p *InstallPlan) Apply() ([]string, error) {
	written := []string{}
	for _, f := range p.Files {
		if f.Action == ActionUnchanged {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(f.Dest), 0o755); err != nil {
			return written, permErr(f.Dest, err)
		}
		if f.Backup != "" {
			cur, err := os.ReadFile(f.Dest)
			if err != nil {
				return written, fmt.Errorf("back up %s: %w", f.Dest, err)
			}
			if err := fsutil.WriteAtomic(f.Backup, cur, fsutil.ExistingPerm(f.Dest, 0o600)); err != nil {
				return written, permErr(f.Backup, err)
			}
		}
		mode := os.FileMode(f.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := fsutil.WriteAtomic(f.Dest, f.data, mode); err != nil {
			return written, permErr(f.Dest, err)
		}
		if err := fsutil.WriteAtomic(f.Dest+ownerSuffix, []byte(sha256Hex(f.data)+"\n"), 0o644); err != nil {
			return written, permErr(f.Dest+ownerSuffix, err)
		}
		written = append(written, f.Dest)
	}
	return written, nil
}

func permErr(p string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("write %s: %w (managed config lives in admin-owned directories: re-run the same command with sudo, or stage it with --root DIR)", p, ErrPermission)
	}
	return fmt.Errorf("write %s: %w", p, err)
}

// LocalProxyDir is where `halo onboard proxy` writes, inside the policy repo.
const LocalProxyDir = ".halos/local"

// DefaultLocalProxy is the loopback listener a local halo-proxy uses.
const DefaultLocalProxy = "127.0.0.1:8088"

// upstreamHeaders are the provider credentials a local proxy injects, by
// upstream kind, as ${ENV} references halo-proxy expands at startup. Kinds
// with a policy credential (openai) or ambient auth (bedrock SigV4, vertex
// ADC) need none.
var upstreamHeaders = map[string]map[string]string{
	"anthropic": {"x-api-key": "${ANTHROPIC_API_KEY}", "anthropic-version": "2023-06-01"},
	"gemini":    {"x-goog-api-key": "${GEMINI_API_KEY}"},
}

// upstreamHeadersYAML is halo-proxy's upstreamHeaders block for org's
// upstreams (empty when none needs a header), each line prefixed by indent.
func upstreamHeadersYAML(org *policy.Org, indent string) string {
	var names []string
	if org.Gateway != nil {
		for n := range org.Gateway.Upstreams {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		hs := upstreamHeaders[org.Gateway.Upstreams[n].Kind]
		if hs == nil {
			continue
		}
		if b.Len() == 0 {
			b.WriteString(indent + "upstreamHeaders:\n")
		}
		var ks []string
		for k := range hs {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		fmt.Fprintf(&b, "%s  %s:\n", indent, n)
		for _, k := range ks {
			fmt.Fprintf(&b, "%s    %s: %q\n", indent, k, hs[k])
		}
	}
	return b.String()
}

// LocalProxy returns the files for a single-developer halo-proxy on loopback
// (identity off: it listens on 127.0.0.1 only) keyed by path relative to the
// policy repo, plus the command that starts it. absDir is the policy repo's
// absolute path (halo-proxy resolves the snapshot path from it).
func LocalProxy(org *policy.Org, absDir, listen string) (map[string][]byte, string, error) {
	if listen == "" {
		listen = DefaultLocalProxy
	}
	if h, _, ok := strings.Cut(listen, ":"); !ok || (h != "127.0.0.1" && h != "localhost" && h != "[::1]") {
		return nil, "", fmt.Errorf("listen %q: a local proxy has no identity check, so it must listen on loopback (127.0.0.1:PORT)", listen)
	}
	snap, err := policy.Compile(org)
	if err != nil {
		return nil, "", err
	}
	var b strings.Builder
	b.WriteString("# Local halo-proxy for one developer (DEV ONLY), written by `halo onboard proxy`.\n")
	b.WriteString("# Loopback only and identity off: anything that can reach the port uses your provider keys.\n")
	b.WriteString("# Keys are read from your environment at startup; this file holds none.\n")
	fmt.Fprintf(&b, "listen: %q\nadminListen: \"\"\npolicy: %q\nidentity:\n  mode: none\n", listen, filepath.Join(absDir, LocalProxyDir, "policy.json"))
	b.WriteString(upstreamHeadersYAML(org, ""))
	cfg := filepath.Join(absDir, LocalProxyDir, "halo-proxy.yaml")
	return map[string][]byte{
		LocalProxyDir + "/policy.json":     snap,
		LocalProxyDir + "/halo-proxy.yaml": []byte(b.String()),
	}, "halo-proxy --config " + cfg, nil
}

// VerifyPrompt is what verify asks; a pass is the token in the reply.
const (
	VerifyPrompt = "Reply with exactly the word HALOS_OK and nothing else."
	verifyToken  = "HALOS_OK"
)

// verifyArgs is each CLI's documented headless invocation.
var verifyArgs = map[string][]string{
	"claude-code": {"-p", VerifyPrompt},
	"codex":       {"exec", "--skip-git-repo-check", VerifyPrompt},
	"gemini-cli":  {"-p", VerifyPrompt},
	"copilot-cli": {"-p", VerifyPrompt},
}

// Verify results.
const (
	VerifyPass    = "pass"
	VerifyFail    = "fail"
	VerifySkipped = "skipped"
	VerifyDryRun  = "dry-run"
)

// VerifyResult is one headless round trip. Output is redacted and truncated.
type VerifyResult struct {
	Harness string   `json:"harness"`
	Command []string `json:"command"`
	Status  string   `json:"status"`
	Detail  string   `json:"detail"`
	Output  string   `json:"output,omitempty"`
}

// Verify runs h headless with VerifyPrompt (unless dry) and checks the reply.
// It is skipped when the CLI is missing or no credential variable is set and
// assumeAuth is false (a logged-in CLI needs --assume-auth: halo cannot see it).
func Verify(ctx context.Context, e Env, h string, assumeAuth, dry bool, timeout time.Duration) VerifyResult {
	args, ok := verifyArgs[h]
	m, _ := harness.MetaOf(h)
	if !ok || m.Binary == "" {
		return VerifyResult{Harness: h, Command: []string{}, Status: VerifyFail, Detail: "unknown harness " + h}
	}
	r := VerifyResult{Harness: h, Command: append([]string{m.Binary}, args...)}
	p, err := e.LookPath(m.Binary)
	switch {
	case err != nil:
		r.Status, r.Detail = VerifySkipped, m.Binary+" is not on PATH: "+installFix(h, "", e.GOOS)
		return r
	case !assumeAuth && !anySet(e, harnessEnvs[h]):
		r.Status, r.Detail = VerifySkipped, "no credential variable set ("+strings.Join(harnessEnvs[h], ", ")+"); if "+m.Binary+" is logged in, pass --assume-auth"
		return r
	case dry:
		r.Status, r.Detail = VerifyDryRun, "would run this command (one short model call)"
		return r
	}
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := e.Run(cctx, p, args...)
	s := strings.TrimSpace(redact(e, string(out)))
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	r.Output = s
	switch {
	case err != nil:
		r.Status, r.Detail = VerifyFail, m.Binary+" exited with an error: "+firstLine(err.Error())
	case strings.Contains(string(out), verifyToken):
		r.Status, r.Detail = VerifyPass, m.Binary+" answered through its configured endpoint"
	default:
		r.Status, r.Detail = VerifyFail, "reply did not contain "+verifyToken
	}
	return r
}
