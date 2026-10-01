package eval

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// DockerRunner isolates each trial in hardened containers by shelling out to
// the docker CLI. Each phase gets a FRESH container from the image, with only
// /work carried over (docker cp out, then in):
//
//	setup  -> container A (task-author shell; no secrets)
//	agent  -> container B (PassEnv secrets via exec -e; nothing A started survives)
//	check  -> container C (no secrets; cannot read B's /proc/<pid>/environ)
//
// Every container is removed (`docker rm -f`, killing all its processes)
// before the next phase starts, on Close, and when a step's context ends.
//
// Remote repos are cloned on the HOST (protocol-allowlisted) and copied in, so
// the containers need no egress for setup/check (Network "none").
//
// Secrets: PassEnv should hold short-lived gateway tokens (minted per run and
// scoped to the Halos gateway), never long-lived provider keys: the agent
// step runs model-driven tool calls that can read its own environment.
// Recommended networking: set Network to a docker network whose only egress
// is the Halos gateway; it applies to every phase's container.
//
// Files are streamed in as a tar whose entries are owned by User: plain
// `docker cp` keeps the host uid (e.g. 501), leaving the non-root agent unable
// to edit files in place. Verified end to end against a real daemon with the
// evals/images/fake stub image.
type DockerRunner struct {
	Bin string // default "docker"
	// Image returns the image for a variant; default
	// ghcr.io/halos-dev/eval-<harness>:<version>.
	Image func(Variant) string
	// PassEnv names host env vars forwarded into the agent step only.
	PassEnv []string
	// Network is passed as --network; default "none".
	Network string
	// Memory (default "4g"), CPUs (default "2") and User (default
	// "1000:1000", non-root) bound each container.
	Memory, CPUs, User string
}

type dockerEnv struct {
	d       *DockerRunner
	job     Job
	bin     string
	name    string // current container ("" once removed)
	passEnv []string
	tmp     string // host scratch: /work snapshots between phases
	phase   int    // phaseSetup -> phaseAgent -> phaseCheck
}

const (
	phaseSetup = iota
	phaseAgent
	phaseCheck
)

func (d *DockerRunner) bin() string {
	if d.Bin == "" {
		return "docker"
	}
	return d.Bin
}

func (d *DockerRunner) image(v Variant) string {
	if d.Image != nil {
		return d.Image(v)
	}
	tag := v.Version
	if tag == "" {
		tag = "latest"
	}
	return fmt.Sprintf("ghcr.io/halos-dev/eval-%s:%s", v.Harness, tag)
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// runArgs builds the `docker run` argv for a job. No env is set here.
func (d *DockerRunner) runArgs(j Job, name string) ([]string, error) {
	args := []string{"run", "-d", "--rm", "--name", name, "-w", "/work",
		"--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512",
		"--memory=" + or(d.Memory, "4g"), "--cpus=" + or(d.CPUs, "2"), "--user=" + or(d.User, "1000:1000"),
		"--network", or(d.Network, "none")}
	if j.Settings != "" && j.SettingsDest != "" {
		// Defense in depth: LoadSuite already enforces this.
		rel, err := filepath.Rel(j.Variant.Dir, j.Settings)
		if j.Variant.Dir == "" || err != nil {
			return nil, fmt.Errorf("settings %s: no suite dir to check against", j.Settings)
		}
		if _, err := resolveWithin(j.Variant.Dir, rel); err != nil {
			return nil, fmt.Errorf("settings: %w", err)
		}
		args = append(args, "-v", j.Settings+":"+j.SettingsDest+":ro")
	}
	return append(args, d.image(j.Variant), "sleep", "infinity"), nil
}

func (d *DockerRunner) Start(ctx context.Context, j Job) (Env, error) {
	tmp, err := os.MkdirTemp("", "halo-eval-*")
	if err != nil {
		return nil, fmt.Errorf("docker runner: %w", err)
	}
	e := &dockerEnv{d: d, job: j, bin: d.bin(), passEnv: d.PassEnv, tmp: tmp}
	fail := func(err error) (Env, error) { _ = e.Close(); return nil, fmt.Errorf("docker runner: %w", err) }
	var repoSrc string
	if isRemote(j.Task.Repo) {
		if err := checkRepo(j.Task.Repo); err != nil {
			return fail(err)
		}
		repoSrc = filepath.Join(tmp, "repo")
		if out, err := exec.CommandContext(ctx, "git", gitCloneArgs(j.Task.Repo, repoSrc)...).CombinedOutput(); err != nil {
			return fail(fmt.Errorf("git clone %s: %w: %s", j.Task.Repo, err, strings.TrimSpace(string(out))))
		}
	} else if repoSrc, err = j.Task.RepoDir(); err != nil {
		return fail(err)
	}
	if err := e.start(ctx, repoSrc); err != nil {
		return fail(err)
	}
	return e, nil
}

// start runs a fresh container and copies src into its /work.
func (e *dockerEnv) start(ctx context.Context, src string) error {
	args, err := e.d.runArgs(e.job, "")
	if err != nil {
		return err
	}
	var rb [6]byte
	if _, err := rand.Read(rb[:]); err != nil {
		return err
	}
	name := "halo-eval-" + hex.EncodeToString(rb[:])
	args[4] = name
	if out, err := exec.CommandContext(ctx, e.bin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("docker run: %w: %s", err, strings.TrimSpace(string(out)))
	}
	e.name = name
	uid, gid, err := parseUser(or(e.d.User, "1000:1000"))
	if err != nil {
		return err
	}
	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(tarDir(pw, src, uid, gid)) }()
	cp := exec.CommandContext(ctx, e.bin, "cp", "-", name+":/work")
	cp.Stdin = pr
	out, err := cp.CombinedOutput()
	_ = pr.CloseWithError(errors.New("docker cp finished")) // unblocks the tar goroutine if cp exited early
	if err != nil {
		return fmt.Errorf("docker cp into %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseUser parses a numeric "uid[:gid]" (gid defaults to uid).
func parseUser(u string) (uid, gid int, err error) {
	a, b, found := strings.Cut(u, ":")
	if uid, err = strconv.Atoi(a); err == nil {
		gid = uid
		if found {
			gid, err = strconv.Atoi(b)
		}
	}
	if err != nil {
		return 0, 0, fmt.Errorf("docker runner: User %q must be numeric uid[:gid]: %w", u, err)
	}
	return uid, gid, nil
}

// tarDir writes the contents of dir as a tar with every entry owned by uid:gid.
// Only regular files, directories and symlinks are included.
func tarDir(w io.Writer, dir string, uid, gid int) error {
	// The task tree is untrusted: every file is opened through an os.Root so a
	// file swapped for a symlink after the walk saw it can't pull host files
	// (e.g. ~/.aws) into the container. Symlinks themselves are copied as links.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("tar %s: %w", dir, err)
	}
	defer func() { _ = root.Close() }()
	tw := tar.NewWriter(w)
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(path); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() && !info.IsDir() {
			return nil
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			h.Name += "/"
		}
		h.Uid, h.Gid, h.Uname, h.Gname = uid, gid, "", ""
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := root.Open(rel)
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("tar %s: %w", dir, err)
	}
	return tw.Close()
}

// advance moves to phase p: snapshot /work to the host, remove the current
// container (killing everything it ran), and start a fresh one from the
// snapshot. A no-op when already there.
func (e *dockerEnv) advance(ctx context.Context, p int) error {
	if e.phase >= p {
		return nil
	}
	e.phase = p
	if e.name == "" {
		return errors.New("docker runner: container already removed")
	}
	snap := filepath.Join(e.tmp, fmt.Sprintf("work-%d", p))
	out, err := exec.CommandContext(ctx, e.bin, "cp", e.name+":/work/.", snap).CombinedOutput()
	if rmErr := e.removeContainer(); err == nil && rmErr != nil {
		return rmErr
	}
	if err != nil {
		return fmt.Errorf("docker cp out of %s: %w: %s", e.name, err, strings.TrimSpace(string(out)))
	}
	return e.start(ctx, snap)
}

func (e *dockerEnv) Exec(ctx context.Context, c Command) (ExecResult, error) {
	if e.phase == phaseAgent { // first command after the agent is the check
		if err := e.advance(ctx, phaseCheck); err != nil {
			return ExecResult{ExitCode: -1}, err
		}
	}
	return e.exec(ctx, c, nil)
}

// ExecAgent runs c in a fresh container with the PassEnv secrets injected.
func (e *dockerEnv) ExecAgent(ctx context.Context, c Command) (ExecResult, error) {
	if e.phase == phaseCheck {
		return ExecResult{ExitCode: -1}, errors.New("docker runner: agent step after check")
	}
	if err := e.advance(ctx, phaseAgent); err != nil {
		return ExecResult{ExitCode: -1}, err
	}
	return e.exec(ctx, c, e.passEnv)
}

func (e *dockerEnv) exec(ctx context.Context, c Command, env []string) (ExecResult, error) {
	if e.name == "" {
		return ExecResult{ExitCode: -1}, errors.New("docker runner: container already removed")
	}
	args := []string{"exec", "-i", "-w", "/work"}
	for _, k := range env {
		args = append(args, "-e", k) // value comes from this process's env, not argv
	}
	args = append(args, e.name)
	args = append(args, c.Args...)
	cmd := exec.CommandContext(ctx, e.bin, args...)
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	res, err := runCmd(ctx, cmd)
	if ctx.Err() != nil {
		// Killing the docker CLI leaves the process running in the container;
		// remove the container so a timed-out step cannot keep going.
		_ = e.removeContainer() // best effort; the step already failed
	}
	return res, err
}

// Close removes the current container and the host scratch dir.
func (e *dockerEnv) Close() error {
	err := e.removeContainer()
	if rerr := os.RemoveAll(e.tmp); rerr != nil {
		err = errors.Join(err, fmt.Errorf("remove %s: %w", e.tmp, rerr))
	}
	return err
}

// removeContainer force-removes the current container, killing all its processes.
func (e *dockerEnv) removeContainer() error {
	if e.name == "" {
		return nil
	}
	name := e.name
	e.name = ""
	// Background context: cleanup must happen even if the trial ctx is cancelled.
	if out, err := exec.CommandContext(context.Background(), e.bin, "rm", "-f", name).CombinedOutput(); err != nil {
		return fmt.Errorf("docker rm %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}
