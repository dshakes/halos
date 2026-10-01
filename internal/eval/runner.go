package eval

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Job is one (task x variant x repeat) trial to set up an environment for.
type Job struct {
	Task    *Task
	Variant Variant
	// Settings is the host path of the rendered managed settings (may be empty)
	// and SettingsDest where it must appear in the environment.
	Settings     string
	SettingsDest string
}

// ExecResult is the outcome of one command. A non-zero ExitCode is not an
// error; err from Exec means the command could not run or was cancelled.
type ExecResult struct {
	Stdout, Stderr []byte
	ExitCode       int
}

// Env is an isolated, prepared workspace with the task repo checked out.
type Env interface {
	Exec(ctx context.Context, c Command) (ExecResult, error)
	Close() error
}

// Runner provisions isolated environments.
type Runner interface {
	Start(ctx context.Context, j Job) (Env, error)
}

// LocalRunner runs in temp directories on the host. It provides no isolation
// beyond a private copy of the repo: use it for tests, not untrusted agents.
// The settings file is copied next to the repo and its path exported to
// commands as HALO_SETTINGS_FILE.
type LocalRunner struct{}

type localEnv struct {
	root, work, settings string
}

func (LocalRunner) Start(ctx context.Context, j Job) (Env, error) {
	root, err := os.MkdirTemp("", "halo-eval-*")
	if err != nil {
		return nil, fmt.Errorf("local runner: %w", err)
	}
	e := &localEnv{root: root, work: filepath.Join(root, "work")}
	fail := func(err error) (Env, error) { _ = e.Close(); return nil, err }
	if isRemote(j.Task.Repo) {
		if err := checkRepo(j.Task.Repo); err != nil {
			return fail(err)
		}
		if out, err := exec.CommandContext(ctx, "git", gitCloneArgs(j.Task.Repo, e.work)...).CombinedOutput(); err != nil {
			return fail(fmt.Errorf("git clone %s: %w: %s", j.Task.Repo, err, out))
		}
	} else if src, err := j.Task.RepoDir(); err != nil {
		return fail(err)
	} else if err := copyDir(src, e.work); err != nil {
		return fail(fmt.Errorf("copy repo %s: %w", src, err))
	}
	if j.Settings != "" {
		if rel, err := filepath.Rel(j.Variant.Dir, j.Settings); j.Variant.Dir == "" || err != nil {
			return fail(fmt.Errorf("settings %s: no suite dir to check against", j.Settings))
		} else if _, err := resolveWithin(j.Variant.Dir, rel); err != nil {
			return fail(fmt.Errorf("settings: %w", err))
		}
		b, err := os.ReadFile(j.Settings)
		if err != nil {
			return fail(fmt.Errorf("read settings: %w", err))
		}
		e.settings = filepath.Join(root, "settings"+filepath.Ext(j.Settings))
		if err := os.WriteFile(e.settings, b, 0o600); err != nil { //nolint:gosec // path is built under a private temp root from a fixed name
			return fail(fmt.Errorf("stage settings: %w", err))
		}
	}
	return e, nil
}

func (e *localEnv) Exec(ctx context.Context, c Command) (ExecResult, error) {
	if len(c.Args) == 0 {
		return ExecResult{}, errors.New("exec: empty command")
	}
	cmd := exec.CommandContext(ctx, c.Args[0], c.Args[1:]...)
	cmd.Dir = e.work
	cmd.Env = append(os.Environ(), "HALO_SETTINGS_FILE="+e.settings)
	cmd.WaitDelay = 2 * time.Second
	if c.Stdin != "" {
		cmd.Stdin = strings.NewReader(c.Stdin)
	}
	return runCmd(ctx, cmd)
}

func (e *localEnv) Close() error { return os.RemoveAll(e.root) }

// runCmd runs cmd capturing output and maps ExitError to ExitCode.
func runCmd(ctx context.Context, cmd *exec.Cmd) (ExecResult, error) {
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	res := ExecResult{Stdout: out.Bytes(), Stderr: errb.Bytes()}
	var ee *exec.ExitError
	switch {
	case ctx.Err() != nil:
		res.ExitCode = -1
		return res, fmt.Errorf("%s: %w", cmd.Args[0], ctx.Err())
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
		return res, nil
	case err != nil:
		res.ExitCode = -1
		return res, fmt.Errorf("run %s: %w", cmd.Args[0], err)
	}
	return res, nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		in, err := os.Open(p) //nolint:gosec // walk over an operator-owned suite dir; only regular files are opened
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }() // read-only
		info, err := d.Info()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			_ = out.Close() // already failing
			return err
		}
		return out.Close()
	})
}
