package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dshakes/halos/internal/harness"
)

func TestImmutableFlag(t *testing.T) {
	e := newEnv(t)
	e.a.Cfg.Immutable, e.a.Install = true, false
	ctx := context.Background()
	p, old := filepath.Join(e.root, settings), filepath.Join(e.root, "/etc/claude-code/old.json")
	flags := func() []string {
		var out []string
		for _, c := range e.cmds {
			if strings.HasPrefix(c, "chattr ") || strings.HasPrefix(c, "chflags ") {
				out = append(out, c)
			}
		}
		e.cmds = nil
		return out
	}

	e.publish(t, "1", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}, {Path: "/etc/claude-code/old.json", Mode: 0o644, Data: []byte("{}")}}, false)
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	// new files: nothing to clear, flag set after the write
	if got := flags(); !slices.Contains(got, "chattr +i "+p) || !slices.Contains(got, "chattr +i "+old) || slices.Contains(got, "chattr -i "+p) {
		t.Fatalf("first apply: %v", got)
	}
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	if got := flags(); !slices.Equal(got, []string{"chattr +i " + p, "chattr +i " + old}) && !slices.Equal(got, []string{"chattr +i " + old, "chattr +i " + p}) {
		t.Fatalf("unchanged files: flag re-applied only, got %v", got)
	}

	// rewrite clears before and sets after; a dropped file is cleared before removal
	e.publish(t, "2", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`2`)}}, false)
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	got := flags()
	i, j := slices.Index(got, "chattr -i "+p), slices.Index(got, "chattr +i "+p)
	if i < 0 || j < i || !slices.Contains(got, "chattr -i "+old) || slices.Contains(got, "chattr +i "+old) {
		t.Fatalf("rewrite/remove: %v", got)
	}
	if !strings.Contains(e.read(settings), `"x":2`) || e.read("/etc/claude-code/old.json") != "<missing>" {
		t.Fatal("release 2 not applied")
	}

	// macOS uses chflags
	if n, f := immutableCmd("darwin", true); n != "chflags" || f != "schg" {
		t.Fatalf("darwin set: %s %s", n, f)
	}
	if n, f := immutableCmd("darwin", false); n != "chflags" || f != "noschg" {
		t.Fatalf("darwin clear: %s %s", n, f)
	}
	if n, _ := immutableCmd("windows", true); n != "" {
		t.Fatal("windows has no immutable flag")
	}
}

func TestImmutableDegradesGracefully(t *testing.T) {
	e := newEnv(t)
	e.a.Cfg.Immutable, e.a.Install = true, false
	var logs bytes.Buffer
	e.a.Log = slog.New(slog.NewTextHandler(&logs, nil))
	run := e.a.Run
	e.a.Run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "chattr" {
			return []byte("chattr: Operation not supported"), errors.New("exit status 1")
		}
		return run(ctx, name, args...)
	}
	e.publish(t, "1", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}, {Path: "/etc/claude-code/b.json", Mode: 0o644, Data: []byte("{}")}}, false)
	st, err := e.a.Once(context.Background())
	if err != nil || st.LastError != "" || !strings.Contains(e.read(settings), `"x":1`) {
		t.Fatalf("a missing chattr must not fail the cycle: %v %+v", err, st)
	}
	if n := strings.Count(logs.String(), "immutable: could not change the flag"); n != 1 {
		t.Fatalf("want the failure logged once, got %d:\n%s", n, logs.String())
	}

	off := newEnv(t) // default: never touched
	off.a.Install = false
	off.publish(t, "1", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`1`)}}, false)
	if _, err := off.a.Once(context.Background()); err != nil || off.ran("chattr") || off.ran("chflags") {
		t.Fatalf("immutable off ran a flag command: %v %v", err, off.cmds)
	}
}
