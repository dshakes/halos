//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO where a user settings file belongs must not hang halod's cycle.
func TestReadSettingsFIFO(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "config.toml")
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	a := &Agent{}
	done := make(chan error, 1)
	go func() { _, err := a.readSettings(p); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read a FIFO as a settings file")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readSettings blocked on a FIFO")
	}
	_ = os.Remove(p)
}
