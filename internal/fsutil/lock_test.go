package fsutil

import (
	"errors"
	"testing"
)

func TestLockDirExclusiveAndReleasedOnClose(t *testing.T) {
	dir := t.TempDir()
	first, err := LockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockDir(dir); !errors.Is(err, ErrLocked) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("second LockDir = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := LockDir(dir)
	if err != nil {
		t.Fatalf("LockDir after Close: %v", err)
	}
	if err := again.Close(); err != nil || again.Close() != nil {
		t.Fatalf("Close twice: %v", err)
	}
}
