package eval

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

var (
	fakeDockerOnce sync.Once
	fakeDockerBin  string
	fakeDockerErr  error
	fakeDockerDir  string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if fakeDockerDir != "" {
		_ = os.RemoveAll(fakeDockerDir)
	}
	os.Exit(code)
}

// fakeDockerCLI builds testdata/fakedocker once and points it at a fresh call
// log. Configure it with t.Setenv (FAKE_DOCKER_*; see its doc comment).
func fakeDockerCLI(t *testing.T) (bin, log string) {
	t.Helper()
	fakeDockerOnce.Do(func() {
		fakeDockerDir, fakeDockerErr = os.MkdirTemp("", "fakedocker")
		if fakeDockerErr != nil {
			return
		}
		name := "docker"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		fakeDockerBin = filepath.Join(fakeDockerDir, name)
		if out, err := exec.Command("go", "build", "-o", fakeDockerBin, "./testdata/fakedocker").CombinedOutput(); err != nil {
			fakeDockerErr = fmt.Errorf("go build ./testdata/fakedocker: %w\n%s", err, out)
		}
	})
	if fakeDockerErr != nil {
		t.Fatalf("build fake docker: %v", fakeDockerErr)
	}
	log = filepath.Join(t.TempDir(), "docker.log")
	t.Setenv("FAKE_DOCKER_LOG", log)
	return fakeDockerBin, log
}
