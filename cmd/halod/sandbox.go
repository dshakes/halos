package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// errSandboxUnavailable is reported with ErrorCode "sandbox_unavailable": the
// applied settings require Claude's sandbox but its Linux dependencies are
// missing, so Claude would refuse to start (sandbox.failIfUnavailable).
var errSandboxUnavailable = errors.New("sandbox unavailable")

// sandboxDeps maps each dependency to the fixed system locations distros
// install it at. Lookup never uses PATH; halod does not install packages.
var sandboxDeps = map[string][]string{
	"bwrap": {"/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"},
	"socat": {"/usr/bin/socat", "/bin/socat", "/usr/local/bin/socat"},
}

// requiresSandbox reports whether a rendered settings file sets
// sandbox.failIfUnavailable (profile permissions.sandboxRequired).
func requiresSandbox(data []byte) bool {
	var d struct {
		Sandbox struct {
			FailIfUnavailable bool `json:"failIfUnavailable"`
		} `json:"sandbox"`
	}
	return json.Unmarshal(data, &d) == nil && d.Sandbox.FailIfUnavailable
}

// checkSandboxDeps returns errSandboxUnavailable when a required dependency is absent.
func (a *Agent) checkSandboxDeps() error {
	var missing []string
	for _, name := range []string{"bwrap", "socat"} {
		found := false
		for _, p := range sandboxDeps[name] {
			if _, err := os.Stat(a.path(p)); err == nil {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: profile requires the sandbox but %s not found (install bubblewrap and socat)", errSandboxUnavailable, strings.Join(missing, ", "))
	}
	return nil
}
