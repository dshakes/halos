// Package all registers every built-in harness adapter via blank imports.
package all

import (
	_ "github.com/dshakes/halos/internal/harness/claudecode"
	_ "github.com/dshakes/halos/internal/harness/codex"
	_ "github.com/dshakes/halos/internal/harness/copilot"
	_ "github.com/dshakes/halos/internal/harness/gemini"
)
