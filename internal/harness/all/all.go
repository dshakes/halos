// Package all registers every built-in harness adapter via blank imports.
package all

import (
	_ "github.com/halos-dev/halos/internal/harness/claudecode"
	_ "github.com/halos-dev/halos/internal/harness/codex"
	_ "github.com/halos-dev/halos/internal/harness/copilot"
	_ "github.com/halos-dev/halos/internal/harness/gemini"
)
