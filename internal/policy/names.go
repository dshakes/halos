package policy

import "regexp"

// nameRe is the only shape a policy identifier may take. Names flow into
// shell scripts, file paths, HTTP headers (ANTHROPIC_CUSTOM_HEADERS, x-halo-*)
// and OTEL attributes, so they are kept to a strict lowercase charset:
// no whitespace, no control characters, no quoting.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidName reports whether s is a safe policy identifier
// (ring, profile, experiment, variant, model alias, upstream, MCP server).
func ValidName(s string) bool { return nameRe.MatchString(s) }
