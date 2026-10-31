package policy

import (
	"fmt"
	"strings"
	"unicode"
)

// identity validates the console login hardening fields (ADR-0036).
func (v *validator) identity() {
	id := v.org.Identity
	if id.GroupsOverage != "" {
		v.oneOf("identity.groupsOverage", "groupsOverage", id.GroupsOverage, []string{GroupsOverageDeny, GroupsOverageGraph})
	}
	for _, f := range []struct {
		name string
		vals []string
	}{{"requireAcr", id.RequireAcr}, {"requireAmr", id.RequireAmr}} {
		seen := map[string]bool{}
		for i, x := range f.vals {
			path := fmt.Sprintf("identity.%s[%d]", f.name, i)
			switch {
			case x == "" || len(x) > 256 || strings.IndexFunc(x, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0:
				v.errf(path, "%q must be 1-256 characters without spaces", x)
			case seen[x]:
				v.errf(path, "%q is listed twice", x)
			}
			seen[x] = true
		}
	}
}
