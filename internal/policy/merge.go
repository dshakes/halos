package policy

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// ResolveProfile returns the named profile with its extends chain applied
// (root ancestor first, child last). Merge semantics:
//   - scalars: child wins when set (non-zero). ponytail: zero means "unset", so a
//     child cannot turn a parent's true bool back to false; add pointer bools if needed.
//   - slices: child replaces the parent's list when non-empty, EXCEPT
//     permissions.deny, mcp.denied, hooks.items, extensions.artifacts, the
//     extensions deny/blocked lists, egress.deniedDomains and
//     sandbox.protectedPaths, which union (see below).
//   - sandbox.mode and permissions.sandbox are one setting: the result
//     carries the effective mode in both.
//   - maps: merged per key; struct values (e.g. harnesses) merge recursively,
//     other values (e.g. overrides) are child-wins per key.
//
// The result is a deep-ish copy: mutating it does not affect the Org.
// Extends cycles and missing parents are errors.
func (o *Org) ResolveProfile(name string) (*Profile, error) {
	chain, err := o.profileChain(name)
	if err != nil {
		return nil, err
	}
	out := &Profile{}
	var deny, mcpDenied, plugBlocked, skillDeny, agentDeny []string
	var blockedMkts []Marketplace
	var hooks []Hook
	var artifacts, deniedDomains, protected []string
	for i := len(chain) - 1; i >= 0; i-- {
		mergeValue(reflect.ValueOf(out).Elem(), reflect.ValueOf(chain[i]).Elem())
		deny = unionAppend(deny, chain[i].Permissions.Deny)
		mcpDenied = unionAppend(mcpDenied, chain[i].MCP.Denied)
		hooks = unionAppend(hooks, chain[i].Hooks.Hooks)
		e := chain[i].Extensions
		plugBlocked = unionAppend(plugBlocked, e.Plugins.Blocked)
		skillDeny = unionAppend(skillDeny, e.Skills.Deny)
		agentDeny = unionAppend(agentDeny, e.Subagents.Deny)
		blockedMkts = unionAppend(blockedMkts, e.BlockedMarketplaces)
		artifacts = unionAppend(artifacts, e.Artifacts)
		deniedDomains = unionAppend(deniedDomains, chain[i].Egress.DeniedDomains)
		protected = unionAppend(protected, chain[i].Sandbox.ProtectedPaths)
		syncSandboxMode(out, chain[i].Sandbox.Mode, chain[i].Permissions.Sandbox)
	}
	// Deny lists and hooks only accumulate down the chain: a child profile can
	// add restrictions (or audit hooks) but never silently drop a parent's.
	// (Same reason the zero-means-unset rule above is a feature for
	// DisableBypass/ManagedOnly.) Hooks dedupe on event+matcher+command.
	out.Permissions.Deny = deny
	out.MCP.Denied = mcpDenied
	out.Hooks.Hooks = hooks
	out.Extensions.Plugins.Blocked = plugBlocked
	out.Extensions.Skills.Deny = skillDeny
	out.Extensions.Subagents.Deny = agentDeny
	out.Extensions.BlockedMarketplaces = blockedMkts
	out.Extensions.Artifacts = artifacts
	out.Egress.DeniedDomains = deniedDomains
	out.Sandbox.ProtectedPaths = protected
	o.resolveArtifacts(out)
	out.Extends = ""
	return out, nil
}

// profileChain returns name's extends chain, child first. Extends cycles and
// missing parents are errors.
func (o *Org) profileChain(name string) ([]*Profile, error) {
	var chain []*Profile
	seen := map[string]bool{}
	for cur := name; cur != ""; {
		if seen[cur] {
			return nil, fmt.Errorf("policy: profile extends cycle: %s -> %s", strings.Join(names(chain), " -> "), cur)
		}
		seen[cur] = true
		p, ok := o.Profiles[cur]
		if !ok {
			if len(chain) == 0 {
				return nil, fmt.Errorf("policy: profile %q not found", cur)
			}
			return nil, fmt.Errorf("policy: profile %q extends unknown profile %q", chain[len(chain)-1].Name, cur)
		}
		chain = append(chain, p)
		cur = p.Extends
	}
	return chain, nil
}

// syncSandboxMode applies one layer's sandbox mode, set as sandbox.mode or
// permissions.sandbox (the later layer wins, as for any scalar), to both
// fields of out. A layer setting the two differently keeps both for Validate
// to report.
func syncSandboxMode(out *Profile, mode, perm string) {
	switch {
	case mode != "" && perm != "":
		out.Sandbox.Mode, out.Permissions.Sandbox = mode, perm
	case mode != "":
		out.Sandbox.Mode, out.Permissions.Sandbox = mode, mode
	case perm != "":
		out.Sandbox.Mode, out.Permissions.Sandbox = perm, perm
	}
}

func unionAppend[T comparable](dst, src []T) []T {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

func names(ps []*Profile) []string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.Name
	}
	return s
}

// mergeValue merges src into dst (dst addressable, same type).
func mergeValue(dst, src reflect.Value) {
	switch src.Kind() {
	case reflect.Struct:
		for i := 0; i < src.NumField(); i++ {
			mergeValue(dst.Field(i), src.Field(i))
		}
	case reflect.Map:
		if src.Len() == 0 {
			return
		}
		if dst.IsNil() {
			dst.Set(reflect.MakeMap(dst.Type()))
		}
		for _, k := range src.MapKeys() {
			sv := src.MapIndex(k)
			if sv.Kind() == reflect.Struct {
				nv := reflect.New(sv.Type()).Elem()
				if dv := dst.MapIndex(k); dv.IsValid() {
					nv.Set(dv)
				}
				mergeValue(nv, sv)
				dst.SetMapIndex(k, nv)
			} else {
				dst.SetMapIndex(k, sv)
			}
		}
	case reflect.Slice:
		if src.Len() > 0 {
			c := reflect.MakeSlice(src.Type(), src.Len(), src.Len())
			reflect.Copy(c, src)
			dst.Set(c)
		}
	default:
		if !src.IsZero() {
			dst.Set(src)
		}
	}
}
