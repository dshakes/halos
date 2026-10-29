package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
)

// ciChange is the change `halo freeze check` judges in CI. base is the
// protected branch (a remote-tracking ref the PR cannot move): governance and
// ring history are read from it, never from the PR's own checkout. from is the
// commit the change (HEAD) is diffed against.
type ciChange struct{ base, from string }

var hexSHA = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)

// eventChange reads base and from out of a GitHub Actions event payload:
// pull_request (base.ref, base.sha) or merge_group (base_ref, base_sha; in the
// merge queue head_ref is empty and ref_name is gh-readonly-queue/...).
func eventChange(p string) (ciChange, error) {
	b, err := os.ReadFile(p) //nolint:gosec // the CI event payload path the caller names
	if err != nil {
		return ciChange{}, fmt.Errorf("--event: %w", err)
	}
	var ev struct {
		PullRequest *struct {
			Base struct {
				Ref string `json:"ref"`
				SHA string `json:"sha"`
			} `json:"base"`
		} `json:"pull_request"`
		MergeGroup *struct {
			BaseRef string `json:"base_ref"`
			BaseSHA string `json:"base_sha"`
		} `json:"merge_group"`
	}
	if err := json.Unmarshal(b, &ev); err != nil {
		return ciChange{}, fmt.Errorf("--event %s: %w", p, err)
	}
	var ref, sha string
	switch {
	case ev.MergeGroup != nil:
		ref, sha = ev.MergeGroup.BaseRef, ev.MergeGroup.BaseSHA
	case ev.PullRequest != nil:
		ref, sha = ev.PullRequest.Base.Ref, ev.PullRequest.Base.SHA
	default:
		return ciChange{}, fmt.Errorf("--event %s: no pull_request or merge_group in the payload", p)
	}
	ref = strings.TrimPrefix(ref, "refs/heads/")
	if ref == "" || strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, " \t\n:\\") || strings.Contains(ref, "..") || !hexSHA.MatchString(sha) {
		return ciChange{}, fmt.Errorf("--event %s: base ref %q / sha %q are not a branch and a commit", p, ref, sha)
	}
	return ciChange{base: "origin/" + ref, from: sha}, nil
}

// rollbackDiff reports whether HEAD changes nothing but the way back since
// merge-base(c.from, HEAD), and why not when it is not. Conservative: every
// changed file is an existing policy YAML file, no document is added or
// removed, and each changed document differs only in
//
//   - Rollout status set to paused or aborted;
//   - Experiment status set to paused;
//   - Ring release set to a release that ring pointed at before on c.base
//     (a previously published release, from the ring file's history).
//
// Anything else (halos.yaml, governance, a new release, comments-only edits to
// non-YAML files) is a forward change and is frozen.
func rollbackDiff(ctx context.Context, top string, c ciChange) (bool, string, error) {
	git := func(args ...string) ([]byte, error) { return promote.Run(ctx, top, "git", args...) }
	mb, err := git("merge-base", c.from, "HEAD")
	if err != nil {
		return false, "", fmt.Errorf("freeze check: merge-base %s HEAD (fetch the base: actions/checkout fetch-depth: 0): %w", c.from, err)
	}
	from := strings.TrimSpace(string(mb))
	out, err := git("diff", "--name-status", "-z", "--no-renames", from, "HEAD", "--")
	if err != nil {
		return false, "", fmt.Errorf("freeze check: diff: %w", err)
	}
	f := strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00")
	if len(f) < 2 {
		return false, "no change", nil
	}
	for i := 0; i+1 < len(f); i += 2 {
		st, file := f[i], f[i+1]
		if st != "M" {
			return false, fmt.Sprintf("%s is %s (only modified policy files can be a rollback)", file, st), nil
		}
		if !strings.HasSuffix(file, ".yaml") && !strings.HasSuffix(file, ".yml") {
			return false, file + " is not a policy YAML file", nil
		}
		old, err := git("show", from+":"+file)
		if err != nil {
			return false, "", fmt.Errorf("freeze check: %w", err)
		}
		nw, err := git("show", "HEAD:"+file)
		if err != nil {
			return false, "", fmt.Errorf("freeze check: %w", err)
		}
		history := func(ring string) ([]string, error) { return ringHistory(ctx, top, c.base, file, ring) }
		if ok, why, err := rollbackFile(old, nw, history); err != nil || !ok {
			return false, file + ": " + why, err
		}
	}
	return true, "", nil
}

// rollbackFile is rollbackDiff for one file's old and new bytes.
func rollbackFile(old, nw []byte, history func(ring string) ([]string, error)) (bool, string, error) {
	od, err := yamlDocs(old)
	if err != nil {
		return false, "old version: " + err.Error(), nil
	}
	nd, err := yamlDocs(nw)
	if err != nil {
		return false, err.Error(), nil
	}
	if len(od) != len(nd) {
		return false, "documents added or removed", nil
	}
	for k, n := range nd {
		o, ok := od[k]
		if !ok {
			return false, "document " + k + " added", nil
		}
		kind, name, _ := strings.Cut(k, "/")
		var allowed []string // fields that may change, each checked below
		switch policy.Kind(kind) {
		case policy.KindRollout:
			allowed = []string{"status"}
			if s := n["status"]; s != o["status"] && s != policy.RolloutPaused && s != policy.RolloutAborted {
				return false, fmt.Sprintf("rollout %s status %v is not paused or aborted", name, s), nil
			}
		case policy.KindExperiment:
			allowed = []string{"status"}
			if s := n["status"]; s != o["status"] && s != "paused" {
				return false, fmt.Sprintf("experiment %s status %v is not paused", name, s), nil
			}
		case policy.KindRing:
			allowed = []string{"release"}
			if r := n["release"]; r != o["release"] {
				rel, _ := r.(string)
				prev, err := history(name)
				if err != nil {
					return false, "", err
				}
				if rel == "" || !slices.Contains(prev, rel) {
					return false, fmt.Sprintf("ring %s release %v was never published to it on the base branch", name, r), nil
				}
			}
		}
		for _, f := range allowed {
			delete(o, f)
			delete(n, f)
		}
		if !reflect.DeepEqual(o, n) {
			return false, "document " + k + " changes more than a rollback may", nil
		}
	}
	return true, "", nil
}

// yamlDocs is each YAML document of b by kind/name (both "" for a document
// without them, such as halos.yaml).
func yamlDocs(b []byte) (map[string]map[string]any, error) {
	docs := map[string]map[string]any{}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var m map[string]any
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return nil, fmt.Errorf("not YAML mappings: %w", err)
		}
		if m == nil {
			continue
		}
		kind, _ := m["kind"].(string)
		name, _ := m["name"].(string)
		k := kind + "/" + name
		if _, dup := docs[k]; dup {
			return nil, errors.New("duplicate document " + k)
		}
		docs[k] = m
	}
}

// maxRingHistory bounds the commits of a ring file read for its past releases.
const maxRingHistory = 500

// ringHistory is every release ring pointed at in file on base.
func ringHistory(ctx context.Context, top, base, file, ring string) ([]string, error) {
	out, err := promote.Run(ctx, top, "git", "log", "--format=%H", fmt.Sprintf("--max-count=%d", maxRingHistory), base, "--", file)
	if err != nil {
		return nil, fmt.Errorf("freeze check: history of %s on %s: %w", file, base, err)
	}
	var rels []string
	for _, c := range strings.Fields(string(out)) {
		b, err := promote.Run(ctx, top, "git", "show", c+":"+file)
		if err != nil {
			continue // the file did not exist under this name then
		}
		docs, err := yamlDocs(b)
		if err != nil {
			continue
		}
		if r, ok := docs[string(policy.KindRing)+"/"+ring]["release"].(string); ok && r != "" && !slices.Contains(rels, r) {
			rels = append(rels, r)
		}
	}
	return rels, nil
}
