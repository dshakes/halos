// Package policytest is the offline tier of testing a policy change
// (`halo test`, MCP `policy_test`): in seconds, with no network or
// credentials, it validates the policy, renders every ring for every harness
// and OS and asserts the security invariants on the output, builds each ring's
// release and checks its manifest, previews who a change reaches, runs
// policy-declared cases (the PolicyTest documents under tests/) and simulates
// every rollout. It reuses internal/policy, internal/release,
// internal/impact and internal/rollout; it implements no rendering, hashing or
// gate logic of its own.
package policytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters
	"github.com/dshakes/halos/internal/policy"
)

// Kind is the document kind of a test file (schemas/policytest.schema.json).
const Kind = "PolicyTest"

// Suite is one PolicyTest document: a named list of cases.
type Suite struct {
	APIVersion  string `yaml:"apiVersion" json:"apiVersion"`
	Kind        string `yaml:"kind" json:"kind"`
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Cases       []Case `yaml:"cases" json:"cases"`
	// File is the path relative to the policy dir; set by LoadSuites.
	File string `yaml:"-" json:"-"`
}

// Case says what an identity must get from the policy.
type Case struct {
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
	Identity    Identity `yaml:"identity" json:"identity"`
	// OS selects the rendered files settings are read from: darwin, linux
	// (default) or windows.
	OS     string `yaml:"os,omitempty" json:"os,omitempty"`
	Expect Expect `yaml:"expect" json:"expect"`
}

// Identity is the subject a case resolves, as the IdP presents it.
type Identity struct {
	User   string   `yaml:"user" json:"user"`
	Groups []string `yaml:"groups,omitempty" json:"groups,omitempty"`
}

// Expect lists the assertions of a case; at least one is required.
type Expect struct {
	// Ring is the ring the identity lands in. A pointer so that "" can assert
	// that no ring matches.
	Ring *string `yaml:"ring,omitempty" json:"ring,omitempty"`
	// Variants maps a running experiment to the variant the identity gets;
	// "" asserts the identity is not enrolled in it.
	Variants map[string]string `yaml:"variants,omitempty" json:"variants,omitempty"`
	// Settings maps a harness to dotted key paths in its rendered config and
	// the value each must have (a null value asserts the key is absent).
	Settings map[string]map[string]any `yaml:"settings,omitempty" json:"settings,omitempty"`
}

// FileError is a test file that does not decode or validate.
type FileError struct {
	File string
	Err  error
}

func (e FileError) Error() string { return e.File + ": " + e.Err.Error() }

// LoadSuites reads every YAML file under dir/tests. A missing directory is no
// tests, not an error. Files that do not decode strictly (unknown fields are
// errors, as everywhere in policy) or fail Check are returned as FileErrors;
// the rest load.
func LoadSuites(dir string) ([]Suite, []FileError, error) {
	root := filepath.Join(dir, policy.TestsDir)
	if st, err := os.Stat(root); errors.Is(err, fs.ErrNotExist) || (err == nil && !st.IsDir()) {
		return nil, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("policytest: %w", err)
	}
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(p) == ".yaml" || filepath.Ext(p) == ".yml") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("policytest: walk %s: %w", root, err)
	}
	sort.Strings(files)
	var suites []Suite
	var bad []FileError
	for _, f := range files {
		rel, rerr := filepath.Rel(dir, f)
		if rerr != nil {
			rel = f
		}
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("policytest: read %s: %w", f, err)
		}
		ss, err := decodeSuites(b)
		if err != nil {
			bad = append(bad, FileError{rel, err})
			continue
		}
		for i := range ss {
			ss[i].File = rel
			if err := ss[i].Check(); err != nil {
				bad = append(bad, FileError{rel, fmt.Errorf("%s: %w", docName(ss[i].Name, i), err)})
				continue
			}
			suites = append(suites, ss[i])
		}
	}
	return suites, bad, nil
}

func docName(name string, i int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("document %d", i+1)
}

// decodeSuites strictly decodes every document of b.
func decodeSuites(b []byte) ([]Suite, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var out []Suite
	for {
		var s Suite
		err := dec.Decode(&s)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("no document")
	}
	return out, nil
}

var validOS = []string{"darwin", "linux", "windows"}

// Check validates a suite's shape; it mirrors schemas/policytest.schema.json
// (a test compares the two) and also knows the registered harnesses.
func (s *Suite) Check() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if s.APIVersion != policy.APIVersion {
		add("apiVersion must be %q, got %q", policy.APIVersion, s.APIVersion)
	}
	if s.Kind != Kind {
		add("kind must be %q, got %q", Kind, s.Kind)
	}
	if s.Name == "" {
		add("name is required")
	}
	if len(s.Cases) == 0 {
		add("cases: at least one case is required")
	}
	seen := map[string]bool{}
	for i, c := range s.Cases {
		at := fmt.Sprintf("cases[%d]", i)
		if c.Name != "" {
			at += " (" + c.Name + ")"
		}
		if c.Name == "" {
			add("%s: name is required", at)
		} else if seen[c.Name] {
			add("%s: duplicate case name", at)
		}
		seen[c.Name] = true
		if c.Identity.User == "" {
			add("%s: identity.user is required", at)
		}
		if c.OS != "" && !slices.Contains(validOS, c.OS) {
			add("%s: os must be one of %s, got %q", at, strings.Join(validOS, ", "), c.OS)
		}
		e := c.Expect
		if e.Ring == nil && len(e.Variants) == 0 && len(e.Settings) == 0 {
			add("%s: expect asserts nothing; set ring, variants or settings", at)
		}
		for h, kv := range e.Settings {
			if _, ok := harness.Get(h); !ok {
				add("%s: expect.settings: unknown harness %q (registered: %s)", at, h, strings.Join(harness.Names(), ", "))
			}
			if len(kv) == 0 {
				add("%s: expect.settings.%s: no key paths", at, h)
			}
			for k, v := range kv {
				if strings.Trim(k, ".") == "" || strings.Contains(k, "..") {
					add("%s: expect.settings.%s: malformed key path %q", at, h, k)
				}
				if _, err := json.Marshal(v); err != nil {
					add("%s: expect.settings.%s.%s: value is not representable as JSON: %v", at, h, k, err)
				}
			}
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
