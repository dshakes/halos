package eval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Variant is one arm of a suite: a harness at a version on a model, with an
// optional rendered managed-settings file mounted into the environment.
type Variant struct {
	Name    string `yaml:"name" json:"name"`
	Harness string `yaml:"harness" json:"harness"` // claude | codex | gemini
	Version string `yaml:"version" json:"version"`
	Model   string `yaml:"model" json:"model"` // gateway model alias
	// Settings is a path (relative to the suite file) to the rendered managed
	// settings for this variant, e.g. the output of `halo render`.
	Settings string `yaml:"settings,omitempty" json:"settings,omitempty"`
	// Dir is the suite dir Settings must live in; set by LoadSuite.
	Dir string `yaml:"-" json:"-"`
}

// Suite lists tasks and the variants to compare.
type Suite struct {
	Name string `yaml:"name" json:"name"`
	// Tasks are task directory names under <suite dir>/../tasks.
	Tasks []string `yaml:"tasks" json:"tasks"`
	// Control names the baseline variant; defaults to the first.
	Control  string    `yaml:"control,omitempty" json:"control"`
	Repeats  int       `yaml:"repeats,omitempty" json:"repeats"`
	Variants []Variant `yaml:"variants" json:"variants"`

	// Dir is the directory of the suite file; set by LoadSuite.
	Dir string `yaml:"-" json:"-"`
}

var knownHarness = map[string]bool{"claude": true, "codex": true, "gemini": true}

// Validate checks the suite and applies defaults.
func (s *Suite) Validate() error {
	if s.Name == "" || len(s.Tasks) == 0 || len(s.Variants) == 0 {
		return fmt.Errorf("suite: name, tasks and variants are required")
	}
	if s.Repeats == 0 {
		s.Repeats = 1
	}
	if s.Repeats < 0 {
		return fmt.Errorf("suite %s: repeats must be >= 1", s.Name)
	}
	seen := map[string]bool{}
	for _, v := range s.Variants {
		switch {
		case v.Name == "" || seen[v.Name]:
			return fmt.Errorf("suite %s: variant names must be non-empty and unique (%q)", s.Name, v.Name)
		case !knownHarness[v.Harness]:
			return fmt.Errorf("suite %s: variant %s: unknown harness %q", s.Name, v.Name, v.Harness)
		}
		seen[v.Name] = true
	}
	if s.Control == "" {
		s.Control = s.Variants[0].Name
	}
	if !seen[s.Control] {
		return fmt.Errorf("suite %s: control %q is not a variant", s.Name, s.Control)
	}
	return nil
}

// LoadSuite reads a suite YAML file.
func LoadSuite(path string) (*Suite, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load suite: %w", err)
	}
	var s Suite
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.Dir = filepath.Dir(path)
	for i := range s.Variants {
		v := &s.Variants[i]
		v.Dir = s.Dir
		if v.Settings == "" {
			continue
		}
		p, err := resolveWithin(s.Dir, v.Settings)
		if err != nil {
			return nil, fmt.Errorf("%s: variant %s: settings: %w", path, v.Name, err)
		}
		v.Settings = p
	}
	return &s, nil
}

// LoadTasks loads the suite's tasks from tasksRoot (default <suite dir>/../tasks).
func (s *Suite) LoadTasks(tasksRoot string) ([]*Task, error) {
	if tasksRoot == "" {
		tasksRoot = filepath.Join(s.Dir, "..", "tasks")
	}
	out := make([]*Task, 0, len(s.Tasks))
	for _, name := range s.Tasks {
		t, err := LoadTask(filepath.Join(tasksRoot, name))
		if err != nil {
			return nil, fmt.Errorf("suite %s: %w", s.Name, err)
		}
		out = append(out, t)
	}
	return out, nil
}
