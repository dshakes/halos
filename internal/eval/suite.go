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
	// Provider labels the upstream the alias routes to (matrix runs); recorded only.
	Provider string `yaml:"provider,omitempty" json:"provider,omitempty"`
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
	// Seed is the base seed for per-trial seeds and bootstrap CIs. No pinned
	// CLI exposes a sampling seed, so it makes the run order and statistics
	// reproducible, not the agent itself.
	Seed uint64 `yaml:"seed,omitempty" json:"seed,omitempty"`
	// K is the k of pass@k and pass^k; default Repeats.
	K int `yaml:"k,omitempty" json:"k,omitempty"`
	// Gate holds the ship/hold/block thresholds.
	Gate Thresholds `yaml:"gate,omitempty" json:"gate"`
	// Judge configures the LLM-as-judge grader used by tasks' judge graders.
	Judge *JudgeConfig `yaml:"judge,omitempty" json:"judge,omitempty"`
	// Matrix, used by `halo eval run --matrix`, replaces Variants with the
	// harness x model x provider cross product.
	Matrix *Matrix `yaml:"matrix,omitempty" json:"matrix,omitempty"`
	// Graders apply to every task in addition to its own (e.g. a judge
	// rubric for the whole suite, so shared tasks stay judge-free).
	Graders []GraderSpec `yaml:"graders,omitempty" json:"graders,omitempty"`

	// Dir is the directory of the suite file; set by LoadSuite.
	Dir string `yaml:"-" json:"-"`
}

var knownHarness = map[string]bool{"claude": true, "codex": true, "gemini": true}

// Validate checks the suite and applies defaults.
func (s *Suite) Validate() error {
	if s.Name == "" || len(s.Tasks) == 0 || (len(s.Variants) == 0 && s.Matrix == nil) {
		return fmt.Errorf("suite: name, tasks and variants (or matrix) are required")
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
	if s.K == 0 {
		s.K = s.Repeats
	}
	if s.K < 1 || s.K > s.Repeats {
		return fmt.Errorf("suite %s: k must be between 1 and repeats (%d)", s.Name, s.Repeats)
	}
	if err := s.Gate.validate(); err != nil {
		return fmt.Errorf("suite %s: gate: %w", s.Name, err)
	}
	if err := s.Judge.validate(); err != nil {
		return fmt.Errorf("suite %s: judge: %w", s.Name, err)
	}
	if err := s.Matrix.validate(); err != nil {
		return fmt.Errorf("suite %s: matrix: %w", s.Name, err)
	}
	if len(s.Variants) == 0 {
		return nil // matrix-only suite
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
	if err := loadGraders(s.Graders, filepath.Dir(s.Dir), filepath.Base(s.Dir)); err != nil {
		return nil, fmt.Errorf("%s: graders: %w", path, err)
	}
	if s.Matrix != nil {
		for i := range s.Matrix.Harnesses {
			h := &s.Matrix.Harnesses[i]
			if h.Settings == "" {
				continue
			}
			p, err := resolveWithin(s.Dir, h.Settings)
			if err != nil {
				return nil, fmt.Errorf("%s: matrix harness %s: settings: %w", path, h.Harness, err)
			}
			h.Settings = p
		}
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
		t.Graders = append(t.Graders, s.Graders...)
		out = append(out, t)
	}
	return out, nil
}
