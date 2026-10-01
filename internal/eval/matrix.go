package eval

import (
	"errors"
	"fmt"
	"sort"
)

// Matrix is one suite run across harness x model x provider. Each harness
// lists the models it can drive (codex does not run a Claude alias), and a
// provider either applies to every model under its own alias or, when it has
// Aliases, only to the models it maps (e.g. bedrock: {sonnet: sonnet-bedrock}).
// Providers are realised as gateway model aliases: the gateway routes each
// alias to its upstream, so the CLI side stays provider-agnostic.
type Matrix struct {
	// Baseline is the control cell name; default the first cell.
	Baseline  string           `yaml:"baseline,omitempty" json:"baseline,omitempty"`
	Harnesses []MatrixHarness  `yaml:"harnesses" json:"harnesses"`
	Providers []MatrixProvider `yaml:"providers,omitempty" json:"providers,omitempty"`
}

// MatrixHarness is one CLI at a pinned version and the models to run it on.
type MatrixHarness struct {
	Harness  string   `yaml:"harness" json:"harness"`
	Version  string   `yaml:"version" json:"version"`
	Models   []string `yaml:"models" json:"models"`
	Settings string   `yaml:"settings,omitempty" json:"settings,omitempty"`
}

// MatrixProvider names an upstream. Aliases maps model -> gateway alias for
// that provider; empty means the model alias itself.
type MatrixProvider struct {
	Name    string            `yaml:"name" json:"name"`
	Aliases map[string]string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
}

func (m *Matrix) validate() error {
	if m == nil {
		return nil
	}
	if len(m.Harnesses) == 0 {
		return errors.New("harnesses are required")
	}
	for _, h := range m.Harnesses {
		if !knownHarness[h.Harness] {
			return fmt.Errorf("unknown harness %q", h.Harness)
		}
		if len(h.Models) == 0 {
			return fmt.Errorf("harness %s: models are required", h.Harness)
		}
	}
	for _, p := range m.Providers {
		if p.Name == "" {
			return errors.New("provider name is required")
		}
	}
	return nil
}

// Cells expands the matrix into variants named
// <harness>@<version>/<model>[/<provider>], in declaration order.
func (m *Matrix) Cells(suiteDir string) []Variant {
	providers := m.Providers
	if len(providers) == 0 {
		providers = []MatrixProvider{{}}
	}
	var out []Variant
	for _, h := range m.Harnesses {
		for _, model := range h.Models {
			for _, p := range providers {
				alias := model
				if len(p.Aliases) > 0 {
					a, ok := p.Aliases[model]
					if !ok {
						continue
					}
					alias = a
				}
				name := h.Harness + "@" + h.Version + "/" + model
				if p.Name != "" {
					name += "/" + p.Name
				}
				out = append(out, Variant{Name: name, Harness: h.Harness, Version: h.Version, Model: alias,
					Provider: p.Name, Settings: h.Settings, Dir: suiteDir})
			}
		}
	}
	return out
}

// WithMatrix returns a copy of s whose variants are the matrix cells and whose
// control is the matrix baseline.
func (s *Suite) WithMatrix() (*Suite, error) {
	if s.Matrix == nil {
		return nil, fmt.Errorf("suite %s: no matrix defined", s.Name)
	}
	cells := s.Matrix.Cells(s.Dir)
	if len(cells) == 0 {
		return nil, fmt.Errorf("suite %s: matrix expands to no cells", s.Name)
	}
	names := make([]string, 0, len(cells))
	for _, c := range cells {
		names = append(names, c.Name)
	}
	cp := *s
	cp.Variants, cp.Control = cells, s.Matrix.Baseline
	if cp.Control == "" {
		cp.Control = cells[0].Name
	}
	if err := cp.Validate(); err != nil {
		sort.Strings(names)
		return nil, fmt.Errorf("%w (cells: %v)", err, names)
	}
	return &cp, nil
}
