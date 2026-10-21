package server

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/storage"
)

// verdicts is LoadVerdicts(VerdictsPath), or with a shared Backend the
// controller's per-experiment verdict documents, which the leader writes and
// every replica serves (ADR-0021).
func (s *Server) verdicts() (map[string]Verdict, error) {
	if s.cfg.Backend == nil {
		return LoadVerdicts(s.cfg.VerdictsPath)
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	out := map[string]Verdict{}
	rows, err := s.cfg.Backend.Docs(ctx, controller.VerdictDocKind)
	if err != nil {
		return out, err
	}
	for _, b := range rows {
		var v Verdict
		if json.Unmarshal(b, &v) == nil && v.Experiment != "" {
			out[v.Experiment] = v
		}
	}
	return out, nil
}

// Verdict is the console's view of an experiment analysis (a local view model
// mirroring promote.Report, plus an optional primary-effect CI for the forest plot).
// Keys are camelCase; encoding/json also matches promote.Report's untagged field names.
type Verdict struct {
	Experiment  string             `json:"experiment"`
	Verdict     string             `json:"verdict"` // promote | rollback | continue | expired
	Reason      string             `json:"reason"`
	Control     string             `json:"control"`
	Treatment   string             `json:"treatment"`
	NControl    int                `json:"nControl"`
	NTreatment  int                `json:"nTreatment"`
	PValue      float64            `json:"pValue"`
	Effect      float64            `json:"effect"`
	EffectLower *float64           `json:"effectLower,omitempty"`
	EffectUpper *float64           `json:"effectUpper,omitempty"`
	Guardrails  []GuardrailVerdict `json:"guardrails"`
	EvaluatedAt *time.Time         `json:"evaluatedAt,omitempty"`
}

type GuardrailVerdict struct {
	Metric string `json:"metric"`
	Result struct {
		Status        string  `json:"status"` // pass | fail | inconclusive
		Regression    float64 `json:"regression"`
		Lower         float64 `json:"lower"`
		Upper         float64 `json:"upper"`
		MaxRegression float64 `json:"maxRegression"`
	} `json:"result"`
}

// LoadVerdicts reads a JSON array of Verdict, keyed by experiment name.
// A missing path or file is not an error (no analysis yet).
func LoadVerdicts(path string) (map[string]Verdict, error) {
	out := map[string]Verdict{}
	if path == "" {
		return out, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	var vs []Verdict
	if err := json.Unmarshal(b, &vs); err != nil {
		return out, err
	}
	for _, v := range vs {
		out[v.Experiment] = v
	}
	return out, nil
}
