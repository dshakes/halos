// Package copilot is Halos Copilot (ADR-0035): a language model drafts
// policy changes, experiment designs and explanations; Halos' deterministic
// checks (validation, plan, impact preview, the invariant-1 bypass-token scan
// and internal/stats) verify them; a human approves every write. Nothing here
// publishes, pushes, opens a PR, merges or promotes.
package copilot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dshakes/halos/internal/eval"
)

// DefaultModel is the pinned model the copilot asks unless configured.
const DefaultModel = "claude-opus-5-5"

// Budget is the hard per-run ceiling. Zero fields take the defaults.
type Budget struct {
	MaxIterations int     // model calls per run (default 3)
	MaxTokens     int     // input + output tokens per run (default 60000)
	MaxCostUSD    float64 // estimated spend per run (default 2)
	// Prices per million tokens, for the cost estimate (default 5 / 25).
	PriceInPerMTok, PriceOutPerMTok float64
	MaxOutputTokens                 int // per call (default 8192)
}

func (b Budget) withDefaults() Budget {
	if b.MaxIterations <= 0 {
		b.MaxIterations = 3
	}
	if b.MaxTokens <= 0 {
		b.MaxTokens = 60000
	}
	if b.MaxCostUSD <= 0 {
		b.MaxCostUSD = 2
	}
	if b.PriceInPerMTok <= 0 {
		b.PriceInPerMTok = 5
	}
	if b.PriceOutPerMTok <= 0 {
		b.PriceOutPerMTok = 25
	}
	if b.MaxOutputTokens <= 0 {
		b.MaxOutputTokens = 8192
	}
	return b
}

// Spend is what a run used.
type Spend struct {
	Calls        int     `json:"calls"`
	InputTokens  int     `json:"inputTokens"`
	OutputTokens int     `json:"outputTokens"`
	CostUSD      float64 `json:"estCostUSD"`
}

var (
	// ErrBudget stops a run that would cross a ceiling. The result so far
	// is still returned; nothing past the ceiling is spent.
	ErrBudget = errors.New("copilot: run ceiling reached")
	// ErrSchema marks a model reply that failed the Go-side schema: it is
	// never used, only fed back.
	ErrSchema = errors.New("copilot: reply failed schema validation")
)

// Client asks the model. LLM nil means offline: every command then uses
// its deterministic template and never calls out.
type Client struct {
	LLM    *eval.HTTPLLM
	Model  string
	Budget Budget
	Log    io.Writer // one line per call: token counts only (nil = discard)
	Debug  bool      // also log prompts and replies

	spend Spend
}

// Offline reports whether the client never calls a model.
func (c *Client) Offline() bool { return c.LLM == nil }

// Spend is the run's usage so far.
func (c *Client) Spend() Spend { return c.spend }

func (c *Client) logf(format string, args ...any) {
	if c.Log != nil {
		fmt.Fprintf(c.Log, format+"\n", args...)
	}
}

func (c *Client) cost(in, out int) float64 {
	b := c.Budget.withDefaults()
	return float64(in)*b.PriceInPerMTok/1e6 + float64(out)*b.PriceOutPerMTok/1e6
}

// ask sends one prompt and strictly decodes the reply into out, then runs
// check. The ceilings are checked before the call against the worst case
// (prompt bytes / 3 in, the output cap out), so a run never spends past
// them. A reply that fails decoding or check returns ErrSchema.
func (c *Client) ask(ctx context.Context, system, prompt string, out any, check func() error) error {
	if c.LLM == nil {
		return errors.New("copilot: no model configured (offline)")
	}
	b := c.Budget.withDefaults()
	if c.spend.Calls >= b.MaxIterations {
		return fmt.Errorf("%w: %d model calls (--max-iterations)", ErrBudget, b.MaxIterations)
	}
	est := (len(system)+len(prompt))/3 + 1 // conservative: YAML runs ~3-4 bytes per token
	left := b.MaxTokens - c.spend.InputTokens - c.spend.OutputTokens
	maxOut := min(b.MaxOutputTokens, left-est)
	if maxOut < 256 {
		return fmt.Errorf("%w: about %d prompt tokens would cross --max-tokens %d (used %d)", ErrBudget, est, b.MaxTokens, b.MaxTokens-left)
	}
	if worst := c.spend.CostUSD + c.cost(est, maxOut); worst > b.MaxCostUSD {
		return fmt.Errorf("%w: the next call could cost up to $%.4f, past --max-cost-usd %.2f (spent $%.4f)", ErrBudget, worst-c.spend.CostUSD, b.MaxCostUSD, c.spend.CostUSD)
	}
	if c.Debug {
		c.logf("copilot: debug: system prompt:\n%s\ncopilot: debug: prompt:\n%s", system, prompt)
	}
	reply, u, err := c.LLM.CompleteUsage(ctx, eval.LLMRequest{Model: c.Model, System: system, Prompt: prompt, MaxTokens: maxOut})
	c.spend.Calls++
	in, outTok := u.InputTokens, u.OutputTokens
	if in == 0 { // provider reported no usage: count the estimate
		in = est
	}
	if outTok == 0 {
		outTok = len(reply)/4 + 1
	}
	if err != nil {
		outTok = 0 // an HTTP error bills the prompt at most
	}
	c.spend.InputTokens += in
	c.spend.OutputTokens += outTok
	c.spend.CostUSD += c.cost(in, outTok)
	c.logf("copilot: llm call %d/%d model=%s input_tokens=%d output_tokens=%d total_tokens=%d est_cost_usd=%.4f",
		c.spend.Calls, b.MaxIterations, c.Model, in, outTok, c.spend.InputTokens+c.spend.OutputTokens, c.spend.CostUSD)
	if err != nil {
		return fmt.Errorf("copilot: model call: %w", err)
	}
	if c.Debug {
		c.logf("copilot: debug: reply:\n%s", reply)
	}
	if err := decodeStrict(reply, out); err != nil {
		return fmt.Errorf("%w: %v", ErrSchema, err)
	}
	if err := check(); err != nil {
		return fmt.Errorf("%w: %v", ErrSchema, err)
	}
	return nil
}

// decodeStrict parses exactly one JSON object with no unknown fields. One
// surrounding Markdown code fence is tolerated; anything else is not.
func decodeStrict(reply string, out any) error {
	s := strings.TrimSpace(reply)
	if rest, ok := strings.CutPrefix(s, "```"); ok {
		rest = strings.TrimPrefix(rest, "json")
		if body, ok := strings.CutSuffix(strings.TrimSpace(rest), "```"); ok {
			s = strings.TrimSpace(body)
		}
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return err
	}
	if dec.More() || dec.InputOffset() != int64(len(s)) {
		return errors.New("trailing data after the JSON object")
	}
	return nil
}

// fence wraps untrusted parts (policy files, Halos outputs) in the eval
// judge's nonce fence and returns the prompt and the system-prompt notice.
func fence(parts ...eval.Part) (string, string, error) {
	p, notice, err := eval.Fence(parts)
	if err != nil {
		return "", "", fmt.Errorf("copilot: %w", err)
	}
	return p, notice, nil
}
