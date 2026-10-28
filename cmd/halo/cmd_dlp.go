package main

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

func (a *app) cmdDLP() *cobra.Command {
	c := &cobra.Command{Use: "dlp", Short: "Gateway data-loss prevention and prompt-injection defense (ADR-0033)"}
	c.AddCommand(a.cmdDLPTest())
	return c
}

// dlpTestReport is `halo dlp test --output json`.
type dlpTestReport struct {
	File            string               `json:"file"`
	Protocol        string               `json:"protocol"`
	As              string               `json:"as"` // request | tool-result
	Ring            string               `json:"ring,omitempty"`
	Units           []string             `json:"units,omitempty"`
	SecretAction    string               `json:"secretAction"`
	InjectionAction string               `json:"injectionAction"`
	Verdict         string               `json:"verdict"` // pass | redact | block
	Findings        []gateway.DLPFinding `json:"findings"`
	Truncated       bool                 `json:"truncated,omitempty"`
	Redacted        string               `json:"redacted,omitempty"`
}

func (a *app) cmdDLPTest() *cobra.Command {
	var ring, unit, proto, as, secrets, injection string
	var showRedacted bool
	c := &cobra.Command{
		Use:         "test <file>",
		Annotations: policyDirAnno,
		Short:       "Dry-run the gateway's secret and prompt-injection scan on a file, locally",
		Long: "Scans <file> the way halo-proxy and halo-kong scan a model call, without sending anything. A JSON model-call body " +
			"(Anthropic messages, OpenAI Responses input, Gemini contents) is scanned as a request; any other file is scanned as a " +
			"tool result, so the prompt-injection signals apply too. With --policy-dir the policy's gateway.dlp, its rules for " +
			"--ring and --unit, and its org patterns apply; without it every built-in detector runs in monitor mode. " +
			"Findings show the detector, an 8-hex SHA-256 prefix and the JSON path, never the secret. " +
			"Exit 0 when nothing is found, 2 when something is.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch {
			case secrets != "" && !slices.Contains([]string{policy.DLPOff, policy.DLPMonitor, policy.DLPRedact, policy.DLPBlock}, secrets):
				return fmt.Errorf("--secrets must be off, monitor, redact or block, got %q", secrets)
			case injection != "" && !slices.Contains([]string{policy.DLPOff, policy.DLPMonitor, policy.DLPBlock}, injection):
				return fmt.Errorf("--injection must be off, monitor or block, got %q", injection)
			case as != "" && as != "request" && as != "tool-result":
				return fmt.Errorf("--as must be request or tool-result, got %q", as)
			}
			b, err := os.ReadFile(args[0]) //nolint:gosec // the file to scan is the point
			if err != nil {
				return fmt.Errorf("read %s: %w", args[0], err)
			}
			d := &policy.DLP{}
			rep := dlpTestReport{File: args[0], Ring: ring}
			if f := cmd.Flags().Lookup("policy-dir"); f != nil && (f.Changed || cmd.Flags().Lookup("dir").Changed) {
				dir, err := policyDir(cmd, nil)
				if err != nil {
					return err
				}
				org, err := a.load(dir)
				if err != nil {
					return err
				}
				if org.Gateway == nil || org.Gateway.DLP == nil {
					return fmt.Errorf("%s has no gateway.dlp", dir)
				}
				d = org.Gateway.DLP
				if unit != "" {
					chain, err := org.UnitChain(unit)
					if err != nil {
						return err
					}
					for i := len(chain) - 1; i >= 0; i-- {
						rep.Units = append(rep.Units, chain[i].Name)
					}
				}
			} else if unit != "" {
				rep.Units = []string{unit}
			}
			if secrets != "" || injection != "" { // explicit actions win over the policy's for this run
				cp := *d
				cp.Rules = nil
				cp.Secrets.Action, cp.Injection.Action = firstSet(secrets, d.Secrets.Action), firstSet(injection, d.Injection.Action)
				d = &cp
			}
			body := b
			rep.As, rep.Protocol = "request", proto
			if detected := dlpProtocol(b); proto == "" && detected != "" {
				rep.Protocol = detected
			}
			if as == "tool-result" || (as == "" && dlpProtocol(b) == "") {
				body, rep.As, rep.Protocol = dlpToolResult(string(b)), "tool-result", gateway.ProtoAnthropic
			}
			if rep.Protocol == "" {
				rep.Protocol = gateway.ProtoAnthropic
			}
			res := gateway.ScanRequest(d, rep.Protocol, ring, rep.Units, body)
			rep.SecretAction, rep.InjectionAction = d.Actions(ring, rep.Units)
			rep.Verdict = "pass"
			if res != nil {
				rep.Findings, rep.Truncated = res.Findings, res.Truncated
				switch {
				case res.Blocked != "":
					rep.Verdict = "block"
				case res.Redacted != nil:
					rep.Verdict = "redact"
					if showRedacted {
						rep.Redacted = string(res.Redacted)
					}
				}
			}
			if rep.Findings == nil {
				rep.Findings = []gateway.DLPFinding{}
			}
			if err := a.emit(rep, func() { a.printDLPTest(rep, res) }); err != nil {
				return err
			}
			if len(rep.Findings) > 0 {
				return &exitErr{code: exitValidation}
			}
			return nil
		},
	}
	c.Flags().StringVar(&ring, "ring", "", "ring the caller is routed to (selects gateway.dlp.rules)")
	c.Flags().StringVar(&unit, "unit", "", "org unit the caller belongs to (selects gateway.dlp.rules; its ancestors match too)")
	c.Flags().StringVar(&proto, "protocol", "", "wire protocol of a request body: anthropic-messages | openai-responses | gemini | bedrock-invoke (default: from the body)")
	c.Flags().StringVar(&as, "as", "", "request | tool-result (default: request for a JSON model-call body, else tool-result)")
	c.Flags().StringVar(&secrets, "secrets", "", "override the secret action for this run: off | monitor | redact | block")
	c.Flags().StringVar(&injection, "injection", "", "override the injection action for this run: off | monitor | block")
	c.Flags().BoolVar(&showRedacted, "show-redacted", false, "print the redacted body (redact action only)")
	return c
}

// dlpProtocol guesses the wire protocol of a model-call body; "" when b is
// not one.
func dlpProtocol(b []byte) string {
	var v map[string]json.RawMessage
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	switch {
	case v["messages"] != nil:
		return gateway.ProtoAnthropic
	case v["input"] != nil:
		return gateway.ProtoResponses
	case v["contents"] != nil:
		return gateway.ProtoGemini
	}
	return ""
}

// dlpToolResult wraps text as the tool_result of an Anthropic request.
func dlpToolResult(text string) []byte {
	b, _ := json.Marshal(map[string]any{"model": "dlp-test", "messages": []any{ // a map of strings: cannot fail
		map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": "file", "content": text}}},
	}})
	return b
}

func (a *app) printDLPTest(rep dlpTestReport, res *gateway.DLPReport) {
	fmt.Fprintf(a.out, "%s scanned as %s (%s); secrets: %s, injection: %s\n", rep.File, rep.As, rep.Protocol, rep.SecretAction, rep.InjectionAction)
	if len(rep.Findings) == 0 {
		fmt.Fprintln(a.out, a.green("no findings: the gateway would pass it unchanged"))
		return
	}
	tw := tabwriter.NewWriter(a.out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tDETECTOR\tHASH\tLOCATION\tSCORE\tSIGNALS")
	for _, f := range rep.Findings {
		score := ""
		if f.Score > 0 {
			score = fmt.Sprint(f.Score)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", f.Kind, f.Detector, f.Hash, f.Location, score, strings.Join(f.Signals, ","))
	}
	_ = tw.Flush()
	switch rep.Verdict {
	case "block":
		r := res.Reject(rep.Protocol)
		fmt.Fprintf(a.out, "%s: HTTP %d %s\n", a.red("would block"), r.Status, r.Message)
	case "redact":
		fmt.Fprintln(a.out, a.yellow("would redact")+": each secret becomes [REDACTED:<detector>:<hash8>] (--show-redacted prints the body)")
		if rep.Redacted != "" {
			fmt.Fprintln(a.out, rep.Redacted)
		}
	default:
		fmt.Fprintln(a.out, a.yellow("would pass")+" (monitor): counted and audited")
	}
	if rep.Truncated {
		fmt.Fprintln(a.out, "note: the scan stopped at gateway.dlp.maxScanBytes or its time budget; the rest was not scanned")
	}
}
