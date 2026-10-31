package policytest

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// maxShown caps the failure details and warnings the text summary prints per
// check; JSON and JUnit carry them all.
const maxShown = 5

// Painter colours text output; nil leaves it plain.
type Painter struct{ Green, Red, Yellow, Bold func(string) string }

func (p Painter) paint(f func(string) string, s string) string {
	if f == nil {
		return s
	}
	return f(s)
}

// Text writes the human summary: one PASS/FAIL/SKIP line per check, failure
// reasons under it, a totals line and next_steps.
func (r *Report) Text(w io.Writer, p Painter) {
	label := r.Dir
	if r.Org != "" {
		label = r.Org + " (" + r.Dir + ")"
	}
	fmt.Fprintf(w, "%s %s\n\n", p.paint(p.Bold, "halo test"), label)
	for _, suite := range suiteOrder {
		for _, res := range r.Results {
			if res.Suite != suite {
				continue
			}
			var tag string
			switch res.Status {
			case Pass:
				tag = p.paint(p.Green, "PASS")
			case Fail:
				tag = p.paint(p.Red, "FAIL")
			default:
				tag = p.paint(p.Yellow, "SKIP")
			}
			fmt.Fprintf(w, "%s  %-10s %s", tag, res.Suite, res.Name)
			if res.Message != "" {
				fmt.Fprintf(w, "  %s", res.Message)
			}
			fmt.Fprintln(w)
			if res.Status == Fail {
				shown(w, res.Details, "      ")
			}
			// A check that carries many warnings (adapters warn about every
			// unsupported setting) says how many in its message; few are listed.
			if len(res.Warnings) > 0 && len(res.Warnings) <= maxShown && res.Status == Pass {
				for _, wn := range res.Warnings {
					fmt.Fprintf(w, "      %s %s\n", p.paint(p.Yellow, "warning:"), wn)
				}
			}
		}
	}
	fmt.Fprintf(w, "\n%d passed, %d failed, %d skipped, %d warnings in %dms", r.Passed, r.Failed, r.Skipped, r.Warnings, r.ElapsedMS)
	if r.Warnings > 0 && !r.Strict {
		fmt.Fprint(w, " (--strict fails on warnings; -o json lists them)")
	}
	fmt.Fprintln(w)
	if len(r.NextSteps) > 0 {
		fmt.Fprintln(w, "\nnext steps:")
		for _, n := range r.NextSteps {
			fmt.Fprintln(w, " -", n)
		}
	}
}

func shown(w io.Writer, lines []string, indent string) {
	for i, l := range lines {
		if i == maxShown {
			fmt.Fprintf(w, "%s... %d more (-o json lists all)\n", indent, len(lines)-maxShown)
			return
		}
		fmt.Fprintf(w, "%s%s\n", indent, strings.ReplaceAll(strings.TrimRight(l, "\n"), "\n", "\n"+indent))
	}
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func secs(ms int64) string { return fmt.Sprintf("%.3f", float64(ms)/1000) }

// JUnit writes the report as JUnit XML: one testsuite per check suite, one
// testcase per check. Warnings go to the case's system-out.
func (r *Report) JUnit(w io.Writer) error {
	root := junitSuites{Name: "halo test", Time: secs(r.ElapsedMS)}
	for _, suite := range suiteOrder {
		js := junitSuite{Name: suite}
		var ms int64
		for _, res := range r.Results {
			if res.Suite != suite {
				continue
			}
			c := junitCase{Name: res.Name, ClassName: "halo.test." + suite, Time: secs(res.ElapsedMS), SystemOut: strings.Join(res.Warnings, "\n")}
			js.Tests++
			ms += res.ElapsedMS
			switch res.Status {
			case Fail:
				js.Failures++
				c.Failure = &junitFailure{Message: res.Message, Type: suite, Body: strings.Join(res.Details, "\n")}
			case Skip:
				js.Skipped++
				c.Skipped = &junitSkipped{Message: res.Message}
			}
			js.Cases = append(js.Cases, c)
		}
		if js.Tests == 0 {
			continue
		}
		js.Time = secs(ms)
		root.Tests += js.Tests
		root.Failures += js.Failures
		root.Skipped += js.Skipped
		root.Suites = append(root.Suites, js)
	}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(root); err != nil {
		return fmt.Errorf("policytest: encode junit: %w", err)
	}
	_, err := io.WriteString(w, "\n")
	return err
}
