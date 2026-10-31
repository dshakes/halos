// Command obsassets regenerates the observability files derived from their single sources:
//
//	go run ./internal/tools/obsassets        # write
//	go run ./internal/tools/obsassets -check # exit 1 when a committed file is stale
//
// Run it from the repo root (`make obs-assets`). It writes the Grafana alert provisioning from the chart's Prometheus rules and
// copies the dashboards into the chart's files/dashboards.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dshakes/halos/internal/obsassets"
)

func main() {
	check := flag.Bool("check", false, "fail instead of writing when a derived file is stale")
	flag.Parse()
	if err := run(*check); err != nil {
		fmt.Fprintln(os.Stderr, "obsassets:", err)
		os.Exit(1)
	}
}

func run(check bool) error {
	raw, err := os.ReadFile(obsassets.RulesPath)
	if err != nil {
		return fmt.Errorf("read rules (run from the repo root): %w", err)
	}
	rf, err := obsassets.ParseRules(raw)
	if err != nil {
		return err
	}
	alerts, err := obsassets.GrafanaAlerts(rf)
	if err != nil {
		return err
	}
	want := map[string][]byte{obsassets.GrafanaAlertsPath: alerts}
	entries, err := os.ReadDir(obsassets.DashboardsDir)
	if err != nil {
		return fmt.Errorf("read dashboards: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(obsassets.DashboardsDir, e.Name()))
		if err != nil {
			return fmt.Errorf("read dashboard %s: %w", e.Name(), err)
		}
		want[filepath.Join(obsassets.ChartDashboardsDir, e.Name())] = b
	}
	stale := 0
	for path, b := range want {
		have, err := os.ReadFile(path)
		if err == nil && bytes.Equal(have, b) {
			continue
		}
		if check {
			fmt.Fprintf(os.Stderr, "stale: %s\n", path)
			stale++
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("mkdir for %s: %w", path, err)
		}
		if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // repository files, world-readable by design
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Println("wrote", path)
	}
	if stale > 0 {
		return fmt.Errorf("%d derived file(s) stale: run `make obs-assets`", stale)
	}
	return nil
}
