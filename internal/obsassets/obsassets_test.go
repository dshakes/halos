package obsassets

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const root = "../.." // repository root, from this package's directory

func read(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func rules(t *testing.T) RuleFile {
	t.Helper()
	rf, err := ParseRules(read(t, RulesPath))
	if err != nil {
		t.Fatal(err)
	}
	return rf
}

func TestGrafanaAlertsAreInSync(t *testing.T) {
	want, err := GrafanaAlerts(rules(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := read(t, GrafanaAlertsPath); !bytes.Equal(got, want) {
		t.Fatalf("%s is stale: run `make obs-assets`", GrafanaAlertsPath)
	}
}

func TestChartDashboardsAreCopies(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(root, DashboardsDir))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		n++
		src := read(t, filepath.Join(DashboardsDir, e.Name()))
		if cp := read(t, filepath.Join(ChartDashboardsDir, e.Name())); !bytes.Equal(src, cp) {
			t.Errorf("%s differs from its chart copy: run `make obs-assets`", e.Name())
		}
	}
	if n < 4 {
		t.Fatalf("expected at least the four Prometheus dashboards, found %d", n)
	}
	chart, err := os.ReadDir(filepath.Join(root, ChartDashboardsDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(chart) != n {
		t.Errorf("chart ships %d dashboards, source has %d (a deleted dashboard must be deleted from the chart too)", len(chart), n)
	}
}

func TestEveryAlertIsDocumented(t *testing.T) {
	guide := string(read(t, OperationsGuide))
	for _, name := range rules(t).AlertNames() {
		if !strings.Contains(guide, name) {
			t.Errorf("alert %s is not listed in %s", name, OperationsGuide)
		}
	}
	if !strings.Contains(guide, "prometheus-rules.yaml") {
		t.Errorf("%s must name deploy/helm/halos/files/prometheus-rules.yaml as the source of the alerts", OperationsGuide)
	}
}

// exportedMetrics collects every halo_* name that appears in a non-test Go source file of the binaries.
func exportedMetrics(t *testing.T) map[string]bool {
	t.Helper()
	have := map[string]bool{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			// This package and its command only mention names; they must not count as an exporter.
			if d.IsDir() && (d.Name() == "obsassets" || d.Name() == "testdata") {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			b, err := os.ReadFile(path) //nolint:gosec // walking the repository
			if err != nil {
				return err
			}
			for _, m := range MetricNames(string(b)) {
				have[m] = true
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return have
}

func exported(have map[string]bool, name string) bool {
	if have[name] {
		return true
	}
	for _, suf := range []string{"_bucket", "_sum", "_count"} {
		if base, ok := strings.CutSuffix(name, suf); ok && have[base] {
			return true
		}
	}
	return false
}

func TestRulesAndDashboardsUseExportedMetrics(t *testing.T) {
	have := exportedMetrics(t)
	if len(have) < 40 {
		t.Fatalf("found only %d exported halo_* names; the scan is broken", len(have))
	}
	var sources = map[string]string{}
	for _, r := range rules(t).Groups {
		for _, rule := range r.Rules {
			sources["alert "+rule.Alert] = rule.Expr
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, DashboardsDir))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			sources["dashboard "+e.Name()] = string(read(t, filepath.Join(DashboardsDir, e.Name())))
		}
	}
	for what, text := range sources {
		for _, m := range MetricNames(text) {
			if !exported(have, m) {
				t.Errorf("%s uses %s, which no binary exports", what, m)
			}
		}
	}
}

// ---- chart rendering (needs the helm binary; CI runners and developer machines have it) ----

type obj struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name   string            `yaml:"name"`
		Labels map[string]string `yaml:"labels"`
	} `yaml:"metadata"`
	Spec map[string]any `yaml:"spec"`
}

type container struct {
	Name            string `yaml:"name"`
	Image           string `yaml:"image"`
	SecurityContext struct {
		AllowPrivilegeEscalation *bool `yaml:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem   *bool `yaml:"readOnlyRootFilesystem"`
		RunAsNonRoot             *bool `yaml:"runAsNonRoot"`
		Capabilities             struct {
			Drop []string `yaml:"drop"`
		} `yaml:"capabilities"`
	} `yaml:"securityContext"`
}

type workload struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		Replicas *int `yaml:"replicas"`
		Template struct {
			Spec struct {
				SecurityContext struct {
					RunAsNonRoot   *bool `yaml:"runAsNonRoot"`
					SeccompProfile struct {
						Type string `yaml:"type"`
					} `yaml:"seccompProfile"`
				} `yaml:"securityContext"`
				ImagePullSecrets []struct {
					Name string `yaml:"name"`
				} `yaml:"imagePullSecrets"`
				Affinity       map[string]any `yaml:"affinity"`
				InitContainers []container    `yaml:"initContainers"`
				Containers     []container    `yaml:"containers"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

func helmTemplate(t *testing.T, args ...string) (string, bool) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	cmd := exec.Command("helm", append([]string{"template", "halos", filepath.Join(root, "deploy/helm/halos"), "-n", "halos"}, args...)...) //nolint:gosec // fixed test arguments
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func decodeAll[T any](t *testing.T, manifest string) []T {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(manifest))
	var out []T
	for {
		var v T
		err := dec.Decode(&v)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("decode manifest: %v", err)
		}
		out = append(out, v)
	}
}

func chartValues(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, "deploy/helm/halos/ci/*.yaml"))
	if err != nil || len(files) < 3 {
		t.Fatalf("expected the chart's ci values files, got %v (%v)", files, err)
	}
	return files
}

// Every container of every workload, in the default render and with each CI values file, keeps the hardened security context.
func TestChartContainersAreHardened(t *testing.T) {
	cases := map[string][]string{"default": nil}
	for _, f := range chartValues(t) {
		cases[filepath.Base(f)] = []string{"-f", f}
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			out, ok := helmTemplate(t, args...)
			if !ok {
				t.Fatalf("helm template failed:\n%s", out)
			}
			n := 0
			for _, w := range decodeAll[workload](t, out) {
				if w.Kind != "Deployment" && w.Kind != "Job" {
					continue
				}
				ps := w.Spec.Template.Spec
				if ps.SecurityContext.SeccompProfile.Type != "RuntimeDefault" || ps.SecurityContext.RunAsNonRoot == nil || !*ps.SecurityContext.RunAsNonRoot {
					t.Errorf("%s: pod needs runAsNonRoot and seccomp RuntimeDefault", w.Metadata.Name)
				}
				for _, c := range append(append([]container{}, ps.InitContainers...), ps.Containers...) {
					n++
					sc := c.SecurityContext
					ok := sc.AllowPrivilegeEscalation != nil && !*sc.AllowPrivilegeEscalation &&
						sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem &&
						sc.RunAsNonRoot != nil && *sc.RunAsNonRoot &&
						len(sc.Capabilities.Drop) == 1 && sc.Capabilities.Drop[0] == "ALL"
					if !ok {
						t.Errorf("%s/%s: container security context is not hardened: %+v", w.Metadata.Name, c.Name, sc)
					}
				}
			}
			if n == 0 {
				t.Fatal("no containers found; the render is empty")
			}
		})
	}
}

// monitoring-values.yaml turns on every new toggle: mirrored registry, pull secrets, anti-affinity, HPAs, PDBs, rules, dashboards.
func TestChartMonitoringValues(t *testing.T) {
	out, ok := helmTemplate(t, "-f", filepath.Join(root, "deploy/helm/halos/ci/monitoring-values.yaml"))
	if !ok {
		t.Fatalf("helm template failed:\n%s", out)
	}
	kinds := map[string]int{}
	for _, o := range decodeAll[obj](t, out) {
		kinds[o.Kind]++
	}
	for kind, min := range map[string]int{"PrometheusRule": 1, "HorizontalPodAutoscaler": 4, "PodDisruptionBudget": 4, "ServiceMonitor": 4, "Deployment": 4} {
		if kinds[kind] < min {
			t.Errorf("rendered %d %s, want at least %d", kinds[kind], kind, min)
		}
	}
	dashboards := 0
	for _, o := range decodeAll[obj](t, out) {
		if o.Kind == "ConfigMap" && o.Metadata.Labels["grafana_dashboard"] == "1" {
			dashboards++
		}
	}
	if dashboards != 4 {
		t.Errorf("rendered %d dashboard ConfigMaps, want 4", dashboards)
	}
	for _, w := range decodeAll[workload](t, out) {
		if w.Kind != "Deployment" {
			continue
		}
		ps := w.Spec.Template.Spec
		if w.Spec.Replicas != nil && w.Metadata.Name != "halos-proxy" {
			t.Errorf("%s: replicas must be left to the HPA, got %d", w.Metadata.Name, *w.Spec.Replicas)
		}
		if len(ps.ImagePullSecrets) != 2 || ps.ImagePullSecrets[0].Name != "regcred" || ps.ImagePullSecrets[1].Name != "legacy-regcred" {
			t.Errorf("%s: imagePullSecrets %+v, want global then chart-level", w.Metadata.Name, ps.ImagePullSecrets)
		}
		if _, ok := ps.Affinity["podAntiAffinity"]; !ok {
			t.Errorf("%s: no default podAntiAffinity", w.Metadata.Name)
		}
		for _, c := range append(append([]container{}, ps.InitContainers...), ps.Containers...) {
			if !strings.HasPrefix(c.Image, "registry.corp.example/") {
				t.Errorf("%s/%s: image %s ignores global.imageRegistry", w.Metadata.Name, c.Name, c.Image)
			}
		}
	}
}

// The PrometheusRule needs the CRD: absent from .Capabilities it is not rendered, present it is.
func TestChartPrometheusRuleHonoursCapabilities(t *testing.T) {
	on := []string{"--set", "monitoring.prometheusRule.enabled=true", "--set", "server.metrics.enabled=true"}
	out, ok := helmTemplate(t, on...)
	if !ok {
		t.Fatalf("helm template failed:\n%s", out)
	}
	if strings.Contains(out, "kind: PrometheusRule") {
		t.Error("PrometheusRule rendered although the cluster does not advertise the CRD")
	}
	out, ok = helmTemplate(t, append(on, "--api-versions", "monitoring.coreos.com/v1/PrometheusRule")...)
	if !ok {
		t.Fatalf("helm template failed:\n%s", out)
	}
	for _, want := range []string{"kind: PrometheusRule", "alert: HaloProxyErrorRateHigh", "alert: HaloServerDown", `up{job="halos-server"}`} {
		if !strings.Contains(out, want) {
			t.Errorf("render with the CRD advertised lacks %q", want)
		}
	}
	for _, not := range []string{"HaloNoControllerLeader", "HaloControllerStalled"} {
		if strings.Contains(out, not) {
			t.Errorf("%s rendered without the HA backend / controller", not)
		}
	}
	out, _ = helmTemplate(t)
	if strings.Contains(out, "kind: PrometheusRule") || strings.Contains(out, "grafana_dashboard") {
		t.Error("default values must not render rules or dashboards")
	}
}
