package roi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/promote"
)

func writeFile(p, s string) error { return os.WriteFile(p, []byte(s), 0o600) }

// fakeClickHouse records inserts and answers the PR and cost SELECTs.
func fakeClickHouse(t *testing.T, costRows string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := r.URL.Query()
		mu.Lock()
		log = append(log, q.Get("query")+"|"+string(body))
		mu.Unlock()
		switch {
		case strings.HasPrefix(q.Get("query"), "INSERT INTO halo_delivery_prs"):
			if q.Get("date_time_input_format") != "best_effort" || q.Get("database") != "halo" {
				http.Error(w, "settings", http.StatusBadRequest)
			}
		case strings.Contains(string(body), "FROM halo_delivery_prs FINAL"):
			if q.Get("param_from") == "" || q.Get("param_to") == "" {
				http.Error(w, "params", http.StatusBadRequest)
				return
			}
			_, _ = io.WriteString(w, `{"source":"github","repo":"a/b","number":7,"author":"alice","subject":"","bot":false,"opened_ms":1788220800000,"merged_ms":1788224400000,"review_rounds":2,"additions":3,"deletions":4,"change_failure":true}`+"\n"+
				`{"source":"github","repo":"a/b","number":8,"author":"bob","subject":"","bot":false,"opened_ms":1788220800000,"merged_ms":0,"review_rounds":0,"additions":0,"deletions":0,"change_failure":false}`+"\n")
		case strings.Contains(string(body), "metric = 'halo.cost.usd'"):
			_, _ = io.WriteString(w, costRows)
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &log
}

func TestClickHouseStore(t *testing.T) {
	srv, log := fakeClickHouse(t, `{"arm":"control","gw":1,"usd":12.5,"units":3}`+"\n"+`{"arm":"next","gw":0,"usd":99,"units":9}`+"\n")
	st := ClickHouseStore{CH: &promote.ClickHouse{URL: srv.URL, Database: "halo"}}
	ctx := context.Background()
	m := t0.Add(1)
	if err := st.Put(ctx, []PR{{Source: "github", Repo: "a/b", Number: 7, Author: "alice", OpenedAt: t0, MergedAt: &m}}); err != nil {
		t.Fatal(err)
	}
	ins := (*log)[0]
	_, row, _ := strings.Cut(ins, "|")
	var got map[string]any
	if err := json.Unmarshal([]byte(row), &got); err != nil {
		t.Fatalf("insert body %q: %v", row, err)
	}
	for _, k := range []string{"source", "repo", "number", "author", "opened_at", "merged_at", "ingested_at"} {
		if _, ok := got[k]; !ok {
			t.Errorf("insert row lacks %s: %v", k, got)
		}
	}
	prs, err := st.PRs(ctx, t0, t1)
	if err != nil {
		t.Fatal(err)
	}
	if len(prs) != 2 || prs[0].MergedAt == nil || prs[0].MergedAt.Sub(prs[0].OpenedAt).Hours() != 1 || !prs[0].ChangeFailure || prs[1].MergedAt != nil {
		t.Fatalf("prs %+v", prs)
	}
	costs, src, err := st.ArmCosts(ctx, "cli-next", nil, t0, t1)
	if err != nil {
		t.Fatal(err)
	}
	// Gateway rows win; the CLI-only arm is not mixed in.
	if src != promote.SourceGateway || len(costs) != 1 || costs["control"].USD != 12.5 {
		t.Fatalf("costs %v source %s", costs, src)
	}
	srv2, _ := fakeClickHouse(t, `{"arm":"ring1","gw":0,"usd":5,"units":2}`+"\n")
	costs, src, err = ClickHouseStore{CH: &promote.ClickHouse{URL: srv2.URL}}.ArmCosts(ctx, "", []string{"ring1", "ring3"}, t0, t1)
	if err != nil || src != promote.SourceCLI || costs["ring1"].USD != 5 {
		t.Fatalf("ring costs %v %s %v", costs, src, err)
	}
	if err := (ClickHouseStore{CH: &promote.ClickHouse{URL: srv.URL + "/bad"}}).Put(ctx, []PR{{}}); err == nil {
		t.Fatal("insert without the database setting must fail on the fake")
	}
}
