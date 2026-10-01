package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/rollout"
)

func TestRolloutsAPI(t *testing.T) {
	data := t.TempDir()
	st := rollout.NewState("opus-5-5-upgrade")
	st.Record(rollout.EventEnter, 2, "canary-5", "", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	st.Last = &rollout.Decision{Action: rollout.Hold, Step: 2, Next: -1, Reasons: []string{"bake: baking"}}
	if err := st.Save(filepath.Join(data, "rollouts")); err != nil {
		t.Fatal(err)
	}
	newSrv := func(admin bool) *Server {
		s, err := New(Config{PolicyDir: "../../examples/acme-corp", Token: tok, DataDir: data, DevUser: "u@test", DevAdmin: admin,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	h := newSrv(true).Handler()

	w := do(h, "GET", "/api/v1/rollouts", "", "")
	var list []RolloutView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list) != 3 {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	w = do(h, "GET", "/api/v1/rollouts/opus-5-5-upgrade", "", "")
	var one RolloutView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &one) != nil {
		t.Fatalf("get: %d %s", w.Code, w.Body)
	}
	if one.State == nil || one.State.StepName != "canary-5" || one.State.Last.Action != rollout.Hold || len(one.Timeline.Steps) != 6 || !one.Timeline.Steps[2].Live {
		t.Fatalf("view: %+v", one)
	}
	w = do(h, "GET", "/api/v1/rollouts/claude-code-2.1.300", "", "")
	var draft RolloutView
	if err := json.Unmarshal(w.Body.Bytes(), &draft); err != nil || draft.State != nil || draft.StateError != "" {
		t.Fatalf("no state expected: %s", w.Body)
	}
	if w := do(h, "GET", "/api/v1/rollouts/nope", "", ""); w.Code != 404 {
		t.Fatalf("unknown: %d", w.Code)
	}
	if w := do(newSrv(false).Handler(), "GET", "/api/v1/rollouts", "", ""); w.Code != 403 {
		t.Fatalf("developer: %d", w.Code)
	}
}
