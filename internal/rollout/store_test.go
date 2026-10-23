package rollout

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type memDocs struct {
	m   map[string][]byte
	err error
}

func (d *memDocs) GetDoc(_ context.Context, kind, name string) ([]byte, bool, error) {
	b, ok := d.m[kind+"/"+name]
	return b, ok, d.err
}

func (d *memDocs) PutDoc(_ context.Context, kind, name string, body []byte) error {
	if d.err != nil {
		return d.err
	}
	d.m[kind+"/"+name] = body
	return nil
}

func TestStateStores(t *testing.T) {
	ctx := context.Background()
	t0 := time.Unix(1000, 0).UTC()
	for name, store := range map[string]StateStore{
		"dir": DirStore(t.TempDir()),
		"doc": DocStore{DB: &memDocs{m: map[string][]byte{}}},
	} {
		t.Run(name, func(t *testing.T) {
			if st, err := store.Load(ctx, "r"); err != nil || st.Rollout != "r" || len(st.History) != 0 {
				t.Fatalf("missing state must load as new: %+v %v", st, err)
			}
			st := NewState("r")
			st.Halt("rollback", "cli", "guardrail failed", t0)
			st.Mark("pr:rollback", "https://pr/9", t0)
			if err := store.Save(ctx, &st); err != nil {
				t.Fatal(err)
			}
			got, err := store.Load(ctx, "r")
			if err != nil || got.HaltReason != "guardrail failed" || len(got.History) != len(st.History) {
				t.Fatalf("round trip: %+v %v", got, err)
			}
			if u, ok := got.Did("pr:rollback"); !ok || u != "https://pr/9" {
				t.Fatalf("Done not rebuilt: %v", got.Done)
			}
			if _, err := store.Load(ctx, "../etc"); err == nil {
				t.Fatal("invalid name accepted")
			}
		})
	}
}

func TestDocStoreVerifies(t *testing.T) {
	ctx := context.Background()
	docs := &memDocs{m: map[string][]byte{}}
	store := DocStore{DB: docs}
	st := NewState("r")
	st.Halt("rollback", "cli", "x", time.Unix(1, 0))
	if err := store.Save(ctx, &st); err != nil {
		t.Fatal(err)
	}
	docs.m[DocKind+"/r"] = []byte(strings.ReplaceAll(string(docs.m[DocKind+"/r"]), `"x"`, `"y"`))
	if _, err := store.Load(ctx, "r"); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered document loaded: %v", err)
	}
	docs.m[DocKind+"/r"] = []byte(`{"rollout":"other"}`)
	if _, err := store.Load(ctx, "r"); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("misfiled document loaded: %v", err)
	}
	docs.err = errors.New("connection refused")
	if _, err := store.Load(ctx, "r"); err == nil {
		t.Fatal("store error swallowed on load")
	}
	if err := store.Save(ctx, &st); err == nil {
		t.Fatal("store error swallowed on save")
	}
}
