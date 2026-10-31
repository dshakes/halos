package server

import (
	"io"
	"log/slog"
	"testing"
)

// BenchmarkPolicyHolderGet is the per-request policy read every ring lookup,
// enrollment and launch does, from many goroutines at once.
func BenchmarkPolicyHolderGet(b *testing.B) {
	p := &policyHolder{dir: "../../examples/acme-corp", log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if org, _, err := p.Get(); org == nil {
		b.Fatalf("policy did not load: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if org, _, _ := p.Get(); org == nil {
				b.Fatal("policy lost")
			}
		}
	})
}
