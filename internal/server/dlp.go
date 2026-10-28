package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

const maxDLPEventBytes = 1 << 20

var (
	dlpHashRe  = regexp.MustCompile(`^[0-9a-f]{8}$`)
	dlpEnumRe  = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	dlpActions = map[string]bool{"monitor": true, "redact": true, "block": true}
)

// dlpBatches remembers recent batch ids so a retried batch is appended once
// (per halo-server replica; across replicas delivery is at least once).
type dlpBatches struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func (b *dlpBatches) first(id string, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil || len(b.seen) > 10_000 {
		b.seen = map[string]time.Time{}
	}
	for k, t := range b.seen {
		if now.Sub(t) > time.Hour {
			delete(b.seen, k)
		}
	}
	if _, ok := b.seen[id]; ok {
		return false
	}
	b.seen[id] = now
	return true
}

func validDLPEvent(e gateway.DLPEvent) error {
	short := func(name, v string, n int) error {
		if len(v) > n || strings.ContainsAny(v, "\x00\n\r") {
			return fmt.Errorf("%s longer than %d or holds control characters", name, n)
		}
		return nil
	}
	switch {
	case e.Kind != gateway.DLPSecret && e.Kind != gateway.DLPInjection:
		return errors.New("kind must be secret or injection")
	case !dlpEnumRe.MatchString(e.Detector):
		return errors.New("detector must match " + dlpEnumRe.String())
	case e.Hash != "" && !dlpHashRe.MatchString(e.Hash):
		return errors.New("hash must be 8 lowercase hex characters") // never a secret
	case !dlpActions[e.Action]:
		return errors.New("action must be monitor, redact or block")
	case e.Direction != gateway.DLPRequest && e.Direction != gateway.DLPResponse:
		return errors.New("direction must be request or response")
	case e.Score < 0 || e.Score > 100 || len(e.Signals) > 16:
		return errors.New("score or signals out of range")
	}
	for _, s := range e.Signals {
		if !dlpEnumRe.MatchString(s) {
			return errors.New("signals must match " + dlpEnumRe.String())
		}
	}
	for _, f := range []struct {
		name, v string
		n       int
	}{{"gateway", e.Gateway, 64}, {"subject", e.Subject, 256}, {"chain", e.Chain, 1024}, {"ring", e.Ring, 128}, {"unit", e.Unit, 128},
		{"protocol", e.Protocol, 64}, {"harness", e.Harness, 64}, {"location", e.Location, 256}} {
		if err := short(f.name, f.v, f.n); err != nil {
			return err
		}
	}
	return nil
}

// postGatewayDLPEvents: POST /api/v1/gateway/dlp/events (gateway token,
// ADR-0033). Each event becomes one audit entry (action dlp.secret or
// dlp.injection, actor gateway:<name>, target the verified subject), so the
// SIEM export (ADR-0016) carries it. A failed append answers 503 and the
// gateway resends the batch; a batch id seen in the last hour is acknowledged
// without appending again.
//
// Which gateway sent the batch comes from the token, never the body: a
// per-gateway token (GatewayDLPTokens) attributes it to that gateway and a
// body gateway name that differs is refused; the DLP capability or shared
// token attributes it to gateway:unverified, with the body's name kept only
// as details.claimedGateway.
func (s *Server) postGatewayDLPEvents(w http.ResponseWriter, r *http.Request) {
	if !s.gatewayEnabled(capDLP) && len(s.dlpGateways) == 0 {
		apiErr(w, http.StatusNotFound, "dlp audit not configured")
		return
	}
	verified, ok := s.dlpGatewayAuth(w, r)
	if !ok {
		return
	}
	var in gateway.DLPBatch
	if err := decodeBody(w, r, maxDLPEventBytes, &in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			apiErr(w, http.StatusRequestEntityTooLarge, "dlp batch too large")
			return
		}
		apiErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	switch {
	case in.Batch == "" || len(in.Batch) > 64:
		apiErr(w, http.StatusUnprocessableEntity, "batch id required (<=64 chars)")
		return
	case len(in.Events) > gateway.MaxDLPEvents:
		apiErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("more than %d events", gateway.MaxDLPEvents))
		return
	}
	for i, e := range in.Events {
		if err := validDLPEvent(e); err != nil {
			apiErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("events[%d]: %v", i, err))
			return
		}
		if verified != "" && e.Gateway != "" && e.Gateway != verified {
			apiErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("events[%d]: gateway %q is not the gateway this token belongs to", i, e.Gateway))
			return
		}
	}
	if !s.dlpBatches.first(in.Batch, s.cfg.Now()) {
		writeJSON(w, http.StatusOK, map[string]any{"events": len(in.Events), "duplicate": true})
		return
	}
	for i, e := range in.Events {
		target := e.Subject
		if target == "" {
			target = "anonymous"
		}
		d := map[string]string{"batch": in.Batch, "at": e.At.UTC().Format(time.RFC3339Nano), "kind": e.Kind, "detector": e.Detector,
			"action": e.Action, "direction": e.Direction, "protocol": e.Protocol, "location": e.Location}
		for k, v := range map[string]string{"hash": e.Hash, "ring": e.Ring, "unit": e.Unit, "harness": e.Harness, "chain": e.Chain, "signals": strings.Join(e.Signals, ",")} {
			if v != "" {
				d[k] = v
			}
		}
		if e.Score > 0 {
			d["score"] = strconv.Itoa(e.Score)
		}
		if e.ToolData {
			d["toolData"] = "true"
		}
		gw := verified
		if gw == "" {
			gw = "unverified"
			if e.Gateway != "" {
				d["claimedGateway"] = e.Gateway
			}
		}
		if err := s.AuditStrict(r.Context(), "gateway:"+gw, "dlp."+e.Kind, target, d); err != nil {
			s.dlpBatches.forget(in.Batch) // not all appended: the resend must append (the rest twice; receivers dedupe on details.batch)
			apiErr(w, http.StatusServiceUnavailable, fmt.Sprintf("audit log unavailable after %d of %d events", i, len(in.Events)))
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": len(in.Events), "duplicate": false})
}

// namedSum is the sha256 of the token one named gateway authenticates with.
type namedSum struct {
	name string
	sum  [32]byte
}

// dlpGatewayAuth authenticates a DLP batch: the name of the gateway whose
// own token (GatewayDLPTokens) it carries, or "" for the DLP capability (or
// shared) token. Failures are gatewayAuth's (401/429, counted per IP).
func (s *Server) dlpGatewayAuth(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sum := sha256.Sum256([]byte(tok))
	name := ""
	for _, g := range s.dlpGateways { // every entry compared: no early exit
		if subtle.ConstantTimeCompare(sum[:], g.sum[:]) == 1 {
			name = g.name
		}
	}
	if ok && name != "" {
		return name, true
	}
	return "", s.gatewayAuth(w, r, capDLP)
}

func (b *dlpBatches) forget(id string) {
	b.mu.Lock()
	delete(b.seen, id)
	b.mu.Unlock()
}
