package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/controller"
	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/policy"
)

// KillExperiment trips the kill switch as actor (the in-process controller)
// and audit-logs it. changed is false when it was already killed. The argument
// order is controller.Killer's (experiment, then actor): main wires it as a
// controller.KillFunc, where swapped strings would still compile.
func (s *Server) KillExperiment(ctx context.Context, name, actor, reason string) (bool, error) {
	changed, err := s.kills.Kill(ctx, name, actor, reason)
	if err == nil && changed {
		// The kill stays applied (fail safe) but the gap is surfaced to the caller.
		if aerr := s.AuditStrict(ctx, actor, "experiment.kill", name, map[string]string{"reason": reason}); aerr != nil {
			return changed, fmt.Errorf("kill of %q applied but audit append failed: %w", name, aerr)
		}
	}
	return changed, err
}

// postKill (admin): POST /api/v1/experiments/{name}/kill|unkill {"reason":"..."}
// (reason required to kill). 501 without KillKey. Takes effect on gateways at their next poll; no PR, no merge.
func (s *Server) postKill(kill bool) authedHandler { return s.killHandler(kill, "experiment") }

// toggleKillPrefix marks a feature-toggle name in the kill store (ValidName
// forbids ':', so it cannot collide with an experiment). writeKillList splits
// the store back into KillList.Experiments and KillList.Toggles.
const toggleKillPrefix = "toggle:"

// postToggleKill (admin): POST /api/v1/toggles/{name}/kill|unkill {"reason":"..."}.
// Same auth, reason rule, audit trail and signed list as the experiment kill.
func (s *Server) postToggleKill(kill bool) authedHandler { return s.killHandler(kill, "toggle") }

// killHandler serves the kill/unkill of an experiment or a toggle (kind).
func (s *Server) killHandler(kill bool, kind string) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		// Without a signing key no kill list is served: a kill would enforce nothing.
		if s.cfg.KillKey == nil {
			apiErr(w, http.StatusNotImplemented, "kill switch not configured (--killswitch-key-file)")
			return
		}
		var in struct {
			Reason string `json:"reason"`
		}
		if err := decodeBody(w, r, 2048, &in); err != nil && !errors.Is(err, io.EOF) {
			apiErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		in.Reason = strings.TrimSpace(in.Reason)
		if (kill && in.Reason == "") || len(in.Reason) > 500 {
			apiErr(w, http.StatusUnprocessableEntity, "reason is required for a kill (<=500 chars)")
			return
		}
		name := r.PathValue("name")
		// ValidName forbids ':', so an experiment endpoint can never reach a
		// "toggle:<name>" store key (and vice versa), kill or unkill.
		if !policy.ValidName(name) {
			apiErr(w, http.StatusBadRequest, "invalid "+kind+" name")
			return
		}
		org, err := s.reqPolicy(r) // the snapshot the scope check used
		if org == nil {
			s.policyUnavailable(w, err)
			return
		}
		// Unkill is allowed for names no longer in policy, so stale kills can be cleared.
		known := slices.ContainsFunc(org.Experiments, func(e *policy.Experiment) bool { return e.Name == name })
		key := name
		if kind == "toggle" {
			known = slices.ContainsFunc(org.Toggles, func(t *policy.Toggle) bool { return t.Name == name })
			key = toggleKillPrefix + name
		}
		if kill && !known {
			apiErr(w, http.StatusNotFound, kind+" not found")
			return
		}
		set, action := s.kills.Unkill, kind+".unkill"
		if kill {
			set, action = s.kills.Kill, kind+".kill"
		}
		changed, err := set(r.Context(), key, p.ID, in.Reason)
		if err != nil {
			s.cfg.Log.Error("killswitch update failed", "experiment", name, "kill", kill, "err", err)
			apiErr(w, http.StatusInternalServerError, "store failed")
			return
		}
		if changed {
			if err := s.AuditStrict(r.Context(), p.ID, action, name, map[string]string{"reason": in.Reason}); err != nil {
				if !kill { // an unrecorded unkill must not stay in force: re-kill (fail safe)
					if _, rerr := s.kills.Kill(r.Context(), key, p.ID, "audit failure: unkill reverted"); rerr != nil {
						s.cfg.Log.Error("revert unkill after audit failure", "experiment", name, "err", rerr)
					}
				}
				apiErr(w, http.StatusInternalServerError, errAuditFailed)
				return
			}
			s.cfg.Log.Warn("killswitch changed", "experiment", name, "killed", kill, "by", p.ID)
		}
		out := map[string]any{kind: name, "killed": kill, "changed": changed}
		if kind == "experiment" && kill {
			if h := s.cloudKillHint(org, name); h != nil {
				out["cloudAgents"] = h // cancelling them is a separate, explicit call
			}
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// getKills (admin): active kills with who/when/why.
func (s *Server) getKills(w http.ResponseWriter, r *http.Request, p Principal) {
	recs, version, err := s.kills.Killed()
	if err != nil {
		s.cfg.Log.Error("read killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "killswitch unreadable")
		return
	}
	if f := newReadFilter(p, permRead); !f.all {
		// Scoped readers (ADR-0037) see kills of the experiments and toggles in
		// their scope; a kill of a name no longer in policy has no scope.
		org, oerr := s.reqPolicy(r)
		recs = slices.DeleteFunc(slices.Clone(recs), func(k controller.KillRecord) bool {
			if oerr != nil {
				return true
			}
			if n, ok := strings.CutPrefix(k.Experiment, toggleKillPrefix); ok {
				return !f.ok(toggleResource(org, n))
			}
			return !f.ok(experimentResource(org, k.Experiment))
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": version, "killed": recs})
}

// getGatewayKillswitch: the signed kill list for halo-proxy / halo-kong.
func (s *Server) getGatewayKillswitch(w http.ResponseWriter, r *http.Request) {
	if !s.gatewayEnabled(capKillswitch) || s.cfg.KillKey == nil {
		apiErr(w, http.StatusNotFound, "killswitch not configured")
		return
	}
	if !s.gatewayAuth(w, r, capKillswitch) {
		return
	}
	s.writeKillList(r.Context(), w)
}

// gatewayCap is one capability a gateway bearer token grants on halo-server.
type gatewayCap int

const (
	capKillswitch gatewayCap = iota // GET /api/v1/gateway/killswitch
	capPosture                      // GET /api/v1/gateway/posture
	capBudget                       // /api/v1/gateway/budget/* (usage writes)
	capDirectory                    // GET /api/v1/gateway/directory (SCIM reads)
	capDLP                          // POST /api/v1/gateway/dlp/events (audit appends)
)

// gatewayToken is the only token accepted for c: its dedicated token when
// set, else the shared GatewayToken. "" = the capability is off.
func (c Config) gatewayToken(cp gatewayCap) string {
	if t := [...]string{capKillswitch: c.GatewayKillswitchToken, capPosture: c.GatewayPostureToken,
		capBudget: c.GatewayBudgetToken, capDirectory: c.GatewayDirectoryToken, capDLP: c.GatewayDLPToken}[cp]; t != "" {
		return t
	}
	return c.GatewayToken
}

// gatewaySums hashes the token of every enabled capability.
func gatewaySums(c Config) map[gatewayCap][32]byte {
	out := map[gatewayCap][32]byte{}
	for _, cp := range []gatewayCap{capKillswitch, capPosture, capBudget, capDirectory, capDLP} {
		if t := c.gatewayToken(cp); t != "" {
			out[cp] = sha256.Sum256([]byte(t))
		}
	}
	return out
}

func (s *Server) gatewayEnabled(cp gatewayCap) bool {
	_, ok := s.gwSums[cp]
	return ok
}

// gatewayAuth checks the bearer token for capability cp, writing the 401/429
// itself on failure. Failures count against the gateway class's own per-IP
// budget (gwFails), and a valid token is accepted even from a blocked IP: a
// gateway sharing an egress IP with someone sending garbage is never locked
// out of its directory, posture, budget or kill list. The cost is that a
// blocked guesser still learns when a guess is right; halo-server refuses
// to start with a gateway token under 32 characters or 128 bits of
// estimated entropy (cmd/halo-server checkGatewayToken), so guessing is
// infeasible.
func (s *Server) gatewayAuth(w http.ResponseWriter, r *http.Request, cp gatewayCap) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	sum := sha256.Sum256([]byte(tok)) // hash first: constant-time regardless of length
	want, enabled := s.gwSums[cp]
	if ok && enabled && subtle.ConstantTimeCompare(sum[:], want[:]) == 1 {
		return true
	}
	ip := s.clientIP(r)
	if s.gwFails.blocked(ip) {
		apiErr(w, http.StatusTooManyRequests, "too many failed attempts")
		return false
	}
	s.gwFails.fail(ip)
	apiErr(w, http.StatusUnauthorized, "gateway token required")
	return false
}

// getFleetKillswitch: the same signed kill list for enrolled halod devices
// (device-token auth), so a killed client-axis experiment reverts devices to
// the ring release without waiting for pause + republish.
func (s *Server) getFleetKillswitch(w http.ResponseWriter, r *http.Request) {
	if s.cfg.KillKey == nil {
		apiErr(w, http.StatusNotFound, "killswitch not configured")
		return
	}
	if _, ok := s.deviceAuth(w, r); !ok {
		return
	}
	s.writeKillList(r.Context(), w)
}

// writeKillList signs and writes the current kill list.
func (s *Server) writeKillList(ctx context.Context, w http.ResponseWriter) {
	recs, version, err := s.kills.Killed()
	if err != nil {
		s.cfg.Log.Error("read killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "killswitch unreadable")
		return
	}
	l := gateway.KillList{Version: version, Experiments: []string{}, IssuedAt: s.cfg.Now().UTC()}
	for _, rec := range recs {
		if t, ok := strings.CutPrefix(rec.Experiment, toggleKillPrefix); ok {
			l.Toggles = append(l.Toggles, t)
			continue
		}
		l.Experiments = append(l.Experiments, rec.Experiment)
	}
	env, err := s.killSig.sign(ctx, s.cfg.KillKey, l, s.cfg.Log)
	if err != nil {
		s.cfg.Log.Error("sign killswitch", "err", err)
		apiErr(w, http.StatusInternalServerError, "sign failed")
		return
	}
	writeJSON(w, http.StatusOK, env)
}

const (
	// killSigTTL is how long a remotely signed (KMS, external signer) kill
	// list is served again unchanged. Every gateway and device polls every few
	// seconds; one KMS Sign per poll would hit KMS request quotas and make the
	// kill switch depend on KMS latency. It is far below the pollers' max age
	// (gateway.DefaultKillMaxAge), and a kill or unkill changes the list,
	// which is signed at once.
	killSigTTL = 30 * time.Second
	// killSigStale bounds how long an unchanged list may keep being served
	// from the cache while the remote signer fails (a KMS outage): well under
	// gateway.DefaultKillMaxAge, so pollers never see an envelope near expiry.
	// A changed list is never served from the cache.
	killSigStale = 3 * time.Minute
	// killSignTimeout bounds one remote signature. The call runs detached
	// from the poll that started it, so a poller giving up does not abandon
	// it: the next poll gets its result.
	killSignTimeout = 30 * time.Second
)

// killSigCache holds the last remotely signed envelope. In-process keys are
// not cached: they sign every response, as before.
//
// At most one remote sign runs at a time. A poll that wants a list other
// than the one being signed takes the single pending slot (replacing an
// older pending list, whose waiters are told it was superseded); the pending
// list is signed when the running sign ends. So a slow or hanging signer
// costs one goroutine and one in-flight call however many distinct lists
// polls ask for.
type killSigCache struct {
	mu       sync.Mutex
	list     gateway.KillList // as signed (IssuedAt included)
	env      gateway.KillEnvelope
	inflight *killSignCall // the remote sign running, if any
	pending  *killSignCall // the newest other list, signed after inflight
	signer   bundle.Signer // for the pending call
	log      *slog.Logger
	failures atomic.Uint64 // remote sign failures (halo_server_killswitch_sign_failures_total)
	staleHit atomic.Uint64 // polls answered from the cache because the remote sign failed
}

// errKillSuperseded ends the wait of polls whose pending list was replaced
// by a newer one before it was signed.
var errKillSuperseded = errors.New("superseded by a newer kill list before it was signed")

// killSignCall is one remote signature shared by every poll that wants the
// same list.
type killSignCall struct {
	list gateway.KillList // as being signed
	ctx  context.Context  // detached from the poll that created it
	done chan struct{}
	env  gateway.KillEnvelope
	err  error
}

// remoteSigner is implemented by internal/signer's KMS and exec backends.
type remoteSigner interface{ Remote() bool }

func sameKillContent(a, b gateway.KillList) bool {
	return a.Version == b.Version && slices.Equal(a.Experiments, b.Experiments) && slices.Equal(a.Toggles, b.Toggles)
}

// sign returns the envelope for l. Remote keys: a fresh cached envelope of
// the same content is reused; otherwise l joins the running sign (same
// content), the pending one (same content), or becomes the pending list. The
// sign runs detached from the poll, with its own timeout, and the mutex is
// never held across it. When the sign fails or this poll stops waiting, an
// unchanged list is answered from the cache while it is younger than
// killSigStale; a changed list is an error, never a stale list presented as
// current.
func (c *killSigCache) sign(ctx context.Context, k bundle.Signer, l gateway.KillList, log *slog.Logger) (gateway.KillEnvelope, error) {
	if rs, ok := k.(remoteSigner); !ok || !rs.Remote() {
		return gateway.SignKillList(ctx, k, l)
	}
	c.mu.Lock()
	cached := c.env.Signature != nil && sameKillContent(c.list, l)
	if cached && l.IssuedAt.Sub(c.list.IssuedAt) < killSigTTL && !l.IssuedAt.Before(c.list.IssuedAt) {
		env := c.env
		c.mu.Unlock()
		return env, nil
	}
	c.signer, c.log = k, log
	var call *killSignCall
	switch {
	case c.inflight != nil && sameKillContent(c.inflight.list, l):
		call = c.inflight
	case c.pending != nil && sameKillContent(c.pending.list, l):
		call = c.pending
	default:
		call = &killSignCall{list: l, ctx: context.WithoutCancel(ctx), done: make(chan struct{})}
		if c.inflight == nil {
			c.start(call)
		} else {
			if old := c.pending; old != nil { // a newer list replaces it: it will never be signed
				old.err = errKillSuperseded
				close(old.done)
			}
			c.pending = call
		}
	}
	c.mu.Unlock()

	var err error
	select {
	case <-call.done: // the writer of env/err happens before close(done)
		if call.err == nil {
			return call.env, nil
		}
		err = call.err
	case <-ctx.Done():
		err = ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.env.Signature != nil && sameKillContent(c.list, l) && l.IssuedAt.Sub(c.list.IssuedAt) < killSigStale {
		c.staleHit.Add(1)
		log.Warn("killswitch: remote signer unavailable; serving the cached signed list (content unchanged)",
			"err", err, "signedAt", c.list.IssuedAt, "maxStale", killSigStale)
		return c.env, nil
	}
	return gateway.KillEnvelope{}, fmt.Errorf("killswitch: remote sign: %w", err)
}

// start makes call the running sign; callers hold c.mu. issuedAt is bumped
// past the cached list's: pollers need a strictly newer list for any change.
func (c *killSigCache) start(call *killSignCall) {
	if !call.list.IssuedAt.After(c.list.IssuedAt) {
		call.list.IssuedAt = c.list.IssuedAt.Add(time.Nanosecond)
	}
	c.inflight = call
	go c.run(call.ctx, c.signer, call, c.log)
}

// run performs one remote signature detached from the poll that started it,
// records it if it is the newest, and starts the pending list, if any.
func (c *killSigCache) run(ctx context.Context, k bundle.Signer, call *killSignCall, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(ctx, killSignTimeout)
	defer cancel()
	c.mu.Lock()
	list := call.list
	c.mu.Unlock()
	env, err := gateway.SignKillList(ctx, k, list)
	c.mu.Lock()
	call.env, call.err = env, err
	switch {
	case err != nil:
		c.failures.Add(1)
		log.Error("killswitch: remote sign failed", "err", err)
	case list.IssuedAt.After(c.list.IssuedAt):
		c.list, c.env = list, env
	}
	c.inflight = nil
	if next := c.pending; next != nil {
		c.pending = nil
		c.start(next)
	}
	c.mu.Unlock()
	close(call.done)
}

// killPubPEM is the PKIX PEM of the kill-list verification key ("" if none).
func (s *Server) killPubPEM() string {
	ks, ok := s.cfg.KillKey.(bundle.KeySigner)
	if !ok {
		return ""
	}
	pv, ok := ks.Verifier().(bundle.PublicKeyVerifier)
	if !ok {
		return ""
	}
	b, err := bundle.MarshalPublicKeyPEM(pv)
	if err != nil {
		return ""
	}
	return string(b)
}

// killswitchPub serves the kill-list public key for enrollment (public, like release.pub).
func (s *Server) killswitchPub(w http.ResponseWriter, _ *http.Request) {
	k := s.killPubPEM()
	if k == "" {
		apiErr(w, http.StatusNotFound, "killswitch not configured")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = fmt.Fprint(w, k)
}
