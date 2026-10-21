package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// Request statuses.
const (
	StatusPending   = "pending"
	StatusApproving = "approving" // transient, in-memory only: a PR is being opened
	StatusApproved  = "approved"
	StatusDenied    = "denied"
)

// Request is a developer's ask for access; approval opens a policy-repo PR, never a merge.
type Request struct {
	ID            string     `json:"id"`
	User          string     `json:"user"`
	Kind          string     `json:"kind"` // mcp-server | model | ring-opt-in | harness
	Item          string     `json:"item"`
	Justification string     `json:"justification"`
	Ring          string     `json:"ring,omitempty"` // requester's ring at request time
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"createdAt"`
	DecidedBy     string     `json:"decidedBy,omitempty"`
	DecidedAt     *time.Time `json:"decidedAt,omitempty"`
	PRURL         string     `json:"prURL,omitempty"`
	Note          string     `json:"note,omitempty"`
}

// PolicyWriter turns an approved request into a reviewable change to the policy repo.
// Implementations must never merge. ErrManual means no automatic patch exists for the kind.
type PolicyWriter interface {
	Propose(ctx context.Context, org *policy.Org, req Request, approver string) (prURL string, err error)
}

// proposeTimeout bounds one PolicyWriter.Propose (fetch, commit, push, gh).
const proposeTimeout = 2 * time.Minute

// ErrManual: approval is recorded but a human must make the change.
var ErrManual = errors.New("no automatic policy change for this request kind")

// requestLog: in-memory map + optional JSONL append log (last line per id wins).
// ponytail: no compaction; fine for human-scale request volume.
type requestLog struct {
	mu   sync.Mutex
	byID map[string]*Request
	log  storage.Log
}

func (l *requestLog) close() error { return storage.CloseLog(&l.mu, l.log) }

func openRequestLog(o storage.Opener) (*requestLog, error) {
	l := &requestLog{byID: map[string]*Request{}}
	ctx, cancel := storage.Ctx()
	defer cancel()
	log, err := o.OpenLog(ctx, "requests", func(line []byte) {
		var r Request
		if json.Unmarshal(line, &r) == nil && r.ID != "" { // torn line: skip
			if r.Status == StatusApproving {
				r.Status = StatusPending
			}
			l.byID[r.ID] = &r
		}
	})
	if err != nil {
		return nil, err
	}
	l.log = log
	return l, nil
}

// save persists r (caller holds mu).
func (l *requestLog) save(r *Request) error {
	if l.log == nil || r.Status == StatusApproving {
		return nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return l.log.Append(ctx, r.ID, b)
}

// catchup applies other replicas' request records (caller holds mu).
func (l *requestLog) catchup() error {
	if l.log == nil {
		return nil
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return l.log.Catchup(ctx)
}

func (l *requestLog) list(filter func(*Request) bool) []Request {
	l.mu.Lock()
	defer l.mu.Unlock()
	_ = l.catchup() // display only: serve the last view (the error is counted by the backend)
	out := []Request{}
	for _, r := range l.byID {
		if filter(r) {
			out = append(out, *r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func validateRequest(org *policy.Org, req *Request) error {
	if !slices.Contains(org.SelfService.Requestable, req.Kind) {
		return fmt.Errorf("kind %q is not requestable", req.Kind)
	}
	if n := len(strings.TrimSpace(req.Justification)); n == 0 || n > 1000 {
		return errors.New("justification required (<=1000 chars)")
	}
	ok := false
	switch req.Kind {
	case "mcp-server":
		ok = slices.ContainsFunc(org.SelfService.Catalog, func(m policy.MCPServer) bool { return m.Name == req.Item })
	case "ring-opt-in":
		ok = slices.ContainsFunc(org.Rings, func(r *policy.Ring) bool { return r.Name == req.Item && r.Membership.OptIn })
	case "model":
		ok = org.Gateway != nil && len(org.Gateway.Models[req.Item].Candidates()) > 0
	case "harness":
		ok = slices.Contains(requestableHarnesses(), req.Item)
	}
	if !ok {
		return fmt.Errorf("unknown %s %q", req.Kind, req.Item)
	}
	return nil
}

func (s *Server) postRequest(w http.ResponseWriter, r *http.Request, p Principal) {
	org := s.selfService(w)
	if org == nil {
		return
	}
	var in Request
	if err := decodeBody(w, r, 8192, &in); err != nil {
		apiErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := validateRequest(org, &in); err != nil {
		apiErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	req := &Request{ID: randB64(9), User: p.ID, Kind: in.Kind, Item: in.Item, Justification: strings.TrimSpace(in.Justification), Status: StatusPending, CreatedAt: s.cfg.Now().UTC()}
	if ring := org.ResolveRing(p.subject()); ring != nil {
		req.Ring = ring.Name
	}
	l := s.reqs
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.catchup(); err != nil {
		s.cfg.Log.Error("read requests", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	}
	for _, x := range l.byID {
		if x.User == p.ID && x.Kind == req.Kind && x.Item == req.Item && (x.Status == StatusPending || x.Status == StatusApproving) {
			apiErr(w, http.StatusConflict, "you already have a pending request for this")
			return
		}
	}
	// Across replicas the scan above can race: the database's uniqueness claim decides.
	if ok, err := s.claimPending(l, req); err != nil {
		s.cfg.Log.Error("claim request", "err", err)
		apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
		return
	} else if !ok {
		apiErr(w, http.StatusConflict, "you already have a pending request for this")
		return
	}
	if err := l.save(req); err != nil {
		s.releasePending(req)
		s.cfg.Log.Error("persist request", "err", err)
		apiErr(w, http.StatusInternalServerError, "store failed")
		return
	}
	l.byID[req.ID] = req
	s.cfg.Log.Info("access request", "id", req.ID, "user", p.ID, "kind", req.Kind, "item", req.Item)
	s.Audit(r.Context(), p.ID, "request.create", req.ID, map[string]string{"kind": req.Kind, "item": req.Item})
	writeJSON(w, http.StatusCreated, req)
}

// pendingKey names the (user, kind, item) a pending request is unique on.
func pendingKey(r *Request) string {
	h := sha256.Sum256([]byte(strings.ToLower(r.User) + "\x00" + r.Kind + "\x00" + r.Item))
	return hex.EncodeToString(h[:])
}

// claimPending takes the shared uniqueness claim for req (caller holds l.mu,
// caught up); true without a Backend, where the scan under l.mu is enough.
func (s *Server) claimPending(l *requestLog, req *Request) (bool, error) {
	if s.cfg.Backend == nil {
		return true, nil
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	return s.cfg.Backend.ClaimPending(ctx, pendingKey(req), req.ID, func(id string) (bool, bool) {
		x := l.byID[id]
		return x != nil, x != nil && (x.Status == StatusPending || x.Status == StatusApproving)
	})
}

// releasePending drops req's claim once it is decided (or was never stored).
// A failed release is harmless: the next request for the item finds the
// holder decided and takes the claim over.
func (s *Server) releasePending(req *Request) {
	if s.cfg.Backend == nil {
		return
	}
	ctx, cancel := storage.Ctx()
	defer cancel()
	if err := s.cfg.Backend.ReleasePending(ctx, pendingKey(req), req.ID); err != nil {
		s.cfg.Log.Warn("release request claim", "id", req.ID, "err", err)
	}
}

// listRequests: developers see their own; admins see everyone's.
func (s *Server) listRequests(w http.ResponseWriter, _ *http.Request, p Principal) {
	writeJSON(w, http.StatusOK, s.reqs.list(func(r *Request) bool { return p.can(permApprove) || r.User == p.ID }))
}

func (s *Server) decide(approve bool) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, p Principal) {
		// One decision at a time per request across replicas; the claim
		// outlives a hung PR attempt only until it expires.
		id := r.PathValue("id")
		if ok, err := s.kv.Add(r.Context(), "request-claim", id, []byte(p.ID), s.cfg.Now().Add(proposeTimeout+time.Minute)); err != nil {
			s.cfg.Log.Error("claim request", "id", id, "err", err)
			apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
			return
		} else if !ok {
			apiErr(w, http.StatusConflict, "request is being decided")
			return
		}
		defer func() {
			ctx, cancel := storage.Ctx()
			defer cancel()
			if err := s.kv.Delete(ctx, "request-claim", id); err != nil {
				s.cfg.Log.Warn("release request claim", "id", id, "err", err) // expires on its own
			}
		}()
		l := s.reqs
		l.mu.Lock()
		if err := l.catchup(); err != nil {
			l.mu.Unlock()
			s.cfg.Log.Error("read requests", "err", err)
			apiErr(w, http.StatusServiceUnavailable, "state store unavailable")
			return
		}
		req := l.byID[id]
		switch {
		case req == nil:
			l.mu.Unlock()
			apiErr(w, http.StatusNotFound, "request not found")
			return
		case req.Status != StatusPending:
			l.mu.Unlock()
			apiErr(w, http.StatusConflict, "request is "+req.Status)
			return
		case req.User == p.ID:
			l.mu.Unlock()
			apiErr(w, http.StatusForbidden, "you cannot decide your own request")
			return
		}
		finish := func(status, pr, note string) Request { // caller holds mu
			now := s.cfg.Now().UTC()
			req.Status, req.DecidedBy, req.DecidedAt, req.PRURL, req.Note = status, p.ID, &now, pr, note
			action := "request.deny"
			if approve {
				action = "request.approve"
			}
			s.Audit(r.Context(), p.ID, action, req.ID, map[string]string{"user": req.User, "kind": req.Kind, "item": req.Item, "prUrl": pr})
			if err := l.save(req); err != nil {
				s.cfg.Log.Error("persist decision", "id", req.ID, "err", err)
			} else {
				s.releasePending(req)
			}
			return *req
		}
		if !approve {
			out := finish(StatusDenied, "", "")
			l.mu.Unlock()
			writeJSON(w, http.StatusOK, out)
			return
		}
		req.Status = StatusApproving // blocks double-approval while the PR opens
		snap := *req
		l.mu.Unlock()

		org, _, _ := s.pol.Get()
		var pr string
		var err error
		switch {
		case org == nil:
			err = errors.New("policy not loaded")
		case s.cfg.Writer == nil:
			err = ErrManual
		default:
			// Not r.Context(): a client disconnect must not abort a half-made PR;
			// bounded instead, since git/gh can hang.
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), proposeTimeout)
			pr, err = s.cfg.Writer.Propose(ctx, org, snap, p.ID)
			cancel()
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		switch {
		case err == nil:
			out := finish(StatusApproved, pr, "")
			s.cfg.Log.Info("request approved", "id", req.ID, "by", p.ID, "pr", pr)
			writeJSON(w, http.StatusOK, out)
		case errors.Is(err, ErrManual):
			out := finish(StatusApproved, "", "Approved; no automatic change available, a policy owner must apply it.")
			writeJSON(w, http.StatusOK, out)
		default:
			req.Status = StatusPending // nothing lost: admin can retry
			s.cfg.Log.Error("policy writer failed", "id", req.ID, "err", err)
			apiErr(w, http.StatusBadGateway, "could not open policy PR: "+err.Error())
		}
	}
}
