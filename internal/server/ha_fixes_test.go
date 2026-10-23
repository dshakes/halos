package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/policy"
)

// Regression tests for the HA review fixes (ADR-0021 "Amended"). Each runs
// against the in-process fake and, with HALO_TEST_PG_DSN, Postgres.

func withSCIM(c *Config) {
	c.SCIMTokenSHA256, c.SCIMAuthoritative, c.GatewayToken = []string{sha256Hex(scimTok)}, true, gwTok
}

// H1: a SCIM mutation whose cluster lock is held elsewhere is refused with
// 503, never applied unlocked.
func TestSCIMLockHeldIs503(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a := replicaEnv(t, b, withSCIM)
		a.s.scim.mu.wait = 200 * time.Millisecond
		if ok, err := b.TryLock(context.Background(), "lock", "scim", "another-replica", time.Minute); !ok || err != nil {
			t.Fatal(ok, err)
		}
		w := a.scim("POST", "/scim/v2/Users", `{"userName":"x@acme.example","active":true}`)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("mutation under another replica's lock: %d %s, want 503", w.Code, w.Body)
		}
		if _, _, known := a.s.scim.store.Lookup("x@acme.example"); known {
			t.Fatal("user written without the lock")
		}
		_ = b.Unlock(context.Background(), "lock", "scim", "another-replica")
		if w := a.scim("POST", "/scim/v2/Users", `{"userName":"x@acme.example","active":true}`); w.Code != http.StatusCreated {
			t.Fatalf("after release: %d %s", w.Code, w.Body)
		}
	})
}

// H1: a holder's release never frees a lock someone else now holds.
func TestClusterMutexOwnerRelease(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		m := &clusterMutex{kv: b, name: "t"}
		unlock, err := m.Lock()
		if err != nil {
			t.Fatal(err)
		}
		// The lock is stolen (as after expiry): our release must leave it alone.
		_ = b.Unlock(context.Background(), "lock", "t", m.owner)
		if ok, _ := b.TryLock(context.Background(), "lock", "t", "thief", time.Minute); !ok {
			t.Fatal("setup")
		}
		unlock()
		if ok, _ := b.TryLock(context.Background(), "lock", "t", "third", time.Minute); ok {
			t.Fatal("a stale holder's release freed the new holder's lock")
		}
	})
}

// H1: two replicas provisioning one userName at the same time (their
// uniqueness checks racing) end with exactly one user: the shared claim decides.
func TestSCIMUserNameClaim(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, withSCIM), replicaEnv(t, b, withSCIM)
		now := time.Now().UTC()
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, e := range []*env{a, c} {
			wg.Go(func() {
				errs[i] = e.s.scim.store.PutUser(SCIMUser{ID: fmt.Sprint("id-", i), UserName: "Dup@Acme.example", Active: true, Created: now, Modified: now})
			})
		}
		wg.Wait()
		taken := 0
		for _, err := range errs {
			switch {
			case err == nil:
			case errors.Is(err, errSCIMUserNameTaken):
				taken++
			default:
				t.Fatal(err)
			}
		}
		if taken != 1 {
			t.Fatalf("both replicas provisioned one userName: %v", errs)
		}
		// Renaming frees the old name; deleting frees the current one.
		winner := "id-0"
		if errs[0] != nil {
			winner = "id-1"
		}
		if err := a.s.scim.store.PutUser(SCIMUser{ID: winner, UserName: "renamed@acme.example", Active: true, Created: now, Modified: now}); err != nil {
			t.Fatal(err)
		}
		if err := c.s.scim.store.PutUser(SCIMUser{ID: "id-9", UserName: "dup@acme.example", Active: true, Created: now, Modified: now}); err != nil {
			t.Fatalf("name not released by the rename: %v", err)
		}
		if err := c.s.scim.store.DeleteUser("id-9"); err != nil {
			t.Fatal(err)
		}
		if err := a.s.scim.store.PutUser(SCIMUser{ID: "id-10", UserName: "dup@acme.example", Active: true, Created: now, Modified: now}); err != nil {
			t.Fatalf("name not released by the delete: %v", err)
		}
	})
}

// M4: a session minted on a replica whose clock runs behind the revoking one
// (by less than the pad) is dead; a fresh login after the revocation is not.
func TestRevocationSkewPad(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, nil), replicaEnv(t, b, nil)
		u := Principal{ID: "carol@acme.example"}
		if w := a.as(admin, "POST", "/api/v1/users/"+u.ID+"/revoke-sessions", ""); w.Code != 204 {
			t.Fatalf("revoke: %d", w.Code)
		}
		// Replica c's clock is 30s ahead of a's: its "just before the revocation" is a's "after".
		skewed := time.Now().Add(30 * time.Second)
		if code := c.sessionAt(u, skewed, "GET", "/api/v1/me").Code; code != 401 {
			t.Fatalf("session minted under 30s of clock skew survived the revocation: %d", code)
		}
		iat, ok := c.s.revoked.issueAt(u.ID, time.Now())
		if !ok {
			t.Fatal("issueAt")
		}
		if code := c.sessionAt(u, time.Unix(0, iat), "GET", "/api/v1/me").Code; code != 200 {
			t.Fatalf("fresh login right after the revocation: %d", code)
		}
	})
}

// M5/L3: a deprovisioning voids tokens issued up to the void (now + skew);
// a token issued after it enrolls normally (the void is an epoch, not a ban).
func TestEnrollVoidWindow(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a := replicaEnv(t, b, nil)
		if err := a.s.enroll.dropUser(dev.ID, a.s.cfg.Now()); err != nil {
			t.Fatal(err)
		}
		inside := decode[Launch](t, a.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		if w := do(a.h, "POST", "/api/v1/enroll", "", `{"token":"`+inside+`"}`); w.Code != 401 {
			t.Fatalf("token issued inside the void window enrolled: %d", w.Code)
		}
		// A second, older deprovisioning (another replica, clock behind) cannot move the void back.
		if err := a.s.enroll.dropUser(dev.ID, a.s.cfg.Now().Add(-time.Hour)); err != nil {
			t.Fatal(err)
		}
		inside2 := decode[Launch](t, a.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		if w := do(a.h, "POST", "/api/v1/enroll", "", `{"token":"`+inside2+`"}`); w.Code != 401 {
			t.Fatalf("an older drop moved the void backwards: %d", w.Code)
		}
		*a.now = a.now.Add(2 * enrollDropSkew)
		after := decode[Launch](t, a.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		w := do(a.h, "POST", "/api/v1/enroll", "", `{"token":"`+after+`"}`)
		var m map[string]any
		if w.Code != 200 || yaml.Unmarshal(w.Body.Bytes(), &m) != nil {
			t.Fatalf("enrollment after the void: %d %s", w.Code, w.Body)
		}
	})
}

// M5: the post-mint re-check itself: a void that lands after consume but
// before the device is checked revokes the just-minted device.
func TestPostMintVoidRevokes(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a := replicaEnv(t, b, nil)
		tok := decode[Launch](t, a.as(dev, "POST", "/api/v1/launch/laptop", "")).Token
		// Intercept between consume and the re-check: void inside mint, via the
		// device store's persist hook point (a concurrent deprovision).
		a.s.devices.afterMint = func() {
			if err := a.s.enroll.dropUser(dev.ID, a.s.cfg.Now()); err != nil {
				t.Error(err)
			}
		}
		if w := do(a.h, "POST", "/api/v1/enroll", "", `{"token":"`+tok+`"}`); w.Code != 401 {
			t.Fatalf("enrollment that raced a deprovisioning: %d %s", w.Code, w.Body)
		}
		for _, d := range a.s.devices.list() {
			if !d.Revoked {
				t.Fatalf("a device minted during the deprovisioning is live: %+v", d)
			}
		}
	})
}

// L1: the jti row outlives the token's exp by exchangeIatSkew.
func TestJTIRowOutlivesExp(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		a, c := replicaEnv(t, b, nil), replicaEnv(t, b, nil)
		key := "jti\x00iss\x00just-expired"
		exp := time.Now().Add(-time.Second) // expired by the issuer's clock, still accepted by a replica 2s behind
		if err := a.s.rememberSubjectToken(key, exp, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := c.s.rememberSubjectToken(key, exp, time.Now()); !errors.Is(err, errReplayed) {
			t.Fatalf("replay just past exp: %v, want errReplayed", err)
		}
	})
}

// L2: the request-decision claim is owner-checked: a decision whose claim
// expired mid-PR and was taken over by another decision does not release the
// new holder's claim when it finishes.
func TestDecisionClaimOwner(t *testing.T) {
	sharedBackends(t, func(t *testing.T, nb func() Backend) {
		b := nb()
		var id string
		steal := hookWriter(func() {
			// The claim expired (a hung PR) and another admin's decision took it.
			_ = b.Delete(context.Background(), "request-claim", id)
			if ok, _ := b.TryLock(context.Background(), "request-claim", id, "other-decision", time.Minute); !ok {
				t.Error("setup: could not take over the claim")
			}
		})
		a := replicaEnv(t, b, func(c *Config) { c.Writer = steal })
		id = decode[Request](t, a.as(dev, "POST", "/api/v1/requests", `{"kind":"mcp-server","item":"jira","justification":"x"}`)).ID
		if w := a.as(admin, "POST", "/api/v1/requests/"+id+"/approve", ""); w.Code != 200 {
			t.Fatalf("approve: %d %s", w.Code, w.Body)
		}
		if ok, _ := b.TryLock(context.Background(), "request-claim", id, "third", time.Minute); ok {
			t.Fatal("the finished decision released the claim another decision now holds")
		}
	})
}

// hookWriter is a PolicyWriter that runs a hook while "opening the PR".
type hookWriter func()

func (h hookWriter) Propose(context.Context, *policy.Org, Request, string) (string, error) {
	h()
	return "https://git.example/pr/9", nil
}

// L8: an unreadable shared head is an error, not seq 0 ("cursor ahead of the log").
func TestHeadSeqErrorNotZero(t *testing.T) {
	b := newMemShared()
	l := &auditLog{shared: failingHead{b}}
	if _, err := l.headSeq(); err == nil {
		t.Fatal("head read error swallowed")
	}
	f := &auditForwarder{name: "s", log: l, batch: 10, cur: auditCursor{Seq: 5, Hash: "h"}}
	_, err := f.next()
	if err == nil || strings.Contains(err.Error(), "ahead of the log") {
		t.Fatalf("forwarder on an unreadable head: %v (must not claim a restored log)", err)
	}
}

type failingHead struct{ *memShared }

func (failingHead) AuditHead(context.Context) (uint64, string, error) {
	return 0, "", errors.New("connection refused")
}

// M6: shared tail reads newest-first and stops (the fake counts rows read).
func TestSharedTailReadsOnlyWhatItNeeds(t *testing.T) {
	b := &countingShared{memShared: newMemShared()}
	e := replicaEnv(t, b, nil)
	for i := range 50 {
		if err := e.s.AuditStrict(context.Background(), "ops", "x", fmt.Sprint(i), nil); err != nil {
			t.Fatal(err)
		}
	}
	snap, _ := e.s.auditLog.snapshot()
	out, err := snap.tail(3, func(AuditEntry) bool { return true })
	if err != nil || len(out) != 3 || out[2].Seq != 50 || out[0].Seq != 48 {
		t.Fatalf("tail %+v %v", out, err)
	}
	if b.read > 3 {
		t.Fatalf("tail of 3 read %d rows", b.read)
	}
}

type countingShared struct {
	*memShared
	read int
}

func (c *countingShared) EachAuditDesc(ctx context.Context, fn func([]byte, AuditEntry) bool) error {
	return c.memShared.EachAuditDesc(ctx, func(raw []byte, e AuditEntry) bool { c.read++; return fn(raw, e) })
}
