package controller

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/dshakes/halos/internal/storage"
)

// Side effects outside the controller's own state (kill switch, pull
// request, notification) cannot be fenced by the leader lease the way a
// database write is. So before each one the controller records an intent in
// its state log, which on the HA backend is fenced (ADR-0021): a replica
// that lost the lease fails that write and skips the call, and the intent's
// key travels with the call (a marker in the PR body, the notification's
// event id) so the next leader, finding an intent without a result, can
// recognise the effect if it already happened instead of repeating it.

// intentPrefix marks intent records in the state log and rollout state.
const intentPrefix = "intent:"

// fenced reports whether err is the leader-lease fence refusing a write:
// this replica no longer leads and must not act.
func fenced(err error) bool { return errors.Is(err, storage.ErrFenced) }

func newIntentKey() string {
	var b [12]byte
	_, _ = rand.Read(b[:]) // crypto/rand does not fail on supported platforms
	return hex.EncodeToString(b[:])
}

// intend records that action on exp/verdict is about to happen and returns
// its dedupe key. prior is true when an earlier attempt (this leader's or a
// previous one's) recorded the intent but no result: the effect may already
// exist. A fenced error means do not act; any other error is returned for
// the tick's error count, and the caller still acts (best effort: a missing
// rollback is worse than a duplicate notification).
func (c *Controller) intend(exp, verdict, action string) (key string, prior bool, err error) {
	if d, ok := c.State.Done(exp, verdict, intentPrefix+action); ok {
		return d, true, nil
	}
	key = newIntentKey()
	if err := c.State.Record(exp, verdict, intentPrefix+action, key, c.now()); err != nil {
		return key, false, c.fail(err)
	}
	return key, false, nil
}

// PRFinder is implemented by PR writers that can find a pull request they
// opened by a marker embedded in its body (GitWriter, through a
// promote.PRFinder opener). The controller uses it when an intent shows a
// PR may already have been opened by a deposed leader.
type PRFinder interface {
	FindPR(ctx context.Context, marker string) (url string, found bool, err error)
}

// intentMarker is the PR-body marker carrying an intent key.
func intentMarker(key string) string { return "<!-- halos-intent: " + key + " -->" }
