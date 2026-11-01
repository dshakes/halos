package server

import (
	"sync"

	"golang.org/x/time/rate"
)

// DefaultAPIRate and DefaultAPIBurst are halo-server's per-principal budget on
// console/API routes: generous for the console (a page load fans out to a few
// dozen calls) and for automation, tight enough that one leaked token or
// runaway script cannot monopolise a replica.
const (
	DefaultAPIRate  = 20
	DefaultAPIBurst = 100
)

// apiLimiter is a token bucket per authenticated principal on console/API
// routes. It runs after authentication, so keys are principals the server
// already trusts: nobody can mint fresh budgets. Per replica: N replicas grant
// N budgets (failed auth, the abuse path, is shared across replicas instead).
type apiLimiter struct {
	mu    sync.Mutex
	m     map[string]*rate.Limiter
	rps   rate.Limit
	burst int
}

// maxAPIPrincipals bounds the map. ponytail: a full map is dropped wholesale
// (every budget refills); keys are authenticated principals, so reaching it
// takes that many real identities. Use an LRU if a deployment ever does.
const maxAPIPrincipals = 100_000

// allow spends one request from key's budget. A nil limiter or rate <= 0
// disables limiting.
func (a *apiLimiter) allow(key string) bool {
	if a == nil || a.rps <= 0 {
		return true
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.m == nil || len(a.m) >= maxAPIPrincipals {
		a.m = map[string]*rate.Limiter{}
	}
	l := a.m[key]
	if l == nil {
		l = rate.NewLimiter(a.rps, max(a.burst, 1))
		a.m[key] = l
	}
	return l.Allow()
}

func newAPILimiter(rps float64, burst int) *apiLimiter {
	return &apiLimiter{rps: rate.Limit(rps), burst: burst}
}
