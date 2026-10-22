package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/storage"
)

// SCIMName is the RFC 7643 §4.1.1 "name" complex attribute (the parts Halos keeps).
type SCIMName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// SCIMEmail is one "emails" value.
type SCIMEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// SCIMUser is a provisioned user. UserName is the halo identity: it must equal
// the OIDC userClaim value (email by default) the console and gateway see.
type SCIMUser struct {
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Name        *SCIMName   `json:"name,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Created     time.Time   `json:"created"`
	Modified    time.Time   `json:"lastModified"`
}

// SCIMGroup is a provisioned group; Members are SCIMUser IDs. Policy refers to
// a group by DisplayName (ring membership, adminGroups, toggle rules).
type SCIMGroup struct {
	ID          string    `json:"id"`
	ExternalID  string    `json:"externalId,omitempty"`
	DisplayName string    `json:"displayName"`
	Members     []string  `json:"members,omitempty"`
	Created     time.Time `json:"created"`
	Modified    time.Time `json:"lastModified"`
}

// SCIMStore persists the SCIM directory. The SCIM handlers serialise every
// mutation, so an implementation only has to make each call atomic. An HA
// backend implements this same interface (ADR-0022).
type SCIMStore interface {
	Users() []SCIMUser   // sorted by userName
	Groups() []SCIMGroup // sorted by displayName
	User(id string) (SCIMUser, bool)
	Group(id string) (SCIMGroup, bool)
	PutUser(SCIMUser) error
	// DeleteUser also removes the user from every group.
	DeleteUser(id string) error
	PutGroup(SCIMGroup) error
	DeleteGroup(id string) error
	// Lookup resolves a login identity (userName, case-insensitive) to the
	// user and the displayNames of the groups they are a member of.
	Lookup(userName string) (u SCIMUser, groups []string, ok bool)
	Close() error
}

// scimRecord is one line of scim.jsonl: a put (User or Group set) or a delete.
type scimRecord struct {
	User     *SCIMUser  `json:"user,omitempty"`
	Group    *SCIMGroup `json:"group,omitempty"`
	DelUser  string     `json:"delUser,omitempty"`
	DelGroup string     `json:"delGroup,omitempty"`
}

// scimLogStore is an in-memory directory over an append-only JSONL log (replayed in order on open).
// ponytail: never compacted; compact on open if the log outgrows replay time.
type scimLogStore struct {
	mu       sync.RWMutex
	users    map[string]SCIMUser
	byName   map[string]string // lower(userName) -> id
	groups   map[string]SCIMGroup
	memberOf map[string]map[string]struct{} // user id -> ids of the groups listing it (Lookup and DeleteUser stay O(user's groups))
	f        *os.File                       // nil = memory only
	log      storage.Log                    // HA: the shared "scim" log instead of f (OpenSCIMStoreOn)
	names    storage.KV                     // HA: userName claims (claimName)
	cc       storage.Coalescer              // HA: one catch-up serves every concurrent reader
}

// errSCIMUserNameTaken is PutUser's refusal of a userName another user holds.
var errSCIMUserNameTaken = errors.New("scim store: userName is already provisioned")

// OpenSCIMStoreOn opens the directory on a shared backend's "scim" log
// (ADR-0021): every read first applies other replicas' writes, so a
// deprovisioning on one replica holds on all of them at once. The memberOf
// index is rebuilt by the same apply on replay and catch-up. names holds
// one claim per canonical userName, so two replicas can never provision the
// same name twice even if their uniqueness checks race.
func OpenSCIMStoreOn(ctx context.Context, o storage.Opener, names storage.KV) (SCIMStore, error) {
	s := &scimLogStore{users: map[string]SCIMUser{}, byName: map[string]string{}, groups: map[string]SCIMGroup{}, memberOf: map[string]map[string]struct{}{}, names: names}
	log, err := o.OpenLog(ctx, "scim", func(line []byte) {
		var rec scimRecord
		if json.Unmarshal(line, &rec) == nil {
			s.apply(rec)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("scim store: %w", err)
	}
	s.log = log
	return s, nil
}

// sync applies other replicas' records; false when the shared log cannot be
// read (the file and memory stores have no other writer). Concurrent readers
// share one catch-up (storage.Coalescer) instead of queueing on s.mu for one
// database round trip each.
func (s *scimLogStore) sync() bool {
	if s.log == nil {
		return true
	}
	return s.cc.Do(func() error {
		s.mu.Lock()
		defer s.mu.Unlock()
		ctx, cancel := storage.Ctx()
		defer cancel()
		return s.log.Catchup(ctx)
	}) == nil
}

const (
	kvSCIMName = "scim-username"
	// scimClaimPending is how long a claim taken before its user is written
	// lives: a replica that dies between the claim and the write does not
	// block the name for longer. A written user's claim is then pinned.
	scimClaimPending = 2 * time.Minute
	scimClaimPinned  = 100 * 365 * 24 * time.Hour
)

// claimName takes userName's claim for id on the shared store; false means
// another user holds it. A claim is re-entrant for its own id.
func (s *scimLogStore) claimName(userName, id string, ttl time.Duration) (bool, error) {
	ctx, cancel := storage.Ctx()
	defer cancel()
	return s.names.TryLock(ctx, kvSCIMName, canonicalUser(userName), id, ttl)
}

func (s *scimLogStore) releaseName(userName, id string) {
	ctx, cancel := storage.Ctx()
	defer cancel()
	_ = s.names.Unlock(ctx, kvSCIMName, canonicalUser(userName), id) // best effort: a stale claim only blocks reuse of a deleted name until an admin clears it
}

// OpenSCIMStore opens dir/scim.jsonl, or a memory-only store when dir is "".
func OpenSCIMStore(dir string) (SCIMStore, error) {
	s := &scimLogStore{users: map[string]SCIMUser{}, byName: map[string]string{}, groups: map[string]SCIMGroup{}, memberOf: map[string]map[string]struct{}{}}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("scim store: %w", err)
	}
	f, err := fsutil.OpenJSONL(filepath.Join(dir, "scim.jsonl"), func(line []byte) {
		var rec scimRecord
		if json.Unmarshal(line, &rec) == nil { // torn line: skip
			s.apply(rec)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("scim store: %w", err)
	}
	s.f = f
	return s, nil
}

func (s *scimLogStore) Close() error { return closeFile(&s.mu, s.f) }

// apply is the single state transition, shared by replay and live writes.
func (s *scimLogStore) apply(rec scimRecord) {
	switch {
	case rec.User != nil && rec.User.ID != "":
		if old, ok := s.users[rec.User.ID]; ok {
			delete(s.byName, canonicalUser(old.UserName))
		}
		s.users[rec.User.ID] = *rec.User
		s.byName[canonicalUser(rec.User.UserName)] = rec.User.ID
	case rec.Group != nil && rec.Group.ID != "":
		s.unindex(rec.Group.ID)
		s.groups[rec.Group.ID] = *rec.Group
		for _, m := range rec.Group.Members {
			if s.memberOf[m] == nil {
				s.memberOf[m] = map[string]struct{}{}
			}
			s.memberOf[m][rec.Group.ID] = struct{}{}
		}
	case rec.DelUser != "":
		if old, ok := s.users[rec.DelUser]; ok {
			delete(s.byName, canonicalUser(old.UserName))
			delete(s.users, rec.DelUser)
		}
		for gid := range s.memberOf[rec.DelUser] {
			g := s.groups[gid]
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == rec.DelUser }) // the store owns this slice: Put and the getters copy
			s.groups[gid] = g
		}
		delete(s.memberOf, rec.DelUser)
	case rec.DelGroup != "":
		s.unindex(rec.DelGroup)
		delete(s.groups, rec.DelGroup)
	}
}

// unindex drops group gid's current members from memberOf.
func (s *scimLogStore) unindex(gid string) {
	for _, m := range s.groups[gid].Members {
		delete(s.memberOf[m], gid)
		if len(s.memberOf[m]) == 0 {
			delete(s.memberOf, m)
		}
	}
}

func (s *scimLogStore) write(rec scimRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log != nil {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		ctx, cancel := storage.Ctx()
		defer cancel()
		if err := s.log.Append(ctx, "", b); err != nil {
			return fmt.Errorf("scim store: write: %w", err) // not applied in memory either
		}
	} else if s.f != nil {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		if _, err := s.f.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("scim store: write: %w", err) // not applied in memory either
		}
	}
	s.apply(rec)
	return nil
}

func (s *scimLogStore) PutUser(u SCIMUser) error {
	if u.ID == "" {
		return errors.New("scim store: user without id")
	}
	if s.names == nil {
		return s.write(scimRecord{User: &u})
	}
	// Shared store: claim the name first, write, then pin the claim and drop
	// the old name's. A crash between claim and write leaves a claim that
	// expires in scimClaimPending.
	if !s.sync() { // the current name may have been written by another replica
		return fmt.Errorf("scim store: %w", storage.ErrUnavailable)
	}
	s.mu.RLock()
	old, had := s.users[u.ID]
	s.mu.RUnlock()
	renamed := had && canonicalUser(old.UserName) != canonicalUser(u.UserName)
	ok, err := s.claimName(u.UserName, u.ID, scimClaimPending)
	if err != nil {
		return fmt.Errorf("scim store: claim userName: %w", err)
	}
	if !ok {
		return errSCIMUserNameTaken
	}
	if err := s.write(scimRecord{User: &u}); err != nil {
		if !had || renamed {
			s.releaseName(u.UserName, u.ID)
		}
		return err
	}
	if _, err := s.claimName(u.UserName, u.ID, scimClaimPinned); err != nil {
		return fmt.Errorf("scim store: pin userName claim: %w", err) // the user is written; the pending claim still holds it for now
	}
	if renamed {
		s.releaseName(old.UserName, u.ID)
	}
	return nil
}

func (s *scimLogStore) PutGroup(g SCIMGroup) error {
	if g.ID == "" {
		return errors.New("scim store: group without id")
	}
	g.Members = append([]string(nil), g.Members...)
	return s.write(scimRecord{Group: &g})
}

func (s *scimLogStore) DeleteUser(id string) error {
	if s.names == nil {
		return s.write(scimRecord{DelUser: id})
	}
	if !s.sync() {
		return fmt.Errorf("scim store: %w", storage.ErrUnavailable)
	}
	s.mu.RLock()
	old, had := s.users[id]
	s.mu.RUnlock()
	if err := s.write(scimRecord{DelUser: id}); err != nil {
		return err
	}
	if had {
		s.releaseName(old.UserName, id)
	}
	return nil
}
func (s *scimLogStore) DeleteGroup(id string) error { return s.write(scimRecord{DelGroup: id}) }

func (s *scimLogStore) User(id string) (SCIMUser, bool) {
	_ = s.sync() // unreadable: serve the last view; writes still replay first
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *scimLogStore) Group(id string) (SCIMGroup, bool) {
	_ = s.sync() // unreadable: serve the last view; writes still replay first
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	g.Members = append([]string(nil), g.Members...)
	return g, ok
}

func (s *scimLogStore) Users() []SCIMUser {
	_ = s.sync() // unreadable: serve the last view; writes still replay first
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SCIMUser, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UserName < out[j].UserName })
	return out
}

func (s *scimLogStore) Groups() []SCIMGroup {
	_ = s.sync() // unreadable: serve the last view; writes still replay first
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SCIMGroup, 0, len(s.groups))
	for _, g := range s.groups {
		g.Members = append([]string(nil), g.Members...)
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DisplayName != out[j].DisplayName {
			return out[i].DisplayName < out[j].DisplayName
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (s *scimLogStore) Lookup(userName string) (SCIMUser, []string, bool) {
	if !s.sync() { // a deprovisioning on another replica might be unseen: fail closed
		return SCIMUser{UserName: userName}, nil, true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byName[canonicalUser(userName)]
	if !ok {
		return SCIMUser{}, nil, false
	}
	var groups []string
	for gid := range s.memberOf[id] {
		groups = append(groups, s.groups[gid].DisplayName)
	}
	sort.Strings(groups)
	return s.users[id], groups, true
}
