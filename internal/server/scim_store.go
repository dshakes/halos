package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dshakes/halos/internal/fsutil"
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
// ponytail: never compacted and Lookup scans every group; compact on open or index memberships if directories reach 100k+ objects.
type scimLogStore struct {
	mu     sync.RWMutex
	users  map[string]SCIMUser
	byName map[string]string // lower(userName) -> id
	groups map[string]SCIMGroup
	f      *os.File // nil = memory only
}

// OpenSCIMStore opens dir/scim.jsonl, or a memory-only store when dir is "".
func OpenSCIMStore(dir string) (SCIMStore, error) {
	s := &scimLogStore{users: map[string]SCIMUser{}, byName: map[string]string{}, groups: map[string]SCIMGroup{}}
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
			delete(s.byName, strings.ToLower(old.UserName))
		}
		s.users[rec.User.ID] = *rec.User
		s.byName[strings.ToLower(rec.User.UserName)] = rec.User.ID
	case rec.Group != nil && rec.Group.ID != "":
		s.groups[rec.Group.ID] = *rec.Group
	case rec.DelUser != "":
		if old, ok := s.users[rec.DelUser]; ok {
			delete(s.byName, strings.ToLower(old.UserName))
			delete(s.users, rec.DelUser)
		}
		for id, g := range s.groups {
			if i := slices.Index(g.Members, rec.DelUser); i >= 0 {
				g.Members = slices.Delete(g.Members, i, i+1) // the store owns this slice: Put and the getters copy
				s.groups[id] = g
			}
		}
	case rec.DelGroup != "":
		delete(s.groups, rec.DelGroup)
	}
}

func (s *scimLogStore) write(rec scimRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
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
	return s.write(scimRecord{User: &u})
}

func (s *scimLogStore) PutGroup(g SCIMGroup) error {
	if g.ID == "" {
		return errors.New("scim store: group without id")
	}
	g.Members = append([]string(nil), g.Members...)
	return s.write(scimRecord{Group: &g})
}

func (s *scimLogStore) DeleteUser(id string) error  { return s.write(scimRecord{DelUser: id}) }
func (s *scimLogStore) DeleteGroup(id string) error { return s.write(scimRecord{DelGroup: id}) }

func (s *scimLogStore) User(id string) (SCIMUser, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *scimLogStore) Group(id string) (SCIMGroup, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	g, ok := s.groups[id]
	g.Members = append([]string(nil), g.Members...)
	return g, ok
}

func (s *scimLogStore) Users() []SCIMUser {
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
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byName[strings.ToLower(userName)]
	if !ok {
		return SCIMUser{}, nil, false
	}
	var groups []string
	for _, g := range s.groups {
		if slices.Contains(g.Members, id) {
			groups = append(groups, g.DisplayName)
		}
	}
	sort.Strings(groups)
	return s.users[id], groups, true
}
