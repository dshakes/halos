package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/dshakes/halos/internal/gateway"
	"github.com/dshakes/halos/internal/identity"
	"github.com/dshakes/halos/internal/policy"
)

// SCIM 2.0 service provider (RFC 7643/7644) at /scim/v2, ADR-0022. The IdP
// authenticates with a dedicated bearer token (only its SHA-256 is
// configured; never a console session). Deactivating or deleting a user
// revokes their sessions, devices and pending enrollments at once; with
// Config.SCIMAuthoritative the directory, not the login's groups claim, decides
// who is active and in which groups.

const (
	scimUserSchema    = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimGroupSchema   = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimListSchema    = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimErrorSchema   = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimSPCSchema     = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	scimRTSchema      = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimSchemaSchema  = "urn:ietf:params:scim:schemas:core:2.0:Schema"
	scimMaxBody       = 1 << 20
	scimMaxResults    = 1000
	scimDefaultCount  = 100
	scimMaxMembers    = 20000 // keeps a group's log line under the JSONL replay limit (1 MiB)
	scimMaxOperations = 1000
	scimActor         = "scim" // audit actor for every provisioning mutation
)

// scimService is the SCIM state; nil on a Server without SCIM.
type scimService struct {
	mu    sync.Mutex // serialises mutations: read-modify-write and uniqueness checks
	sums  [][32]byte
	store SCIMStore
	owned bool // opened by New, so Close closes it
}

// emptySum is SHA-256(""): configuring it would accept a missing token.
var emptySum = sha256.Sum256(nil)

func newSCIM(cfg Config) (*scimService, error) {
	if len(cfg.SCIMTokenSHA256) == 0 {
		if cfg.SCIMAuthoritative {
			return nil, errors.New("server: SCIMAuthoritative needs SCIMTokenSHA256")
		}
		return nil, nil
	}
	sc := &scimService{}
	for i, h := range cfg.SCIMTokenSHA256 {
		b, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(b) != sha256.Size || [32]byte(b) == emptySum {
			return nil, fmt.Errorf("server: SCIM token hash %d is not the hex SHA-256 of a non-empty token", i+1)
		}
		sc.sums = append(sc.sums, [32]byte(b))
	}
	if sc.store = cfg.SCIMStore; sc.store == nil {
		st, err := OpenSCIMStore(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		sc.store, sc.owned = st, true
	}
	return sc, nil
}

func (sc *scimService) close() error {
	if sc == nil || !sc.owned {
		return nil
	}
	return sc.store.Close()
}

// directoryGroups applies the SCIM directory to a user authenticated by other
// means (session cookie, device token, OIDC callback). ok=false: the user is
// deactivated, or unknown while the directory is authoritative. Authoritative
// mode also replaces the groups with the directory's.
func (s *Server) directoryGroups(user string, groups []string) ([]string, bool) {
	if s.scim == nil {
		return groups, true
	}
	u, dg, known := s.scim.store.Lookup(user)
	switch {
	case known && !u.Active:
		return nil, false
	case s.cfg.SCIMAuthoritative && !known:
		return nil, false
	case s.cfg.SCIMAuthoritative:
		return dg, true
	}
	return groups, true
}

// deprovision ends everything userName holds on halo-server: every session
// (epoch), every device token, every unconsumed enrollment token. Idempotent.
func (s *Server) deprovision(userName string) (devices int, err error) {
	if err := s.revoked.revoke(userName, s.cfg.Now()); err != nil {
		return 0, fmt.Errorf("revoke sessions of %q: %w", userName, err)
	}
	n, err := s.devices.revokeUser(userName)
	if err != nil {
		return n, fmt.Errorf("revoke devices of %q: %w", userName, err)
	}
	s.enroll.dropUser(userName)
	return n, nil
}

// revokeUser revokes every live device bound to user (userName is case-insensitive).
func (d *deviceStore) revokeUser(user string) (int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, v := range d.byID {
		if v.Revoked || !sameUser(v.UserID, user) {
			continue
		}
		v.Revoked = true
		if err := d.persist(v); err != nil {
			v.Revoked = false
			return n, err
		}
		n++
	}
	return n, nil
}

func (e *enrollments) dropUser(user string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for h, v := range e.m {
		if sameUser(v.user.ID, user) {
			delete(e.m, h)
		}
	}
}

// ---- routes and auth ----

// scimRoutes registers the SCIM API (SCIM bearer token) and the gateway
// directory (gateway token). Neither takes a session cookie, so they sit outside
// routePerms on the reviewed public list (rbac_test.go publicRoutes).
func (s *Server) scimRoutes(m *routeMux) {
	h := func(fn http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if s.scimAuth(w, r) {
				fn(w, r)
			}
		}
	}
	m.HandleFunc("GET /scim/v2/ServiceProviderConfig", h(s.scimSPC))
	m.HandleFunc("GET /scim/v2/ResourceTypes", h(s.scimResourceTypes))
	m.HandleFunc("GET /scim/v2/ResourceTypes/{id}", h(s.scimResourceTypes))
	m.HandleFunc("GET /scim/v2/Schemas", h(s.scimSchemas))
	m.HandleFunc("GET /scim/v2/Schemas/{id}", h(s.scimSchemas))
	m.HandleFunc("GET /scim/v2/Users", h(s.scimListUsers))
	m.HandleFunc("POST /scim/v2/Users", h(s.scimCreateUser))
	m.HandleFunc("GET /scim/v2/Users/{id}", h(s.scimGetUser))
	m.HandleFunc("PUT /scim/v2/Users/{id}", h(s.scimPutUser))
	m.HandleFunc("PATCH /scim/v2/Users/{id}", h(s.scimPatchUser))
	m.HandleFunc("DELETE /scim/v2/Users/{id}", h(s.scimDeleteUser))
	m.HandleFunc("GET /scim/v2/Groups", h(s.scimListGroups))
	m.HandleFunc("POST /scim/v2/Groups", h(s.scimCreateGroup))
	m.HandleFunc("GET /scim/v2/Groups/{id}", h(s.scimGetGroup))
	m.HandleFunc("PUT /scim/v2/Groups/{id}", h(s.scimPutGroup))
	m.HandleFunc("PATCH /scim/v2/Groups/{id}", h(s.scimPatchGroup))
	m.HandleFunc("DELETE /scim/v2/Groups/{id}", h(s.scimDeleteGroup))
	m.HandleFunc("/scim/v2/", h(func(w http.ResponseWriter, _ *http.Request) {
		scimError(w, http.StatusNotFound, "", "unknown SCIM endpoint or method")
	}))
	m.HandleFunc("GET /api/v1/gateway/directory", s.getGatewayDirectory)
}

// scimAuth accepts only the SCIM bearer token: any configured hash matches
// (two during a rotation), compared in constant time over every hash. Session
// cookies are never looked at. Failures count against SCIM's own per-IP
// budget (scimFails), so SCIM noise cannot lock out gateways or devices.
func (s *Server) scimAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.scim == nil {
		scimError(w, http.StatusNotFound, "", "SCIM provisioning is not enabled on this server")
		return false
	}
	ip := s.clientIP(r)
	if s.scimFails.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		scimError(w, http.StatusTooManyRequests, "", "too many failed attempts")
		return false
	}
	a := r.Header.Get("Authorization")
	ok := len(a) > 7 && strings.EqualFold(a[:7], "bearer ")
	tok := ""
	if ok {
		tok = strings.TrimSpace(a[7:])
	}
	sum := sha256.Sum256([]byte(tok)) // hash first: constant-time regardless of length
	match := 0
	for _, h := range s.scim.sums {
		match |= subtle.ConstantTimeCompare(sum[:], h[:])
	}
	if !ok || tok == "" || match != 1 {
		s.scimFails.fail(ip)
		w.Header().Set("WWW-Authenticate", `Bearer realm="halos-scim"`)
		scimError(w, http.StatusUnauthorized, "", "SCIM bearer token required")
		return false
	}
	return true
}

// getGatewayDirectory: GET /api/v1/gateway/directory?subject=<id> (gateway
// token). Gateways with a directory configured route only active users with
// these groups; a verified caller listed inactive here is refused (403).
func (s *Server) getGatewayDirectory(w http.ResponseWriter, r *http.Request) {
	if !s.gatewayEnabled(capDirectory) || s.scim == nil {
		apiErr(w, http.StatusNotFound, "SCIM directory not configured")
		return
	}
	if !s.gatewayAuth(w, r, capDirectory) {
		return
	}
	sub := r.URL.Query().Get("subject")
	if sub == "" || len(sub) > 256 {
		apiErr(w, http.StatusBadRequest, "subject required (<=256 chars)")
		return
	}
	u, groups, ok := s.scim.store.Lookup(sub)
	if !ok || !u.Active {
		writeJSON(w, http.StatusOK, gateway.DirectoryEntry{})
		return
	}
	writeJSON(w, http.StatusOK, gateway.DirectoryEntry{Active: true, Groups: groups})
}

// ---- wire format ----

type scimErr struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail"`
}

// scimFail is a handler outcome that becomes a SCIM error response.
type scimFail struct {
	status   int
	scimType string
	detail   string
}

func (e *scimFail) Error() string { return e.detail }

func badValue(format string, a ...any) *scimFail {
	return &scimFail{http.StatusBadRequest, "invalidValue", fmt.Sprintf(format, a...)}
}

func writeSCIM(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v) // client gone: nothing useful to do
}

func scimError(w http.ResponseWriter, code int, scimType, detail string) {
	writeSCIM(w, code, scimErr{Schemas: []string{scimErrorSchema}, Status: strconv.Itoa(code), ScimType: scimType, Detail: detail})
}

func writeFail(w http.ResponseWriter, err error) {
	var f *scimFail
	if errors.As(err, &f) {
		scimError(w, f.status, f.scimType, f.detail)
		return
	}
	scimError(w, http.StatusInternalServerError, "", "internal error")
}

type scimMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location"`
	Version      string    `json:"version"`
}

type scimRef struct {
	Value   string `json:"value"`
	Ref     string `json:"$ref,omitempty"`
	Display string `json:"display,omitempty"`
}

type scimUserOut struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *SCIMName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []SCIMEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Groups      []scimRef   `json:"groups,omitempty"`
	Meta        scimMeta    `json:"meta"`
}

type scimGroupOut struct {
	Schemas     []string  `json:"schemas"`
	ID          string    `json:"id"`
	ExternalID  string    `json:"externalId,omitempty"`
	DisplayName string    `json:"displayName"`
	Members     []scimRef `json:"members,omitempty"`
	Meta        scimMeta  `json:"meta"`
}

type scimList struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

// scimVersion is the weak ETag of a stored resource.
func scimVersion(v any) string {
	b, _ := json.Marshal(v) // plain structs: cannot fail
	h := sha256.Sum256(b)
	return `W/"` + hex.EncodeToString(h[:8]) + `"`
}

// ifMatch reports whether an If-Match precondition (if any) names version.
func ifMatch(r *http.Request, version string) bool {
	im := strings.TrimSpace(r.Header.Get("If-Match"))
	if im == "" || im == "*" {
		return true
	}
	bare := strings.TrimPrefix(version, "W/")
	for _, t := range strings.Split(im, ",") {
		if t = strings.TrimPrefix(strings.TrimSpace(t), "W/"); t == bare {
			return true
		}
	}
	return false
}

func (s *Server) scimLocation(r *http.Request, kind, id string) string {
	return s.baseURL(r) + "/scim/v2/" + kind + "/" + id
}

// memberships maps user id -> the groups it belongs to.
func (s *Server) memberships(r *http.Request) map[string][]scimRef {
	out := map[string][]scimRef{}
	for _, g := range s.scim.store.Groups() {
		for _, m := range g.Members {
			out[m] = append(out[m], scimRef{Value: g.ID, Ref: s.scimLocation(r, "Groups", g.ID), Display: g.DisplayName})
		}
	}
	return out
}

func (s *Server) userOut(r *http.Request, u SCIMUser, groups []scimRef) scimUserOut {
	return scimUserOut{Schemas: []string{scimUserSchema}, ID: u.ID, ExternalID: u.ExternalID, UserName: u.UserName, Name: u.Name,
		DisplayName: u.DisplayName, Emails: u.Emails, Active: u.Active, Groups: groups,
		Meta: scimMeta{ResourceType: "User", Created: u.Created, LastModified: u.Modified, Location: s.scimLocation(r, "Users", u.ID), Version: scimVersion(u)}}
}

func (s *Server) groupOut(r *http.Request, g SCIMGroup, withMembers bool) scimGroupOut {
	out := scimGroupOut{Schemas: []string{scimGroupSchema}, ID: g.ID, ExternalID: g.ExternalID, DisplayName: g.DisplayName,
		Meta: scimMeta{ResourceType: "Group", Created: g.Created, LastModified: g.Modified, Location: s.scimLocation(r, "Groups", g.ID), Version: scimVersion(g)}}
	if withMembers {
		for _, id := range g.Members {
			ref := scimRef{Value: id, Ref: s.scimLocation(r, "Users", id)}
			if u, ok := s.scim.store.User(id); ok {
				ref.Display = u.UserName
			}
			out.Members = append(out.Members, ref)
		}
	}
	return out
}

// ---- request decoding ----

// scimBool accepts a JSON boolean or a string such as "True"/"False" (Entra ID
// sends PATCH values as strings).
type scimBool bool

func (b *scimBool) UnmarshalJSON(d []byte) error {
	var v any
	if err := json.Unmarshal(d, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case bool:
		*b = scimBool(t)
		return nil
	case string:
		p, err := strconv.ParseBool(strings.TrimSpace(t))
		if err != nil {
			return fmt.Errorf("%q is not a boolean", t)
		}
		*b = scimBool(p)
		return nil
	}
	return fmt.Errorf("%s is not a boolean", d)
}

type scimEmailIn struct {
	Value   string   `json:"value"`
	Type    string   `json:"type"`
	Primary scimBool `json:"primary"`
}

func (e scimEmailIn) email() SCIMEmail {
	return SCIMEmail{Value: e.Value, Type: e.Type, Primary: bool(e.Primary)}
}

type scimUserIn struct {
	ExternalID  string        `json:"externalId"`
	UserName    string        `json:"userName"`
	DisplayName string        `json:"displayName"`
	Name        *SCIMName     `json:"name"`
	Emails      []scimEmailIn `json:"emails"`
	Active      *scimBool     `json:"active"`
}

type scimMemberIn struct {
	Value string `json:"value"`
}

type scimGroupIn struct {
	ExternalID  string         `json:"externalId"`
	DisplayName string         `json:"displayName"`
	Members     []scimMemberIn `json:"members"`
}

type scimOp struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

type scimPatchIn struct {
	Operations []scimOp `json:"Operations"`
}

// decodeSCIM decodes one JSON body (capped, nothing trailing) into v.
func decodeSCIM(w http.ResponseWriter, r *http.Request, v any) error {
	if err := decodeBody(w, r, scimMaxBody, v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &scimFail{http.StatusRequestEntityTooLarge, "", "request body exceeds 1 MiB"}
		}
		if errors.Is(err, io.EOF) {
			return &scimFail{http.StatusBadRequest, "invalidSyntax", "request body required"}
		}
		return &scimFail{http.StatusBadRequest, "invalidSyntax", "invalid JSON: " + err.Error()}
	}
	return nil
}

func emails(in []scimEmailIn) []SCIMEmail {
	var out []SCIMEmail
	for _, e := range in {
		out = append(out, e.email())
	}
	return out
}

// checkText bounds an attribute and refuses control characters (values end up
// in audit entries, logs and revocation keys).
func checkText(attr, v string, required bool) error {
	if required && strings.TrimSpace(v) == "" {
		return badValue("%s is required", attr)
	}
	if len(v) > 256 {
		return badValue("%s exceeds 256 bytes", attr)
	}
	if strings.ContainsFunc(v, unicode.IsControl) {
		return badValue("%s contains control characters", attr)
	}
	return nil
}

func validUser(u SCIMUser) error {
	if len(u.Emails) > 20 {
		return badValue("at most 20 emails")
	}
	checks := [][2]string{{"userName", u.UserName}, {"externalId", u.ExternalID}, {"displayName", u.DisplayName}}
	if u.Name != nil {
		checks = append(checks, [2]string{"name.formatted", u.Name.Formatted}, [2]string{"name.givenName", u.Name.GivenName}, [2]string{"name.familyName", u.Name.FamilyName})
	}
	for _, e := range u.Emails {
		checks = append(checks, [2]string{"emails.value", e.Value}, [2]string{"emails.type", e.Type})
	}
	for i, c := range checks {
		if err := checkText(c[0], c[1], i == 0); err != nil {
			return err
		}
	}
	if identity.CheckHumanID(u.UserName) != nil {
		return badValue("userName must not start with %q (reserved for workload identities)", policy.WorkloadSubjectPrefix)
	}
	return nil
}

func (s *Server) validGroup(g SCIMGroup) error {
	if err := checkText("displayName", g.DisplayName, true); err != nil {
		return err
	}
	if err := checkText("externalId", g.ExternalID, false); err != nil {
		return err
	}
	if len(g.Members) > scimMaxMembers {
		return badValue("a group holds at most %d members", scimMaxMembers)
	}
	for _, m := range g.Members {
		if _, ok := s.scim.store.User(m); !ok {
			return badValue("member %q is not a provisioned user (nested groups are not supported)", m)
		}
	}
	return nil
}

// ---- filter and pagination ----

// parseFilter accepts `<attr> eq "<value>"` for attr in attrs (lowercase).
// Attribute names are case-insensitive and may carry the schema URN.
func parseFilter(f string, attrs ...string) (attr, val string, err error) {
	f = strings.TrimSpace(f)
	if f == "" {
		return "", "", nil
	}
	a, rest, ok := strings.Cut(f, " ")
	op, lit, ok2 := strings.Cut(strings.TrimSpace(rest), " ")
	lit = strings.TrimSpace(lit)
	if !ok || !ok2 || !strings.EqualFold(op, "eq") || len(lit) < 2 || lit[0] != '"' || json.Unmarshal([]byte(lit), &val) != nil {
		return "", "", &scimFail{http.StatusBadRequest, "invalidFilter", `only filters of the form <attribute> eq "<value>" are supported`}
	}
	attr = strings.ToLower(a)
	if i := strings.LastIndex(attr, ":"); i >= 0 {
		attr = attr[i+1:]
	}
	if !slices.Contains(attrs, attr) {
		return "", "", &scimFail{http.StatusBadRequest, "invalidFilter", "filtering is supported on " + strings.Join(attrs, ", ")}
	}
	return attr, val, nil
}

// page returns the 1-based startIndex and count (RFC 7644 §3.4.2.4).
func page(r *http.Request) (start, count int, err error) {
	start, count = 1, scimDefaultCount
	q := r.URL.Query()
	if v := q.Get("startIndex"); v != "" {
		if start, err = strconv.Atoi(v); err != nil {
			return 0, 0, badValue("startIndex must be an integer")
		}
		start = max(start, 1)
	}
	if v := q.Get("count"); v != "" {
		if count, err = strconv.Atoi(v); err != nil {
			return 0, 0, badValue("count must be an integer")
		}
		count = min(max(count, 0), scimMaxResults)
	}
	return start, count, nil
}

func pageOf[T any](all []T, start, count int) []T {
	if start > len(all) {
		return nil
	}
	return all[start-1 : min(len(all), start-1+count)]
}

func list(total, start int, items []any) scimList {
	if items == nil {
		items = []any{}
	}
	return scimList{Schemas: []string{scimListSchema}, TotalResults: total, StartIndex: start, ItemsPerPage: len(items), Resources: items}
}

// excluded reports whether the excludedAttributes query parameter names attr.
func excluded(r *http.Request, attr string) bool {
	for _, a := range strings.Split(r.URL.Query().Get("excludedAttributes"), ",") {
		if strings.EqualFold(strings.TrimSpace(a), attr) {
			return true
		}
	}
	return false
}

// ---- users ----

func (s *Server) scimListUsers(w http.ResponseWriter, r *http.Request) {
	attr, val, err := parseFilter(r.URL.Query().Get("filter"), "username", "externalid", "id")
	if err != nil {
		writeFail(w, err)
		return
	}
	start, count, err := page(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	var match []SCIMUser
	for _, u := range s.scim.store.Users() {
		if attr == "" || (attr == "username" && sameUser(u.UserName, val)) ||
			(attr == "externalid" && u.ExternalID == val) || (attr == "id" && u.ID == val) {
			match = append(match, u)
		}
	}
	mem := s.memberships(r)
	var items []any
	for _, u := range pageOf(match, start, count) {
		items = append(items, s.userOut(r, u, mem[u.ID]))
	}
	writeSCIM(w, http.StatusOK, list(len(match), start, items))
}

func (s *Server) writeUser(w http.ResponseWriter, r *http.Request, code int, u SCIMUser) {
	out := s.userOut(r, u, s.memberships(r)[u.ID])
	w.Header().Set("ETag", out.Meta.Version)
	if code == http.StatusCreated {
		w.Header().Set("Location", out.Meta.Location)
	}
	writeSCIM(w, code, out)
}

func (s *Server) scimGetUser(w http.ResponseWriter, r *http.Request) {
	u, ok := s.scim.store.User(r.PathValue("id"))
	if !ok {
		scimError(w, http.StatusNotFound, "", "user not found")
		return
	}
	s.writeUser(w, r, http.StatusOK, u)
}

func (s *Server) scimCreateUser(w http.ResponseWriter, r *http.Request) {
	var in scimUserIn
	if err := decodeSCIM(w, r, &in); err != nil {
		writeFail(w, err)
		return
	}
	now := s.cfg.Now().UTC()
	u := SCIMUser{ID: newUUID(), ExternalID: in.ExternalID, UserName: in.UserName, DisplayName: in.DisplayName, Name: in.Name,
		Emails: emails(in.Emails), Active: in.Active == nil || bool(*in.Active), Created: now, Modified: now}
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	if err := s.commitUser(r, "scim.user.create", nil, u, nil); err != nil {
		writeFail(w, err)
		return
	}
	s.writeUser(w, r, http.StatusCreated, u)
}

// loadUser fetches the user for a mutation and checks If-Match.
func (s *Server) loadUser(r *http.Request) (SCIMUser, error) {
	u, ok := s.scim.store.User(r.PathValue("id"))
	if !ok {
		return u, &scimFail{http.StatusNotFound, "", "user not found"}
	}
	if !ifMatch(r, scimVersion(u)) {
		return u, &scimFail{http.StatusPreconditionFailed, "", "If-Match does not match the current version"}
	}
	return u, nil
}

// scimPutUser replaces the user (Okta updates users with PUT). An absent
// "active" keeps the current state: a partial PUT never reactivates anyone.
func (s *Server) scimPutUser(w http.ResponseWriter, r *http.Request) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	old, err := s.loadUser(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	var in scimUserIn
	if err := decodeSCIM(w, r, &in); err != nil {
		writeFail(w, err)
		return
	}
	u := SCIMUser{ID: old.ID, ExternalID: in.ExternalID, UserName: in.UserName, DisplayName: in.DisplayName, Name: in.Name,
		Emails: emails(in.Emails), Active: old.Active, Created: old.Created, Modified: s.cfg.Now().UTC()}
	if in.Active != nil {
		u.Active = bool(*in.Active)
	}
	if err := s.commitUser(r, "scim.user.replace", &old, u, nil); err != nil {
		writeFail(w, err)
		return
	}
	s.writeUser(w, r, http.StatusOK, u)
}

func (s *Server) scimPatchUser(w http.ResponseWriter, r *http.Request) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	old, err := s.loadUser(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	ops, err := decodePatch(w, r)
	if err != nil {
		writeFail(w, err)
		return
	}
	u := old
	u.Name = clonePtr(old.Name)
	u.Emails = slices.Clone(old.Emails)
	var ignored []string
	for _, op := range ops {
		ig, err := patchUser(&u, op)
		if err != nil {
			writeFail(w, err)
			return
		}
		ignored = append(ignored, ig...)
	}
	u.Modified = s.cfg.Now().UTC()
	if err := s.commitUser(r, "scim.user.patch", &old, u, ignored); err != nil {
		writeFail(w, err)
		return
	}
	s.writeUser(w, r, http.StatusOK, u)
}

func (s *Server) scimDeleteUser(w http.ResponseWriter, r *http.Request) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	u, err := s.loadUser(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	n, err := s.deprovision(u.UserName) // before the delete: a failure leaves the user for the IdP's retry
	if err != nil {
		s.cfg.Log.Error("scim deprovision", "user", u.UserName, "err", err)
		writeFail(w, err)
		return
	}
	if err := s.scim.store.DeleteUser(u.ID); err != nil {
		s.cfg.Log.Error("scim store", "user", u.UserName, "err", err)
		writeFail(w, err)
		return
	}
	s.cfg.Log.Info("scim user deleted", "user", u.UserName, "devicesRevoked", n)
	if err := s.AuditStrict(r.Context(), scimActor, "scim.user.delete", u.UserName,
		map[string]string{"id": u.ID, "sessionsRevoked": "true", "devicesRevoked": strconv.Itoa(n)}); err != nil {
		scimError(w, http.StatusInternalServerError, "", errAuditFailed) // the delete itself is in force
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// commitUser validates u, enforces userName uniqueness, deprovisions what the
// change takes away (a deactivation, or the old name on a rename) and only
// then persists: a failed revocation leaves the old state for the IdP's
// retry. Callers hold s.scim.mu.
func (s *Server) commitUser(r *http.Request, action string, old *SCIMUser, u SCIMUser, ignored []string) error {
	if err := validUser(u); err != nil {
		return err
	}
	if other, _, ok := s.scim.store.Lookup(u.UserName); ok && other.ID != u.ID {
		return &scimFail{http.StatusConflict, "uniqueness", "userName is already provisioned"}
	}
	details := map[string]string{"id": u.ID, "active": strconv.FormatBool(u.Active)}
	var gone []string
	if old != nil && !sameUser(old.UserName, u.UserName) {
		details["previousUserName"] = old.UserName
		gone = append(gone, old.UserName)
	}
	if !u.Active && (old == nil || old.Active) {
		gone = append(gone, u.UserName)
	}
	devs := 0
	for _, name := range gone {
		n, err := s.deprovision(name)
		devs += n
		if err != nil {
			s.cfg.Log.Error("scim deprovision", "user", name, "err", err)
			return err
		}
	}
	if len(gone) > 0 {
		details["sessionsRevoked"], details["devicesRevoked"] = "true", strconv.Itoa(devs)
	}
	if len(ignored) > 0 {
		details["ignoredAttributes"] = strings.Join(ignored, ",")
	}
	if err := s.scim.store.PutUser(u); err != nil {
		s.cfg.Log.Error("scim store", "user", u.UserName, "err", err)
		return err
	}
	s.cfg.Log.Info("scim user", "action", action, "user", u.UserName, "active", u.Active)
	if err := s.AuditStrict(r.Context(), scimActor, action, u.UserName, details); err != nil {
		return &scimFail{http.StatusInternalServerError, "", errAuditFailed} // the change itself is in force
	}
	return nil
}

func clonePtr[T any](p *T) *T {
	if p == nil {
		return nil
	}
	c := *p
	return &c
}

// ---- PATCH (RFC 7644 §3.5.2) ----

func decodePatch(w http.ResponseWriter, r *http.Request) ([]scimOp, error) {
	var in scimPatchIn
	if err := decodeSCIM(w, r, &in); err != nil {
		return nil, err
	}
	if len(in.Operations) == 0 || len(in.Operations) > scimMaxOperations {
		return nil, &scimFail{http.StatusBadRequest, "invalidSyntax", fmt.Sprintf("Operations must hold 1 to %d operations", scimMaxOperations)}
	}
	for i := range in.Operations {
		op := &in.Operations[i]
		op.Op = strings.ToLower(strings.TrimSpace(op.Op)) // Entra ID sends "Add", "Replace", "Remove"
		if op.Op != "add" && op.Op != "replace" && op.Op != "remove" {
			return nil, &scimFail{http.StatusBadRequest, "invalidSyntax", fmt.Sprintf("operation %d: op must be add, replace or remove", i+1)}
		}
		if op.Op != "remove" && isNull(op.Value) {
			return nil, &scimFail{http.StatusBadRequest, "invalidValue", fmt.Sprintf("operation %d: %s needs a value", i+1, op.Op)}
		}
	}
	return in.Operations, nil
}

func isNull(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t == "" || t == "null"
}

// stripURN removes the core schema URN some clients qualify paths with.
func stripURN(p string) string {
	p = strings.TrimSpace(p)
	for _, urn := range []string{scimUserSchema + ":", scimGroupSchema + ":"} {
		if len(p) > len(urn) && strings.EqualFold(p[:len(urn)], urn) {
			p = p[len(urn):]
		}
	}
	return p
}

// patchPath normalises a PATCH path or attribute name for comparison (names
// are case-insensitive).
func patchPath(p string) string { return strings.ToLower(stripURN(p)) }

// valueFilter matches `attr[sub eq "x"]rest` (attr case-insensitive) and
// returns x, case preserved, and rest.
func valueFilter(path, attr, sub string) (val, rest string, ok bool) {
	path = stripURN(path)
	if len(path) <= len(attr) || !strings.EqualFold(path[:len(attr)+1], attr+"[") {
		return "", "", false
	}
	cond, rest, found := strings.Cut(path[len(attr)+1:], "]")
	if !found {
		return "", "", false
	}
	a, v, err := parseFilter(cond, sub)
	if err != nil || a == "" {
		return "", "", false
	}
	return v, rest, true
}

func str(attr string, raw json.RawMessage) (string, error) {
	if isNull(raw) {
		return "", nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", badValue("%s must be a string", attr)
	}
	return v, nil
}

// objectOps expands a path-less add/replace (value is an object of attribute
// -> value, as Okta sends) into one operation per attribute.
func objectOps(op scimOp) ([]scimOp, error) {
	if op.Op == "remove" {
		return nil, &scimFail{http.StatusBadRequest, "noTarget", "remove needs a path"}
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(op.Value, &obj); err != nil {
		return nil, badValue("a patch without a path needs an object value")
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	slices.Sort(keys) // deterministic application order
	out := make([]scimOp, 0, len(keys))
	for _, k := range keys {
		switch patchPath(k) {
		case "id", "schemas", "meta":
			continue // read-only echoes (Okta repeats the id)
		}
		out = append(out, scimOp{Op: op.Op, Path: k, Value: obj[k]})
	}
	return out, nil
}

// patchUser applies one operation; it returns the attributes it ignored
// (ones Halos does not keep, e.g. title or the enterprise extension).
func patchUser(u *SCIMUser, op scimOp) ([]string, error) {
	if strings.TrimSpace(op.Path) == "" {
		ops, err := objectOps(op)
		if err != nil {
			return nil, err
		}
		var ignored []string
		for _, o := range ops {
			ig, err := patchUser(u, o)
			if err != nil {
				return nil, err
			}
			ignored = append(ignored, ig...)
		}
		return ignored, nil
	}
	path := patchPath(op.Path)
	remove := op.Op == "remove"
	setName := func(f func(n *SCIMName, v string)) error {
		v, err := str(op.Path, op.Value)
		if err != nil {
			return err
		}
		if u.Name == nil {
			u.Name = &SCIMName{}
		}
		if remove {
			v = ""
		}
		f(u.Name, v)
		return nil
	}
	var err error
	switch path {
	case "active":
		if remove {
			return nil, &scimFail{http.StatusBadRequest, "mutability", "active cannot be removed"}
		}
		var b scimBool
		if json.Unmarshal(op.Value, &b) != nil {
			return nil, badValue("active must be a boolean")
		}
		u.Active = bool(b)
	case "username":
		if remove {
			return nil, &scimFail{http.StatusBadRequest, "mutability", "userName cannot be removed"}
		}
		u.UserName, err = str(op.Path, op.Value)
	case "externalid":
		u.ExternalID, err = str(op.Path, op.Value)
		if remove {
			u.ExternalID = ""
		}
	case "displayname":
		u.DisplayName, err = str(op.Path, op.Value)
		if remove {
			u.DisplayName = ""
		}
	case "name":
		if remove {
			u.Name = nil
			return nil, nil
		}
		var n SCIMName
		if json.Unmarshal(op.Value, &n) != nil {
			return nil, badValue("name must be an object")
		}
		if u.Name == nil {
			u.Name = &SCIMName{}
		}
		if n.Formatted != "" {
			u.Name.Formatted = n.Formatted
		}
		if n.GivenName != "" {
			u.Name.GivenName = n.GivenName
		}
		if n.FamilyName != "" {
			u.Name.FamilyName = n.FamilyName
		}
	case "name.givenname":
		err = setName(func(n *SCIMName, v string) { n.GivenName = v })
	case "name.familyname":
		err = setName(func(n *SCIMName, v string) { n.FamilyName = v })
	case "name.formatted":
		err = setName(func(n *SCIMName, v string) { n.Formatted = v })
	case "emails":
		if remove {
			u.Emails = nil
			return nil, nil
		}
		var in []scimEmailIn
		if json.Unmarshal(op.Value, &in) != nil {
			return nil, badValue("emails must be an array of email objects")
		}
		if op.Op == "replace" {
			u.Emails = nil
		}
		u.Emails = append(u.Emails, emails(in)...)
	default:
		typ, rest, ok := valueFilter(op.Path, "emails", "type")
		rest = strings.ToLower(rest)
		if !ok || (rest != "" && rest != ".value") {
			return []string{op.Path}, nil // an attribute Halos does not keep
		}
		i := slices.IndexFunc(u.Emails, func(e SCIMEmail) bool { return strings.EqualFold(e.Type, typ) })
		if remove {
			u.Emails = slices.DeleteFunc(u.Emails, func(e SCIMEmail) bool { return strings.EqualFold(e.Type, typ) })
			return nil, nil
		}
		if rest != ".value" {
			return nil, &scimFail{http.StatusBadRequest, "invalidPath", "set emails[type eq ...].value"}
		}
		v, err := str(op.Path, op.Value)
		if err != nil {
			return nil, err
		}
		if i < 0 {
			u.Emails = append(u.Emails, SCIMEmail{Value: v, Type: typ})
		} else {
			u.Emails[i].Value = v
		}
	}
	return nil, err
}

// ---- groups ----

func (s *Server) scimListGroups(w http.ResponseWriter, r *http.Request) {
	attr, val, err := parseFilter(r.URL.Query().Get("filter"), "displayname", "externalid", "id")
	if err != nil {
		writeFail(w, err)
		return
	}
	start, count, err := page(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	var match []SCIMGroup
	for _, g := range s.scim.store.Groups() {
		if attr == "" || (attr == "displayname" && strings.EqualFold(g.DisplayName, val)) ||
			(attr == "externalid" && g.ExternalID == val) || (attr == "id" && g.ID == val) {
			match = append(match, g)
		}
	}
	withMembers := !excluded(r, "members")
	var items []any
	for _, g := range pageOf(match, start, count) {
		items = append(items, s.groupOut(r, g, withMembers))
	}
	writeSCIM(w, http.StatusOK, list(len(match), start, items))
}

func (s *Server) writeGroup(w http.ResponseWriter, r *http.Request, code int, g SCIMGroup) {
	out := s.groupOut(r, g, !excluded(r, "members"))
	w.Header().Set("ETag", out.Meta.Version)
	if code == http.StatusCreated {
		w.Header().Set("Location", out.Meta.Location)
	}
	writeSCIM(w, code, out)
}

func (s *Server) scimGetGroup(w http.ResponseWriter, r *http.Request) {
	g, ok := s.scim.store.Group(r.PathValue("id"))
	if !ok {
		scimError(w, http.StatusNotFound, "", "group not found")
		return
	}
	s.writeGroup(w, r, http.StatusOK, g)
}

func memberIDs(in []scimMemberIn) []string {
	var out []string
	seen := make(map[string]struct{}, len(in))
	for _, m := range in {
		if _, dup := seen[m.Value]; !dup {
			seen[m.Value] = struct{}{}
			out = append(out, m.Value)
		}
	}
	return out
}

// idSet is ids as a set, for linear membership deltas.
func idSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func (s *Server) scimCreateGroup(w http.ResponseWriter, r *http.Request) {
	var in scimGroupIn
	if err := decodeSCIM(w, r, &in); err != nil {
		writeFail(w, err)
		return
	}
	now := s.cfg.Now().UTC()
	g := SCIMGroup{ID: newUUID(), ExternalID: in.ExternalID, DisplayName: in.DisplayName, Members: memberIDs(in.Members), Created: now, Modified: now}
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	if err := s.commitGroup(r, "scim.group.create", nil, g, nil); err != nil {
		writeFail(w, err)
		return
	}
	s.writeGroup(w, r, http.StatusCreated, g)
}

func (s *Server) loadGroup(r *http.Request) (SCIMGroup, error) {
	g, ok := s.scim.store.Group(r.PathValue("id"))
	if !ok {
		return g, &scimFail{http.StatusNotFound, "", "group not found"}
	}
	if !ifMatch(r, scimVersion(g)) {
		return g, &scimFail{http.StatusPreconditionFailed, "", "If-Match does not match the current version"}
	}
	return g, nil
}

func (s *Server) scimPutGroup(w http.ResponseWriter, r *http.Request) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	old, err := s.loadGroup(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	var in scimGroupIn
	if err := decodeSCIM(w, r, &in); err != nil {
		writeFail(w, err)
		return
	}
	g := SCIMGroup{ID: old.ID, ExternalID: in.ExternalID, DisplayName: in.DisplayName, Members: memberIDs(in.Members), Created: old.Created, Modified: s.cfg.Now().UTC()}
	if err := s.commitGroup(r, "scim.group.replace", &old, g, nil); err != nil {
		writeFail(w, err)
		return
	}
	s.writeGroup(w, r, http.StatusOK, g)
}

// scimPatchGroup: Okta and Entra ID both change membership with PATCH
// (add/remove "members", remove `members[value eq "id"]`).
func (s *Server) scimPatchGroup(w http.ResponseWriter, r *http.Request) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	old, err := s.loadGroup(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	ops, err := decodePatch(w, r)
	if err != nil {
		writeFail(w, err)
		return
	}
	g := old
	g.Members = slices.Clone(old.Members)
	var ignored []string
	for _, op := range ops {
		ig, err := patchGroup(&g, op)
		if err != nil {
			writeFail(w, err)
			return
		}
		ignored = append(ignored, ig...)
	}
	g.Modified = s.cfg.Now().UTC()
	if err := s.commitGroup(r, "scim.group.patch", &old, g, ignored); err != nil {
		writeFail(w, err)
		return
	}
	s.writeGroup(w, r, http.StatusOK, g)
}

func (s *Server) scimDeleteGroup(w http.ResponseWriter, r *http.Request) {
	s.scim.mu.Lock()
	defer s.scim.mu.Unlock()
	g, err := s.loadGroup(r)
	if err != nil {
		writeFail(w, err)
		return
	}
	if err := s.scim.store.DeleteGroup(g.ID); err != nil {
		s.cfg.Log.Error("scim store", "group", g.DisplayName, "err", err)
		writeFail(w, err)
		return
	}
	if err := s.AuditStrict(r.Context(), scimActor, "scim.group.delete", g.DisplayName,
		map[string]string{"id": g.ID, "members": strconv.Itoa(len(g.Members))}); err != nil {
		scimError(w, http.StatusInternalServerError, "", errAuditFailed) // the delete itself is in force
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// commitGroup validates g (unique displayName, members are provisioned users),
// persists it and audits the membership delta. Callers hold s.scim.mu.
func (s *Server) commitGroup(r *http.Request, action string, old *SCIMGroup, g SCIMGroup, ignored []string) error {
	if err := s.validGroup(g); err != nil {
		return err
	}
	for _, o := range s.scim.store.Groups() {
		if o.ID != g.ID && strings.EqualFold(o.DisplayName, g.DisplayName) {
			return &scimFail{http.StatusConflict, "uniqueness", "displayName is already provisioned"}
		}
	}
	var before []string
	details := map[string]string{"id": g.ID}
	if old != nil {
		before = old.Members
		if old.DisplayName != g.DisplayName {
			details["previousDisplayName"] = old.DisplayName
		}
	}
	if added := s.userNames(g.Members, before); added != "" {
		details["added"] = added
	}
	if removed := s.userNames(before, g.Members); removed != "" {
		details["removed"] = removed
	}
	if len(ignored) > 0 {
		details["ignoredAttributes"] = strings.Join(ignored, ",")
	}
	if err := s.scim.store.PutGroup(g); err != nil {
		s.cfg.Log.Error("scim store", "group", g.DisplayName, "err", err)
		return err
	}
	s.cfg.Log.Info("scim group", "action", action, "group", g.DisplayName, "members", len(g.Members))
	if err := s.AuditStrict(r.Context(), scimActor, action, g.DisplayName, details); err != nil {
		return &scimFail{http.StatusInternalServerError, "", errAuditFailed} // the change itself is in force
	}
	return nil
}

// userNames lists the userNames of ids in a but not in b.
// ponytail: a membership delta of thousands makes one long audit detail; summarise if that hurts SIEM ingestion.
func (s *Server) userNames(a, b []string) string {
	var out []string
	inB := idSet(b)
	for _, id := range a {
		if _, ok := inB[id]; !ok {
			name := id
			if u, ok := s.scim.store.User(id); ok {
				name = u.UserName
			}
			out = append(out, name)
		}
	}
	return strings.Join(out, ",")
}

func patchGroup(g *SCIMGroup, op scimOp) ([]string, error) {
	if strings.TrimSpace(op.Path) == "" {
		ops, err := objectOps(op)
		if err != nil {
			return nil, err
		}
		var ignored []string
		for _, o := range ops {
			ig, err := patchGroup(g, o)
			if err != nil {
				return nil, err
			}
			ignored = append(ignored, ig...)
		}
		return ignored, nil
	}
	path := patchPath(op.Path)
	remove := op.Op == "remove"
	var err error
	switch path {
	case "displayname":
		if remove {
			return nil, &scimFail{http.StatusBadRequest, "mutability", "displayName cannot be removed"}
		}
		g.DisplayName, err = str(op.Path, op.Value)
	case "externalid":
		g.ExternalID, err = str(op.Path, op.Value)
		if remove {
			g.ExternalID = ""
		}
	case "members":
		if remove && isNull(op.Value) {
			g.Members = nil
			return nil, nil
		}
		ids, err := members(op.Value)
		if err != nil {
			return nil, err
		}
		switch op.Op {
		case "replace":
			g.Members = ids
		case "add":
			have := idSet(g.Members)
			for _, id := range ids {
				if _, ok := have[id]; !ok {
					g.Members = append(g.Members, id)
				}
			}
		case "remove":
			drop := idSet(ids)
			g.Members = slices.DeleteFunc(g.Members, func(m string) bool { _, ok := drop[m]; return ok })
		}
	default:
		id, rest, ok := valueFilter(op.Path, "members", "value")
		if !ok {
			return []string{op.Path}, nil // an attribute Halos does not keep
		}
		if !remove || rest != "" {
			return nil, &scimFail{http.StatusBadRequest, "invalidPath", `only remove is supported on members[value eq "..."]`}
		}
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == id })
	}
	return nil, err
}

// members decodes a members value: an array of {"value": id}, or a single
// object (some clients send one member unwrapped).
func members(raw json.RawMessage) ([]string, error) {
	var in []scimMemberIn
	if err := json.Unmarshal(raw, &in); err != nil {
		var one scimMemberIn
		if json.Unmarshal(raw, &one) != nil {
			return nil, badValue(`members must be an array of {"value": "<user id>"}`)
		}
		in = []scimMemberIn{one}
	}
	for _, m := range in {
		if m.Value == "" {
			return nil, badValue("a member needs a value (the user id)")
		}
	}
	return memberIDs(in), nil
}

// ---- discovery (RFC 7644 §4) ----

func (s *Server) scimSPC(w http.ResponseWriter, r *http.Request) {
	sup := func(b bool) map[string]bool { return map[string]bool{"supported": b} }
	writeSCIM(w, http.StatusOK, map[string]any{
		"schemas":          []string{scimSPCSchema},
		"documentationUri": "https://github.com/dshakes/halos/blob/main/docs/src/content/docs/guides/scim-provisioning.md",
		"patch":            sup(true),
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": scimMaxResults},
		"changePassword":   sup(false),
		"sort":             sup(false),
		"etag":             sup(true),
		"authenticationSchemes": []map[string]any{{
			"type": "oauthbearertoken", "name": "Bearer token", "primary": true,
			"description": "A dedicated SCIM bearer token; halo-server stores only its SHA-256.",
		}},
		"meta": map[string]string{"resourceType": "ServiceProviderConfig", "location": s.baseURL(r) + "/scim/v2/ServiceProviderConfig"},
	})
}

func (s *Server) scimResourceTypes(w http.ResponseWriter, r *http.Request) {
	rt := func(name, endpoint, schema string) map[string]any {
		return map[string]any{"schemas": []string{scimRTSchema}, "id": name, "name": name, "endpoint": endpoint, "schema": schema,
			"meta": map[string]string{"resourceType": "ResourceType", "location": s.baseURL(r) + "/scim/v2/ResourceTypes/" + name}}
	}
	all := []map[string]any{rt("User", "/Users", scimUserSchema), rt("Group", "/Groups", scimGroupSchema)}
	discovery(w, r, all)
}

type scimAttr struct {
	Name          string     `json:"name"`
	Type          string     `json:"type"`
	MultiValued   bool       `json:"multiValued"`
	Required      bool       `json:"required"`
	CaseExact     bool       `json:"caseExact"`
	Mutability    string     `json:"mutability"`
	Returned      string     `json:"returned"`
	Uniqueness    string     `json:"uniqueness"`
	SubAttributes []scimAttr `json:"subAttributes,omitempty"`
}

func strAttr(name string) scimAttr {
	return scimAttr{Name: name, Type: "string", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
}

func (s *Server) scimSchemas(w http.ResponseWriter, r *http.Request) {
	userName := strAttr("userName")
	userName.Required, userName.Uniqueness = true, "server"
	active := scimAttr{Name: "active", Type: "boolean", Mutability: "readWrite", Returned: "default", Uniqueness: "none"}
	primary := active
	primary.Name = "primary"
	emailsAttr := scimAttr{Name: "emails", Type: "complex", MultiValued: true, Mutability: "readWrite", Returned: "default", Uniqueness: "none",
		SubAttributes: []scimAttr{strAttr("value"), strAttr("type"), primary}}
	name := scimAttr{Name: "name", Type: "complex", Mutability: "readWrite", Returned: "default", Uniqueness: "none",
		SubAttributes: []scimAttr{strAttr("formatted"), strAttr("givenName"), strAttr("familyName")}}
	ref := func(n, mut string) scimAttr {
		value := strAttr("value")
		value.CaseExact, value.Mutability = true, mut
		display := strAttr("display")
		display.Mutability = "readOnly"
		return scimAttr{Name: n, Type: "complex", MultiValued: true, Mutability: mut, Returned: "default", Uniqueness: "none",
			SubAttributes: []scimAttr{value, display}}
	}
	externalID := strAttr("externalId")
	externalID.CaseExact = true
	groupName := strAttr("displayName")
	groupName.Required, groupName.Uniqueness = true, "server"
	schema := func(id, name, desc string, attrs []scimAttr) map[string]any {
		return map[string]any{"schemas": []string{scimSchemaSchema}, "id": id, "name": name, "description": desc, "attributes": attrs,
			"meta": map[string]string{"resourceType": "Schema", "location": s.baseURL(r) + "/scim/v2/Schemas/" + id}}
	}
	all := []map[string]any{
		schema(scimUserSchema, "User", "User account (the attributes Halos keeps; others are accepted and ignored)",
			[]scimAttr{userName, externalID, name, strAttr("displayName"), emailsAttr, active, ref("groups", "readOnly")}),
		schema(scimGroupSchema, "Group", "Group; policy refers to it by displayName",
			[]scimAttr{groupName, externalID, ref("members", "readWrite")}),
	}
	discovery(w, r, all)
}

// discovery answers a discovery list, or one entry when the path names an id.
func discovery(w http.ResponseWriter, r *http.Request, all []map[string]any) {
	id := r.PathValue("id")
	if id == "" {
		items := make([]any, len(all))
		for i, a := range all {
			items[i] = a
		}
		writeSCIM(w, http.StatusOK, list(len(items), 1, items))
		return
	}
	for _, a := range all {
		if a["id"] == id {
			writeSCIM(w, http.StatusOK, a)
			return
		}
	}
	scimError(w, http.StatusNotFound, "", "not found")
}
