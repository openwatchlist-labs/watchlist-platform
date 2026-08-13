package reviewauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

func LoadRegistry(path string) (Registry, error) {
	var r Registry
	b, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&r); e != nil {
		return r, e
	}
	if e = VerifyRegistry(r); e != nil {
		return r, e
	}
	r.buildIndex()
	return r, nil
}
func VerifyRegistry(r Registry) error {
	if r.SchemaVersion != RegistrySchemaV1 {
		return errors.New("unsupported identity registry schema")
	}
	if r.RegistryID == "" || r.Version == "" || len(r.Roles) == 0 || len(r.Users) == 0 {
		return errors.New("registry identity, version, roles, and users are required")
	}
	rs := map[string]Role{}
	for _, x := range r.Roles {
		if x.RoleID == "" || len(x.Permissions) == 0 {
			return errors.New("role_id and permissions are required")
		}
		if _, ok := rs[x.RoleID]; ok {
			return fmt.Errorf("duplicate role %q", x.RoleID)
		}
		if !sort.StringsAreSorted(x.Permissions) {
			return fmt.Errorf("role %s permissions must be sorted", x.RoleID)
		}
		rs[x.RoleID] = x
	}
	us := map[string]struct{}{}
	for _, u := range r.Users {
		if u.UserID == "" || u.DisplayName == "" || u.SessionEpoch == 0 {
			return errors.New("user_id, display_name, and positive session_epoch are required")
		}
		if _, ok := us[u.UserID]; ok {
			return fmt.Errorf("duplicate user %q", u.UserID)
		}
		us[u.UserID] = struct{}{}
		if len(u.Bindings) == 0 {
			return fmt.Errorf("user %s has no bindings", u.UserID)
		}
		seen := map[string]struct{}{}
		for _, b := range u.Bindings {
			if b.TenantID == "" || len(b.Roles) == 0 {
				return fmt.Errorf("user %s has invalid binding", u.UserID)
			}
			if _, ok := seen[b.TenantID]; ok {
				return fmt.Errorf("user %s has duplicate tenant binding", u.UserID)
			}
			seen[b.TenantID] = struct{}{}
			if !sort.StringsAreSorted(b.Roles) {
				return fmt.Errorf("user %s roles must be sorted", u.UserID)
			}
			for _, id := range b.Roles {
				if _, ok := rs[id]; !ok {
					return fmt.Errorf("user %s references unknown role %s", u.UserID, id)
				}
			}
		}
	}
	c := r
	want := c.RegistrySHA256
	c.RegistrySHA256 = ""
	got, e := HashObject(c)
	if e != nil {
		return e
	}
	if want == "" || want != got {
		return fmt.Errorf("identity registry checksum mismatch: expected %s actual %s", want, got)
	}
	return nil
}

// buildIndex populates userIndex/roleIndex so User() and Role() become O(1)
// lookups. The maps hold slice positions rather than copies of User/Role
// values: User()/Role() re-read r.Users[i]/r.Roles[i] on every call, so an
// in-place mutation to an existing entry (as several tests do, to simulate
// session revocation or binding removal without a full registry reload) is
// observed identically to the original linear scan. Storing value copies
// instead would silently freeze fields like SessionEpoch at build time and
// break revocation -- this was caught by go test -race turning up a real
// failure (TestScreeningAuthTokenLifecycleRejections/revoked_session_epoch)
// during development of this change.
//
// buildIndex must only be called synchronously, before the Registry value
// is shared with any concurrent reader: LoadRegistry and NewTokenService
// both call it once, right after VerifyRegistry succeeds, which is every
// construction path that feeds the token verification hot path
// (Parse -> User -> RolesFor). Registry values built by other means (e.g.
// struct literals used directly in tests) are left unindexed; User()/Role()
// fall back to the original linear scan for those, so behavior is
// identical either way -- only the indexed path is O(1).
func (r *Registry) buildIndex() {
	r.userIndex = make(map[string]int, len(r.Users))
	for i, u := range r.Users {
		r.userIndex[u.UserID] = i
	}
	r.roleIndex = make(map[string]int, len(r.Roles))
	for i, x := range r.Roles {
		r.roleIndex[x.RoleID] = i
	}
}
func (r Registry) User(id string) (User, bool) {
	if r.userIndex != nil {
		i, ok := r.userIndex[id]
		if !ok {
			return User{}, false
		}
		return r.Users[i], true
	}
	for _, u := range r.Users {
		if u.UserID == id {
			return u, true
		}
	}
	return User{}, false
}
func (r Registry) Role(id string) (Role, bool) {
	if r.roleIndex != nil {
		i, ok := r.roleIndex[id]
		if !ok {
			return Role{}, false
		}
		return r.Roles[i], true
	}
	for _, x := range r.Roles {
		if x.RoleID == id {
			return x, true
		}
	}
	return Role{}, false
}
func (r Registry) RolesFor(u User, tenant string) ([]string, error) {
	m := map[string]struct{}{}
	for _, b := range u.Bindings {
		if b.TenantID == tenant || b.TenantID == "*" {
			for _, x := range b.Roles {
				m[x] = struct{}{}
			}
		}
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("user %s has no role binding for tenant %s", u.UserID, tenant)
	}
	o := make([]string, 0, len(m))
	for x := range m {
		o = append(o, x)
	}
	sort.Strings(o)
	return o, nil
}
func (r Registry) Permissions(roles []string) []string {
	m := map[string]struct{}{}
	for _, id := range roles {
		if x, ok := r.Role(id); ok {
			for _, p := range x.Permissions {
				m[p] = struct{}{}
			}
		}
	}
	o := make([]string, 0, len(m))
	for p := range m {
		o = append(o, p)
	}
	sort.Strings(o)
	return o
}

// resourcePermissions is the closed, enumerable set of concrete permission
// strings this system checks, grouped by the resource a "resource.*" grant
// in a role's permission list expands to. It must track every permission
// string actually tested by internal/reviewconsoleapi (see
// actionPermission and the permit(...) call sites in server.go) and every
// concrete permission listed in configs/**/identity-registry*.json. A
// "resource.*" grant is scoped to exactly this set -- not to any need
// string that happens to share the "resource." prefix, which would also
// match a permission string that doesn't exist yet or was never intended
// to be covered by the wildcard.
var resourcePermissions = map[string][]string{
	"alert":      {"alert.read"},
	"assistance": {"assistance.read", "assistance.request", "assistance.review"},
	"case":       {"case.assign_any", "case.assign_self", "case.create", "case.investigate", "case.read", "case.reopen", "case.rescreen"},
	"decision":   {"decision.approve", "decision.propose"},
	"evidence":   {"evidence.request", "evidence.submit"},
}

func PermissionAllowed(g []string, need string) bool {
	for _, p := range g {
		if p == "*" || p == need {
			return true
		}
		if strings.HasSuffix(p, ".*") {
			resource := strings.TrimSuffix(p, ".*")
			for _, m := range resourcePermissions[resource] {
				if m == need {
					return true
				}
			}
		}
	}
	return false
}
