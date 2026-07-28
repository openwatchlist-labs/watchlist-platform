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
	return r, VerifyRegistry(r)
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
func (r Registry) User(id string) (User, bool) {
	for _, u := range r.Users {
		if u.UserID == id {
			return u, true
		}
	}
	return User{}, false
}
func (r Registry) Role(id string) (Role, bool) {
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
func PermissionAllowed(g []string, need string) bool {
	for _, p := range g {
		if p == "*" || p == need {
			return true
		}
		if strings.HasSuffix(p, ".*") && strings.HasPrefix(need, strings.TrimSuffix(p, "*")) {
			return true
		}
	}
	return false
}
