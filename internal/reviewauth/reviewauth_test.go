package reviewauth

import (
	"testing"
	"time"
)

func reg() Registry {
	r := Registry{SchemaVersion: RegistrySchemaV1, RegistryID: "t", Version: "r1", Roles: []Role{{RoleID: "analyst", Permissions: []string{"case.read"}}}, Users: []User{{UserID: "alice", DisplayName: "Alice", Active: true, SessionEpoch: 1, Bindings: []RoleBinding{{TenantID: "tenant-a", Roles: []string{"analyst"}}}}}}
	h, _ := HashObject(r)
	r.RegistrySHA256 = h
	return r
}
func TestToken(t *testing.T) {
	s, e := NewTokenService(reg(), []byte("01234567890123456789012345678901"), time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	n := time.Now().UTC()
	tok, _, e := s.Issue("alice", "tenant-a", time.Minute, n)
	if e != nil {
		t.Fatal(e)
	}
	c, e := s.Parse(tok, n)
	if e != nil || c.Subject != "alice" {
		t.Fatal(e, c)
	}
	if _, e = s.Parse(tok, n.Add(2*time.Minute)); e == nil {
		t.Fatal("expected expiry")
	}
}

// SEC-11: "case.*" must expand to exactly the defined case.* permissions,
// not to any need string that happens to share the "case." prefix. Before
// the fix, a made-up permission that was never granted to any role --
// "case.destroy_all" -- passed PermissionAllowed purely because it starts
// with "case.". That is not a real, intended member of the case.* scope
// (see the case.* enumeration in configs/release/identity-registry.json
// and internal/reviewconsoleapi/server.go's actionPermission), so it must
// be denied.
func TestPermissionAllowedWildcardDoesNotPrefixMatch(t *testing.T) {
	g := []string{"case.*"}
	if !PermissionAllowed(g, "case.read") {
		t.Fatal("case.* must still grant a real member permission, case.read")
	}
	if !PermissionAllowed(g, "case.rescreen") {
		t.Fatal("case.* must still grant a real member permission, case.rescreen")
	}
	if PermissionAllowed(g, "case.destroy_all") {
		t.Fatal("case.* incorrectly granted case.destroy_all, which is not a defined case permission -- prefix match, not scope membership")
	}
	if PermissionAllowed(g, "case.") {
		t.Fatal("case.* incorrectly granted the bare prefix \"case.\"")
	}
}

func TestPermissionAllowedNonWildcardExact(t *testing.T) {
	g := []string{"case.read"}
	if !PermissionAllowed(g, "case.read") {
		t.Fatal("exact permission must be granted")
	}
	if PermissionAllowed(g, "case.rescreen") {
		t.Fatal("a non-wildcard grant must not match a different permission")
	}
}

func TestPermissionAllowedSuperWildcard(t *testing.T) {
	if !PermissionAllowed([]string{"*"}, "case.destroy_all") {
		t.Fatal("the bare \"*\" grant must still allow any permission, defined or not")
	}
}
