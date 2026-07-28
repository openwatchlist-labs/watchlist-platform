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
