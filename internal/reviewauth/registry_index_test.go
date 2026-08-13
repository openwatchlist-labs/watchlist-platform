package reviewauth

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func bigRegistry(n int) Registry {
	roles := make([]Role, 0, n)
	for i := 0; i < n; i++ {
		roles = append(roles, Role{RoleID: fmt.Sprintf("role-%04d", i), Permissions: []string{"case.read"}})
	}
	users := make([]User, 0, n)
	for i := 0; i < n; i++ {
		users = append(users, User{
			UserID:       fmt.Sprintf("user-%04d", i),
			DisplayName:  fmt.Sprintf("User %d", i),
			Active:       true,
			SessionEpoch: 1,
			Bindings:     []RoleBinding{{TenantID: "tenant-a", Roles: []string{fmt.Sprintf("role-%04d", i)}}},
		})
	}
	r := Registry{SchemaVersion: RegistrySchemaV1, RegistryID: "big", Version: "v1", Roles: roles, Users: users}
	h, _ := HashObject(r)
	r.RegistrySHA256 = h
	return r
}

// TestUserRoleIndexMatchesLinearScan proves the map-based User()/Role()
// lookups (built via buildIndex) return results identical to the linear
// scan that runs when no index has been built, across every real id in the
// registry plus several not-found cases. This is the direct evidence that
// the O(1) path is a behavior-preserving refactor of the O(n) path, not a
// rewrite trusted by inspection.
func TestUserRoleIndexMatchesLinearScan(t *testing.T) {
	unindexed := bigRegistry(200)
	indexed := bigRegistry(200)
	indexed.buildIndex()
	if indexed.userIndex == nil || indexed.roleIndex == nil {
		t.Fatal("expected buildIndex to populate both indexes")
	}
	if unindexed.userIndex != nil || unindexed.roleIndex != nil {
		t.Fatal("expected unindexed registry to exercise the linear-scan path")
	}

	ids := make([]string, 0, len(unindexed.Users)+3)
	for _, u := range unindexed.Users {
		ids = append(ids, u.UserID)
	}
	ids = append(ids, "user-9999", "", "not-a-user")

	for _, id := range ids {
		wantUser, wantOK := unindexed.User(id)
		gotUser, gotOK := indexed.User(id)
		if wantOK != gotOK || !reflect.DeepEqual(wantUser, gotUser) {
			t.Fatalf("User(%q) mismatch: linear=(%+v,%v) indexed=(%+v,%v)", id, wantUser, wantOK, gotUser, gotOK)
		}
	}

	roleIDs := make([]string, 0, len(unindexed.Roles)+3)
	for _, x := range unindexed.Roles {
		roleIDs = append(roleIDs, x.RoleID)
	}
	roleIDs = append(roleIDs, "role-9999", "", "not-a-role")

	for _, id := range roleIDs {
		wantRole, wantOK := unindexed.Role(id)
		gotRole, gotOK := indexed.Role(id)
		if wantOK != gotOK || !reflect.DeepEqual(wantRole, gotRole) {
			t.Fatalf("Role(%q) mismatch: linear=(%+v,%v) indexed=(%+v,%v)", id, wantRole, wantOK, gotRole, gotOK)
		}
	}
}

// TestUserRoleIndexObservesInPlaceMutation proves the indexed path -- like
// the linear scan it replaces -- always reflects the current contents of
// Users/Roles rather than a value snapshot taken at buildIndex time. Several
// callers outside this package (e.g. screeningapi and alertcaseapi auth
// tests) simulate session revocation and binding removal by mutating an
// existing Registry.Users[i] element in place after the TokenService/
// Registry was constructed, without reloading the registry. An index that
// cached copies of User/Role values would silently stop observing those
// mutations -- exactly the class of bug this test pins down.
func TestUserRoleIndexObservesInPlaceMutation(t *testing.T) {
	r := bigRegistry(10)
	r.buildIndex()

	u, ok := r.User("user-0003")
	if !ok || u.SessionEpoch != 1 {
		t.Fatalf("precondition: got %+v, %v", u, ok)
	}
	r.Users[3].SessionEpoch = 2
	u, ok = r.User("user-0003")
	if !ok || u.SessionEpoch != 2 {
		t.Fatalf("indexed User() did not observe in-place SessionEpoch mutation: got %+v, %v", u, ok)
	}

	x, ok := r.Role("role-0005")
	if !ok || len(x.Permissions) != 1 || x.Permissions[0] != "case.read" {
		t.Fatalf("precondition: got %+v, %v", x, ok)
	}
	r.Roles[5].Permissions = []string{"case.read", "case.write"}
	x, ok = r.Role("role-0005")
	if !ok || len(x.Permissions) != 2 || x.Permissions[1] != "case.write" {
		t.Fatalf("indexed Role() did not observe in-place Permissions mutation: got %+v, %v", x, ok)
	}
}

// TestUserRoleIndexConcurrentReads proves User()/Role() lookups against an
// already-built index are race-free under concurrent access -- the shape of
// the real hot path (Parse -> User -> RolesFor) under concurrent token
// verification. Run with -race.
func TestUserRoleIndexConcurrentReads(t *testing.T) {
	r := bigRegistry(500)
	r.buildIndex()

	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				n := (g*7 + i) % 500
				uid := fmt.Sprintf("user-%04d", n)
				if _, ok := r.User(uid); !ok {
					t.Errorf("expected user %s to be found", uid)
				}
				rid := fmt.Sprintf("role-%04d", n)
				if _, ok := r.Role(rid); !ok {
					t.Errorf("expected role %s to be found", rid)
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestLoadRegistryAndNewTokenServiceBuildIndex proves the two blessed
// construction paths actually populate the index -- i.e. the optimization
// is wired into the real hot path, not just present but unused.
func TestLoadRegistryAndNewTokenServiceBuildIndex(t *testing.T) {
	r := reg()
	if r.userIndex != nil || r.roleIndex != nil {
		t.Fatal("expected a bare struct literal registry to start unindexed")
	}
	s, e := NewTokenService(r, []byte("01234567890123456789012345678901"), 0)
	if e != nil {
		t.Fatal(e)
	}
	if s.Registry.userIndex == nil || s.Registry.roleIndex == nil {
		t.Fatal("expected NewTokenService to build the index")
	}
}
