package authz

import (
	"slices"
	"testing"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

// fixture: resource "album" with scopes view / delete, a role policy, a
// user policy and permissions on them.
func fixture() *Data {
	view := &model.AuthzScope{ID: "s-view", Name: "view"}
	del := &model.AuthzScope{ID: "s-delete", Name: "delete"}
	album := &model.AuthzResource{ID: "r-album", Name: "album", Type: "urn:album", Owner: "rs", ScopeIDs: []string{"s-view", "s-delete"}}
	doc := &model.AuthzResource{ID: "r-doc", Name: "doc", Type: "urn:doc", Owner: "rs"}
	d := &Data{
		Server:    &model.ResourceServer{ClientID: "rs", PolicyEnforcementMode: Enforcing, DecisionStrategy: Unanimous},
		Resources: []*model.AuthzResource{album, doc},
		Scopes:    []*model.AuthzScope{view, del},
		Policies: []*model.AuthzPolicy{
			{ID: "p-role", Name: "users", Type: "role", Logic: Positive, Config: map[string]string{"roles": `[{"id":"role-user","required":false}]`}},
			{ID: "p-alice", Name: "alice", Type: "user", Logic: Positive, Config: map[string]string{"users": `["alice"]`}},
			{ID: "perm-view", Name: "view albums", Type: TypeScope, Logic: Positive, DecisionStrategy: Unanimous,
				ResourceIDs: []string{"r-album"}, ScopeIDs: []string{"s-view"}, AssociatedIDs: []string{"p-role"}},
			{ID: "perm-delete", Name: "delete albums", Type: TypeScope, Logic: Positive, DecisionStrategy: Unanimous,
				ScopeIDs: []string{"s-delete"}, AssociatedIDs: []string{"p-alice"}},
		},
	}
	d.Index()
	return d
}

func identity(user string, roles ...string) *Identity {
	id := &Identity{UserID: user, Roles: map[string]bool{}, ClientScopes: map[string]bool{}, Now: time.Date(2026, 6, 15, 10, 30, 0, 0, time.Local)}
	for _, r := range roles {
		id.Roles[r] = true
	}
	return id
}

func granted(res *Result) []string {
	var out []string
	for _, s := range res.Granted {
		out = append(out, s.Name)
	}
	return out
}

func TestScopePermissions(t *testing.T) {
	d := fixture()
	res := Evaluate(d, identity("bob", "role-user"), []Requested{{ResourceID: "r-album"}})[0]
	if !slices.Equal(granted(res), []string{"view"}) || !res.Allowed {
		t.Fatalf("bob: %v", granted(res))
	}
	res = Evaluate(d, identity("alice", "role-user"), []Requested{{ResourceID: "r-album"}})[0]
	if !slices.Equal(granted(res), []string{"view", "delete"}) {
		t.Fatalf("alice: %v", granted(res))
	}
	res = Evaluate(d, identity("eve"), []Requested{{ResourceID: "r-album"}})[0]
	if res.Allowed {
		t.Fatalf("eve: %v", granted(res))
	}
	// scope only request
	results := Evaluate(d, identity("alice"), []Requested{{Scopes: []string{"s-delete"}}})
	if len(results) != 1 || !slices.Equal(granted(results[0]), []string{"delete"}) {
		t.Fatalf("scope request: %+v", results)
	}
	// a resource without permissions is denied when enforcing, granted when permissive
	if Evaluate(d, identity("alice"), []Requested{{ResourceID: "r-doc"}})[0].Allowed {
		t.Fatal("doc allowed while enforcing")
	}
	d.Server.PolicyEnforcementMode = Permissive
	if !Evaluate(d, identity("alice"), []Requested{{ResourceID: "r-doc"}})[0].Allowed {
		t.Fatal("doc denied while permissive")
	}
}

func TestDecisionStrategiesAndLogic(t *testing.T) {
	d := fixture()
	// a second permission on view that denies bob
	d.Policies = append(d.Policies, &model.AuthzPolicy{ID: "perm-view2", Name: "view by alice", Type: TypeScope, Logic: Positive,
		DecisionStrategy: Unanimous, ScopeIDs: []string{"s-view"}, AssociatedIDs: []string{"p-alice"}})
	d.Index()
	bob := identity("bob", "role-user")
	if res := Evaluate(d, bob, []Requested{{ResourceID: "r-album", Scopes: []string{"s-view"}}})[0]; res.Allowed {
		t.Fatal("unanimous: bob allowed")
	}
	d.Server.DecisionStrategy = Affirmative
	if res := Evaluate(d, bob, []Requested{{ResourceID: "r-album", Scopes: []string{"s-view"}}})[0]; !res.Allowed {
		t.Fatal("affirmative: bob denied")
	}
	d.Server.DecisionStrategy = Consensus
	if res := Evaluate(d, bob, []Requested{{ResourceID: "r-album", Scopes: []string{"s-view"}}})[0]; res.Allowed {
		t.Fatal("consensus 1-1: bob allowed")
	}
	// negative logic inverts a policy
	d.Server.DecisionStrategy = Unanimous
	d.Policy("p-alice").Logic = Negative
	if res := Evaluate(d, bob, []Requested{{ResourceID: "r-album", Scopes: []string{"s-view"}}})[0]; !res.Allowed {
		t.Fatal("negative alice policy: bob denied")
	}
	// an affirmative permission over two policies
	d.Policy("perm-delete").DecisionStrategy = Affirmative
	d.Policy("perm-delete").AssociatedIDs = []string{"p-alice", "p-role"}
	if res := Evaluate(d, identity("carol", "role-user"), []Requested{{ResourceID: "r-album", Scopes: []string{"s-delete"}}})[0]; !res.Allowed {
		t.Fatal("affirmative permission denied")
	}
}

func TestResourcePermissionsOwnersAndTickets(t *testing.T) {
	d := fixture()
	d.Policies = append(d.Policies, &model.AuthzPolicy{ID: "perm-docs", Name: "docs", Type: TypeResource, Logic: Positive,
		DecisionStrategy: Unanimous, Config: map[string]string{"defaultResourceType": "urn:doc"}, AssociatedIDs: []string{"p-role"}})
	d.Resources = append(d.Resources, &model.AuthzResource{ID: "r-mine", Name: "mine", Type: "urn:doc", Owner: "dave", OwnerManagedAccess: true})
	d.Index()
	if !Evaluate(d, identity("bob", "role-user"), []Requested{{ResourceID: "r-doc"}})[0].Allowed {
		t.Fatal("typed resource permission")
	}
	if !Evaluate(d, identity("dave"), []Requested{{ResourceID: "r-mine"}})[0].Allowed {
		t.Fatal("owner denied")
	}
	if Evaluate(d, identity("eve"), []Requested{{ResourceID: "r-mine"}})[0].Allowed {
		t.Fatal("eve allowed")
	}
	d.Tickets = []*model.PermissionTicket{{ResourceID: "r-mine", Requester: "eve", Owner: "dave", GrantedTimestamp: 1}}
	if !Evaluate(d, identity("eve"), []Requested{{ResourceID: "r-mine"}})[0].Allowed {
		t.Fatal("granted ticket denied")
	}
	// disabled enforcement grants everything
	d.Server.PolicyEnforcementMode = Disabled
	if !Evaluate(d, identity("eve"), []Requested{{ResourceID: "r-album"}})[0].Allowed {
		t.Fatal("disabled enforcement")
	}
	// entitlement: every resource (typed permissions cover user owned
	// resources of the type too)
	d.Server.PolicyEnforcementMode = Enforcing
	perms := Permissions(Evaluate(d, identity("bob", "role-user"), nil), true)
	if len(perms) != 3 {
		t.Fatalf("entitlement: %+v", perms)
	}
}

func TestRules(t *testing.T) {
	id := identity("alice", "r1")
	id.Groups = []Group{{ID: "g-dev", Path: "/eng/dev"}}
	id.ClientID = "c1"
	id.ClientScopes["cs-email"] = true
	id.Claims = map[string]any{"email": "alice@example.org", "org": map[string]any{"units": []any{"eng", "ops"}}}
	id.Attributes = map[string][]string{"ip": {"10.0.0.7"}}
	for _, tc := range []struct {
		name string
		p    *model.AuthzPolicy
		want bool
	}{
		{"role required missing", &model.AuthzPolicy{Type: "role", Config: map[string]string{"roles": `[{"id":"r1"},{"id":"r2","required":true}]`}}, false},
		{"role", &model.AuthzPolicy{Type: "role", Config: map[string]string{"roles": `[{"id":"r1"},{"id":"r2"}]`}}, true},
		{"group exact", &model.AuthzPolicy{Type: "group", Config: map[string]string{"groups": `[{"id":"g-dev"}]`}}, true},
		{"group parent", &model.AuthzPolicy{Type: "group", Config: map[string]string{"groups": `[{"id":"g-eng","path":"/eng"}]`}}, false},
		{"group parent extended", &model.AuthzPolicy{Type: "group", Config: map[string]string{"groups": `[{"id":"g-eng","path":"/eng","extendChildren":true}]`}}, true},
		{"client", &model.AuthzPolicy{Type: "client", Config: map[string]string{"clients": `["c1"]`}}, true},
		{"client scope", &model.AuthzPolicy{Type: "client-scope", Config: map[string]string{"clientScopes": `[{"id":"cs-email","required":true}]`}}, true},
		{"time window", &model.AuthzPolicy{Type: "time", Config: map[string]string{"hour": "9", "hourEnd": "17"}}, true},
		{"time after", &model.AuthzPolicy{Type: "time", Config: map[string]string{"nbf": "2027-01-01 00:00:00"}}, false},
		{"regex claim", &model.AuthzPolicy{Type: "regex", Config: map[string]string{"targetClaim": "email", "pattern": ".*@example\\.org"}}, true},
		{"regex nested", &model.AuthzPolicy{Type: "regex", Config: map[string]string{"targetClaim": "org.units", "pattern": "ops"}}, true},
		{"regex context", &model.AuthzPolicy{Type: "regex", Config: map[string]string{"targetClaim": "ip", "pattern": "10\\..*", "targetContextAttributes": "true"}}, true},
		{"default js", &model.AuthzPolicy{Type: "js", Config: map[string]string{"code": DefaultPolicyCode}}, true},
		{"other js", &model.AuthzPolicy{Type: "js", Config: map[string]string{"code": "$evaluation.deny();"}}, false},
	} {
		if got := evaluateRule(id, tc.p); got != tc.want {
			t.Errorf("%s: got %v", tc.name, got)
		}
	}
}

func TestMerge(t *testing.T) {
	got := Merge([]Permission{{ResourceID: "a", Scopes: []string{"x"}}}, []Permission{{ResourceID: "a", Scopes: []string{"y"}}, {ResourceID: "b"}})
	if len(got) != 2 || !slices.Equal(got[0].Scopes, []string{"x", "y"}) {
		t.Fatalf("merge: %+v", got)
	}
}
