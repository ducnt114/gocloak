package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// photoz sets up a photoz-like application: a resource server
// "photoz-restful-api" with album scopes and role based permissions, and
// users alice and bob (role user) and jdoe (roles user and admin).
type photoz struct {
	e     *env
	admin string
	rsID  string
	Z     string
}

func newPhotoz(t *testing.T) *photoz {
	e := newEnv(t)
	admin := e.adminToken()
	R := "/admin/realms/photoz"
	e.expect(e.do(nil, "POST", "/admin/realms", admin, map[string]any{"realm": "photoz", "enabled": true}, nil), 201)
	rsID := idFromLocation(t, e.expect(e.do(nil, "POST", R+"/clients", admin, map[string]any{
		"clientId": "photoz-restful-api", "secret": "secret", "authorizationServicesEnabled": true, "serviceAccountsEnabled": true,
		"directAccessGrantsEnabled": true}, nil), 201))
	e.expect(e.do(nil, "POST", R+"/clients", admin, map[string]any{"clientId": "photoz-html5-client", "publicClient": true,
		"directAccessGrantsEnabled": true}, nil), 201)
	for _, role := range []string{"user", "admin"} {
		e.expect(e.do(nil, "POST", R+"/roles", admin, map[string]any{"name": role}, nil), 201)
	}
	users := map[string][]string{"alice": {"user"}, "bob": {"user"}, "jdoe": {"user", "admin"}}
	for name, roles := range users {
		id := idFromLocation(t, e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": name, "enabled": true,
			"email": name + "@photoz.test", "firstName": name, "lastName": "X",
			"credentials": []map[string]any{{"type": "password", "value": name, "temporary": false}}}, nil), 201))
		var reps []any
		for _, role := range roles {
			var rep map[string]any
			e.expect(e.do(nil, "GET", R+"/roles/"+role, admin, nil, nil), 200).json(&rep)
			reps = append(reps, rep)
		}
		e.expect(e.do(nil, "POST", R+"/users/"+id+"/role-mappings/realm", admin, reps, nil), 204)
	}
	p := &photoz{e: e, admin: admin, rsID: rsID, Z: R + "/clients/" + rsID + "/authz/resource-server"}
	roleID := func(name string) string {
		var rep map[string]any
		e.expect(e.do(nil, "GET", R+"/roles/"+name, admin, nil, nil), 200).json(&rep)
		return rep["id"].(string)
	}
	for _, s := range []string{"album:view", "album:delete"} {
		e.expect(e.do(nil, "POST", p.Z+"/scope", admin, map[string]any{"name": s}, nil), 201)
	}
	var anyUser, onlyAdmin, view map[string]any
	e.expect(e.do(nil, "POST", p.Z+"/policy/role", admin, map[string]any{"name": "Any User Policy",
		"roles": []map[string]any{{"id": roleID("user")}}}, nil), 201).json(&anyUser)
	e.expect(e.do(nil, "POST", p.Z+"/policy/role", admin, map[string]any{"name": "Only Admin Policy",
		"roles": []map[string]any{{"id": roleID("admin"), "required": true}}}, nil), 201).json(&onlyAdmin)
	e.expect(e.do(nil, "GET", p.Z+"/scope/search?name=album:view", admin, nil, nil), 200).json(&view)
	e.expect(e.do(nil, "POST", p.Z+"/permission/resource", admin, map[string]any{"name": "Album Resource Permission",
		"resourceType": "urn:photoz:album", "policies": []string{anyUser["id"].(string)}}, nil), 201)
	e.expect(e.do(nil, "POST", p.Z+"/permission/scope", admin, map[string]any{"name": "Delete Album Permission",
		"scopes": []string{"album:delete"}, "policies": []string{"Only Admin Policy"}}, nil), 201)
	return p
}

func (p *photoz) token(user string) string {
	tk, r := p.e.passwordGrant("photoz", "photoz-html5-client", "", user, user)
	p.e.expect(r, 200)
	return tk.AccessToken
}

func (p *photoz) pat() string {
	var tk tokens
	p.e.expect(p.e.do(nil, "POST", "/realms/photoz/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"photoz-restful-api"}, "client_secret": {"secret"}}), 200).json(&tk)
	return tk.AccessToken
}

// uma asks for permissions with a bearer token.
func (p *photoz) uma(bearer string, form url.Values) *response {
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	return p.e.do(nil, "POST", "/realms/photoz/protocol/openid-connect/token", bearer, nil, form)
}

func rptPermissions(t *testing.T, r *response) map[string][]string {
	t.Helper()
	var tk struct {
		AccessToken string `json:"access_token"`
	}
	r.json(&tk)
	c := claims(t, tk.AccessToken)
	out := map[string][]string{}
	az, _ := c["authorization"].(map[string]any)
	list, _ := az["permissions"].([]any)
	for _, x := range list {
		m := x.(map[string]any)
		out[m["rsname"].(string)] = strs(m["scopes"])
	}
	return out
}

func TestUMAPhotoz(t *testing.T) {
	p := newPhotoz(t)
	e := p.e
	pat := p.pat()

	// the resource server registers albums through the protection API
	reg := func(name, owner string) string {
		var res map[string]any
		e.expect(e.do(nil, "POST", "/realms/photoz/authz/protection/resource_set", pat, map[string]any{
			"name": name, "type": "urn:photoz:album", "owner": owner, "ownerManagedAccess": true,
			"resource_scopes": []string{"album:view", "album:delete"}, "uris": []string{"/album/" + name}}, nil), 201).json(&res)
		return res["_id"].(string)
	}
	aliceAlbum := reg("alice-album", "alice")
	var ids []string
	e.expect(e.do(nil, "GET", "/realms/photoz/authz/protection/resource_set?owner=alice", pat, nil, nil), 200).json(&ids)
	if !slices.Equal(ids, []string{aliceAlbum}) {
		t.Fatalf("resource_set query: %v", ids)
	}
	e.expect(e.do(nil, "GET", "/realms/photoz/authz/protection/resource_set", p.token("alice"), nil, nil), 403)

	alice, bob, jdoe := p.token("alice"), p.token("bob"), p.token("jdoe")
	// alice owns her album
	perms := rptPermissions(t, e.expect(p.uma(alice, url.Values{"audience": {"photoz-restful-api"}, "permission": {"alice-album"}}), 200))
	if !slices.Equal(perms["alice-album"], []string{"album:view", "album:delete"}) {
		t.Fatalf("alice: %v", perms)
	}
	// jdoe: view through the typed permission, delete as admin
	perms = rptPermissions(t, e.expect(p.uma(jdoe, url.Values{"audience": {"photoz-restful-api"}, "permission": {"alice-album"}}), 200))
	if !slices.Equal(perms["alice-album"], []string{"album:view", "album:delete"}) {
		t.Fatalf("jdoe: %v", perms)
	}
	// bob may view but not delete
	var decision map[string]bool
	e.expect(p.uma(bob, url.Values{"audience": {"photoz-restful-api"}, "permission": {"alice-album#album:view"},
		"response_mode": {"decision"}}), 200).json(&decision)
	if !decision["result"] {
		t.Fatal("bob view decision")
	}
	r := e.expect(p.uma(bob, url.Values{"audience": {"photoz-restful-api"}, "permission": {"alice-album#album:delete"}}), 403)
	if !strings.Contains(string(r.body), "not_authorized") {
		t.Fatalf("bob delete: %s", r.body)
	}
	var list []map[string]any
	e.expect(p.uma(bob, url.Values{"audience": {"photoz-restful-api"}, "response_mode": {"permissions"}}), 200).json(&list)
	if len(list) != 2 { // alice-album (view) and the default resource
		t.Fatalf("bob entitlements: %v", list)
	}
	e.expect(p.uma(bob, url.Values{"audience": {"photoz-restful-api"}, "permission": {"nope"}}), 400)
	e.expect(p.uma(bob, url.Values{"response_mode": {"decision"}}), 400)
	e.expect(p.uma("", url.Values{"audience": {"photoz-restful-api"}, "client_id": {"photoz-html5-client"}}), 400)

	// UMA: the resource server gets a ticket, bob asks for delete and
	// submits a request that alice approves
	var ticket map[string]string
	e.expect(e.do(nil, "POST", "/realms/photoz/authz/protection/permission", pat, []map[string]any{
		{"resource_id": aliceAlbum, "resource_scopes": []string{"album:delete"}}}, nil), 201).json(&ticket)
	r = e.expect(p.uma(bob, url.Values{"ticket": {ticket["ticket"]}, "submit_request": {"true"}}), 403)
	if !strings.Contains(string(r.body), "request_submitted") {
		t.Fatalf("submit request: %s", r.body)
	}
	var tickets []map[string]any
	e.expect(e.do(nil, "GET", "/realms/photoz/authz/protection/permission/ticket?granted=false", pat, nil, nil), 200).json(&tickets)
	if len(tickets) != 1 || tickets[0]["requesterName"] != "bob" || tickets[0]["scopeName"] != "album:delete" {
		t.Fatalf("tickets: %v", tickets)
	}
	e.expect(e.do(nil, "PUT", "/realms/photoz/authz/protection/permission/ticket", pat, map[string]any{"id": tickets[0]["id"], "granted": true}, nil), 204)
	r = e.expect(p.uma(bob, url.Values{"ticket": {ticket["ticket"]}}), 200)
	perms = rptPermissions(t, r)
	if !slices.Contains(perms["alice-album"], "album:delete") {
		t.Fatalf("approved request: %v", perms)
	}

	// an RPT is upgraded with new permissions
	var first map[string]any
	e.expect(p.uma(bob, url.Values{"audience": {"photoz-restful-api"}, "permission": {"Default Resource"}}), 200).json(&first)
	r = e.expect(p.uma(bob, url.Values{"audience": {"photoz-restful-api"}, "permission": {"alice-album#album:view"},
		"rpt": {first["access_token"].(string)}}), 200)
	var up map[string]any
	r.json(&up)
	perms = rptPermissions(t, r)
	if up["upgraded"] != true || len(perms) != 2 {
		t.Fatalf("upgrade: %v %v", up["upgraded"], perms)
	}

	// introspection of an RPT carries its permissions
	var intro map[string]any
	e.expect(e.do(nil, "POST", "/realms/photoz/protocol/openid-connect/token/introspect", "", nil, url.Values{
		"token": {up["access_token"].(string)}, "client_id": {"photoz-restful-api"}, "client_secret": {"secret"}}), 200).json(&intro)
	if intro["active"] != true || intro["authorization"] == nil {
		t.Fatalf("introspection: %v", intro)
	}
	var cfg map[string]any
	e.expect(e.do(nil, "GET", "/realms/photoz/.well-known/uma2-configuration", "", nil, nil), 200).json(&cfg)
	if !strings.HasSuffix(cfg["permission_endpoint"].(string), "/authz/protection/permission") {
		t.Fatalf("uma2 configuration: %v", cfg)
	}
}

func TestAuthzAdminAPI(t *testing.T) {
	p := newPhotoz(t)
	e, admin, Z := p.e, p.admin, p.Z

	var rs map[string]any
	e.expect(e.do(nil, "GET", Z, admin, nil, nil), 200).json(&rs)
	if rs["policyEnforcementMode"] != "ENFORCING" || rs["name"] != "photoz-restful-api" {
		t.Fatalf("resource server: %v", rs)
	}
	e.expect(e.do(nil, "PUT", Z, admin, map[string]any{"decisionStrategy": "AFFIRMATIVE"}, nil), 204)
	var res map[string]any
	e.expect(e.do(nil, "POST", Z+"/resource", admin, map[string]any{"name": "Main Page", "type": "urn:photoz:page",
		"scopes": []map[string]string{{"name": "album:view"}}, "uris": []string{"/"}}, nil), 201).json(&res)
	e.expect(e.do(nil, "POST", Z+"/resource", admin, map[string]any{"name": "Main Page"}, nil), 409)
	e.expect(e.do(nil, "POST", Z+"/scope", admin, map[string]any{"name": "album:view"}, nil), 409)
	e.expect(e.do(nil, "POST", Z+"/policy/role", admin, map[string]any{"name": "Any User Policy", "roles": []any{}}, nil), 409)
	e.expect(e.do(nil, "POST", Z+"/policy/js", admin, map[string]any{"name": "custom", "code": "$evaluation.deny();"}, nil), 400)

	var policies []map[string]any
	e.expect(e.do(nil, "GET", Z+"/policy?permission=false", admin, nil, nil), 200).json(&policies)
	names := []string{}
	for _, x := range policies {
		names = append(names, x["name"].(string))
	}
	if !slices.Contains(names, "Any User Policy") || slices.Contains(names, "Delete Album Permission") {
		t.Fatalf("policies: %v", names)
	}
	var typed map[string]any
	var onlyAdmin map[string]any
	e.expect(e.do(nil, "GET", Z+"/policy/search?name=Only%20Admin%20Policy", admin, nil, nil), 200).json(&onlyAdmin)
	e.expect(e.do(nil, "GET", Z+"/policy/role/"+onlyAdmin["id"].(string), admin, nil, nil), 200).json(&typed)
	roles := typed["roles"].([]any)
	if len(roles) != 1 || roles[0].(map[string]any)["required"] != true {
		t.Fatalf("typed role policy: %v", typed)
	}
	var dependent []map[string]any
	e.expect(e.do(nil, "GET", Z+"/policy/"+onlyAdmin["id"].(string)+"/dependentPolicies", admin, nil, nil), 200).json(&dependent)
	if len(dependent) != 1 || dependent[0]["name"] != "Delete Album Permission" {
		t.Fatalf("dependent: %v", dependent)
	}

	// policy evaluation for a user
	var eval map[string]any
	e.expect(e.do(nil, "POST", Z+"/policy/evaluate", admin, map[string]any{"userId": "bob",
		"resources": []map[string]any{{"name": "Main Page", "scopes": []map[string]string{{"name": "album:view"}}}}}, nil), 200).json(&eval)
	if eval["status"] != "DENY" { // no permission covers the page type
		t.Fatalf("evaluation: %v", eval["status"])
	}
	e.expect(e.do(nil, "PUT", Z, admin, map[string]any{"policyEnforcementMode": "PERMISSIVE"}, nil), 204)
	e.expect(e.do(nil, "POST", Z+"/policy/evaluate", admin, map[string]any{"userId": "bob",
		"resources": []map[string]any{{"name": "Main Page"}}}, nil), 200).json(&eval)
	if eval["status"] != "PERMIT" {
		t.Fatalf("permissive evaluation: %v", eval["status"])
	}

	// settings export / import into another client
	var settings map[string]any
	e.expect(e.do(nil, "GET", Z+"/settings", admin, nil, nil), 200).json(&settings)
	other := idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/photoz/clients", admin, map[string]any{
		"clientId": "copy", "secret": "s", "authorizationServicesEnabled": true}, nil), 201))
	OZ := "/admin/realms/photoz/clients/" + other + "/authz/resource-server"
	e.expect(e.do(nil, "POST", OZ+"/import", admin, settings, nil), 204)
	var copied map[string]any
	e.expect(e.do(nil, "GET", OZ+"/settings", admin, nil, nil), 200).json(&copied)
	a, _ := json.Marshal(settings)
	b, _ := json.Marshal(copied)
	if !bytes.Equal(a, b) {
		t.Fatalf("settings round trip:\n%s\n%s", a, b)
	}

	// a realm export keeps authorization settings
	full, err := e.app.ExportRealm(t.Context(), "photoz")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, c := range full.Clients {
		if c.ClientID != nil && *c.ClientID == "photoz-restful-api" {
			found = len(c.AuthorizationSettings) > 0 && c.AuthorizationServicesEnabled != nil
		}
	}
	if !found {
		t.Fatal("authorizationSettings missing in the export")
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/photoz", admin, nil, nil), 204)
	e.expect(e.do(nil, "POST", "/admin/realms", admin, full, nil), 201)
	var clients []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/photoz/clients?clientId=photoz-restful-api", admin, nil, nil), 200).json(&clients)
	var imported map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/photoz/clients/"+clients[0]["id"].(string)+"/authz/resource-server/settings", admin, nil, nil), 200).json(&imported)
	if len(imported["policies"].([]any)) != len(settings["policies"].([]any)) {
		t.Fatalf("imported policies: %v", imported["policies"])
	}

	// disabling authorization removes the resource server
	id := clients[0]["id"].(string)
	e.expect(e.do(nil, "PUT", "/admin/realms/photoz/clients/"+id, admin, map[string]any{"authorizationServicesEnabled": false}, nil), 204)
	e.expect(e.do(nil, "GET", "/admin/realms/photoz/clients/"+id+"/authz/resource-server", admin, nil, nil), 404)
	resp, _ := http.Get(e.srv.URL + "/realms/photoz/.well-known/uma2-configuration")
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}
