package server

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func flags() map[string]string {
	return map[string]string{"access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"}
}

func with(m map[string]string, kv ...string) map[string]string {
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func TestClientScopesAndMappers(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	const R = "/admin/realms/demo"
	web := clientUUID(e, admin, "web")

	var scopes []map[string]any
	e.expect(e.do(nil, "GET", R+"/client-scopes", admin, nil, nil), 200).json(&scopes)
	names := []string{}
	for _, s := range scopes {
		names = append(names, s["name"].(string))
	}
	for _, want := range []string{"profile", "email", "roles", "web-origins", "acr", "basic", "address", "phone", "offline_access", "microprofile-jwt"} {
		if !slices.Contains(names, want) {
			t.Fatalf("built-in scope %s missing: %v", want, names)
		}
	}

	// A custom optional scope with an audience mapper.
	apiID := idFromLocation(t, e.expect(e.do(nil, "POST", R+"/client-scopes", admin, map[string]any{
		"name": "api", "protocol": "openid-connect",
		"attributes":      map[string]string{"include.in.token.scope": "true"},
		"protocolMappers": []any{map[string]any{"name": "aud", "protocol": "openid-connect", "protocolMapper": "oidc-audience-mapper", "config": with(flags(), "included.custom.audience", "api://orders")}},
	}, nil), 201))
	e.expect(e.do(nil, "POST", R+"/client-scopes", admin, map[string]any{"name": "api"}, nil), 409)
	e.expect(e.do(nil, "PUT", R+"/clients/"+web+"/optional-client-scopes/"+apiID, admin, nil, nil), 204)
	var optional []map[string]any
	e.expect(e.do(nil, "GET", R+"/clients/"+web+"/optional-client-scopes", admin, nil, nil), 200).json(&optional)
	if !slices.ContainsFunc(optional, func(m map[string]any) bool { return m["name"] == "api" }) {
		t.Fatalf("api not in optional scopes: %v", optional)
	}

	grant := func(scope string) (map[string]any, *response) {
		f := url.Values{"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"},
			"username": {"alice"}, "password": {"wonderland"}}
		if scope != "" {
			f.Set("scope", scope)
		}
		r := e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, f)
		var body map[string]any
		if r.status == 200 {
			r.json(&body)
		}
		return body, r
	}
	body, r := grant("openid api")
	e.expect(r, 200)
	c := claims(t, body["access_token"].(string))
	if !slices.Contains(c.Audience(), "api://orders") || !strings.Contains(c.String("scope"), "api") {
		t.Fatalf("api scope not applied: aud=%v scope=%q", c["aud"], c.String("scope"))
	}
	body, _ = grant("openid")
	if slices.Contains(claims(t, body["access_token"].(string)).Audience(), "api://orders") {
		t.Fatal("optional scope applied without being requested")
	}
	_, r = grant("openid orders")
	if r.status != 400 || !strings.Contains(string(r.body), "invalid_scope") {
		t.Fatalf("expected invalid_scope, got %d %s", r.status, r.body)
	}

	// Mappers on the client: multivalued attribute, groups with full path,
	// a renamed realm role and a hardcoded client role.
	// Like Keycloak 26, free-form attributes need unmanaged attributes enabled.
	var profile map[string]any
	e.expect(e.do(nil, "GET", R+"/users/profile", admin, nil, nil), 200).json(&profile)
	e.expect(e.do(nil, "PUT", R+"/users/"+aliceID, admin, map[string]any{"attributes": map[string][]string{"dept": {"eng"}}}, nil), 204)
	var alice map[string]any
	e.expect(e.do(nil, "GET", R+"/users/"+aliceID, admin, nil, nil), 200).json(&alice)
	if alice["attributes"] != nil {
		t.Fatalf("unmanaged attribute stored while disabled: %v", alice["attributes"])
	}
	profile["unmanagedAttributePolicy"] = "ENABLED"
	e.expect(e.do(nil, "PUT", R+"/users/profile", admin, profile, nil), 200)
	e.expect(e.do(nil, "PUT", R+"/users/"+aliceID, admin, map[string]any{"attributes": map[string][]string{"dept": {"eng", "ops"}}}, nil), 204)
	e.expect(e.do(nil, "POST", R+"/clients/"+web+"/protocol-mappers/add-models", admin, []any{
		map[string]any{"name": "dept", "protocolMapper": "oidc-usermodel-attribute-mapper", "config": with(flags(), "user.attribute", "dept", "claim.name", "org.dept", "multivalued", "true", "jsonType.label", "String")},
		map[string]any{"name": "groups", "protocolMapper": "oidc-group-membership-mapper", "config": with(flags(), "claim.name", "groups", "full.path", "true")},
		map[string]any{"name": "rename", "protocolMapper": "oidc-role-name-mapper", "config": map[string]string{"role": "editor", "new.role.name": "chief-editor"}},
		map[string]any{"name": "hardcoded", "protocolMapper": "oidc-hardcoded-role-mapper", "config": map[string]string{"role": "web.special"}},
	}, nil), 204)
	e.expect(e.do(nil, "POST", R+"/clients/"+web+"/protocol-mappers/models", admin, map[string]any{"name": "bad", "protocolMapper": "script-mapper"}, nil), 400)
	body, r = grant("openid")
	e.expect(r, 200)
	c = claims(t, body["access_token"].(string))
	org, _ := c["org"].(map[string]any)
	if fmt.Sprint(org["dept"]) != "[eng ops]" {
		t.Errorf("dept claim = %v", c["org"])
	}
	if fmt.Sprint(c["groups"]) != "[/staff]" {
		t.Errorf("groups claim = %v", c["groups"])
	}
	if rr := realmRoles(c); slices.Contains(rr, "editor") || !slices.Contains(rr, "chief-editor") {
		t.Errorf("role name mapper: %v", rr)
	}
	if cr := clientRoles(c, "web"); !slices.Contains(cr, "special") {
		t.Errorf("hardcoded role: %v", cr)
	}
	idc := claims(t, body["id_token"].(string))
	if fmt.Sprint(idc["groups"]) != "[/staff]" || idc["realm_access"] != nil {
		t.Errorf("id token: groups=%v realm_access=%v", idc["groups"], idc["realm_access"])
	}

	// Removing the email scope from the client removes the email claims.
	var emailScope string
	for _, s := range scopes {
		if s["name"] == "email" {
			emailScope = s["id"].(string)
		}
	}
	e.expect(e.do(nil, "DELETE", R+"/clients/"+web+"/default-client-scopes/"+emailScope, admin, nil, nil), 204)
	body, _ = grant("openid")
	if c := claims(t, body["access_token"].(string)); c["email"] != nil || strings.Contains(c.String("scope"), "email") {
		t.Fatalf("email claims still present: %v", c)
	}
	// realm default scopes cannot be deleted
	e.expect(e.do(nil, "DELETE", R+"/client-scopes/"+emailScope, admin, nil, nil), 400)

	// evaluate-scopes
	var example map[string]any
	e.expect(e.do(nil, "GET", R+"/clients/"+web+"/evaluate-scopes/generate-example-access-token?scope=openid+api&userId="+aliceID, admin, nil, nil), 200).json(&example)
	if example["preferred_username"] != "alice" || !strings.Contains(fmt.Sprint(example["aud"]), "api://orders") {
		t.Fatalf("example token = %v", example)
	}
	var evaluated []map[string]any
	e.expect(e.do(nil, "GET", R+"/clients/"+web+"/evaluate-scopes/protocol-mappers?scope=openid", admin, nil, nil), 200).json(&evaluated)
	if len(evaluated) == 0 {
		t.Fatal("no evaluated mappers")
	}

	// attribute search
	var users []map[string]any
	e.expect(e.do(nil, "GET", R+"/users?q=dept:ops", admin, nil, nil), 200).json(&users)
	if len(users) != 1 || users[0]["username"] != "alice" {
		t.Fatalf("q search = %v", users)
	}
	e.expect(e.do(nil, "GET", R+"/users?q=dept:sales", admin, nil, nil), 200).json(&users)
	if len(users) != 0 {
		t.Fatalf("q search = %v", users)
	}
	e.expect(e.do(nil, "GET", R+"/users?briefRepresentation=true&search=alice", admin, nil, nil), 200).json(&users)
	if users[0]["attributes"] != nil {
		t.Fatalf("brief representation has attributes: %v", users[0])
	}
}

func TestAuthorizeScopesAndAuthTime(t *testing.T) {
	e := newEnv(t)
	e.setupDemo()
	browser := newBrowser()

	r := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?client_id=web&response_type=code&scope=openid+nope&state=s&redirect_uri=http%3A%2F%2Fapp.test%2Fcb", "", nil, nil), 302)
	loc, _ := url.Parse(r.header.Get("Location"))
	if loc.Query().Get("error") != "invalid_scope" || loc.Query().Get("state") != "s" {
		t.Fatalf("expected invalid_scope redirect, got %s", loc)
	}

	code := e.browserLogin(browser, "openid", "alice", "wonderland")
	var tok tokens
	e.expect(e.do(nil, "POST", "/realms/demo/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://app.test/cb"},
		"client_id": {"web"}, "client_secret": {"web-secret"},
	}), 200).json(&tok)
	for _, tk := range []string{tok.AccessToken, tok.IDToken} {
		if claims(t, tk).Int("auth_time") == 0 {
			t.Fatalf("auth_time missing after browser login: %v", claims(t, tk))
		}
	}
	// password grants carry no auth_time, as in Keycloak
	pw, r := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	if _, ok := claims(t, pw.AccessToken)["auth_time"]; ok {
		t.Fatal("auth_time present for password grant")
	}
}

func TestImportClientScopes(t *testing.T) {
	e := newEnv(t)
	admin := e.adminToken()
	e.expect(e.do(nil, "POST", "/admin/realms", admin, map[string]any{
		"realm": "scoped", "enabled": true,
		"roles": map[string]any{"realm": []any{map[string]any{"name": "reader"}, map[string]any{"name": "writer"}}},
		"clientScopes": []any{map[string]any{"name": "orders", "protocol": "openid-connect",
			"protocolMappers": []any{map[string]any{"name": "flag", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
				"config": with(flags(), "claim.name", "orders", "claim.value", "true", "jsonType.label", "boolean")}}}},
		"clients": []any{map[string]any{"clientId": "app", "publicClient": true, "directAccessGrantsEnabled": true, "fullScopeAllowed": false,
			"defaultClientScopes": []string{"profile", "orders", "roles"}, "optionalClientScopes": []string{}}},
		"scopeMappings": []any{map[string]any{"clientScope": "orders", "roles": []string{"reader"}}},
		"users": []any{map[string]any{"username": "bob", "email": "bob@example.com", "firstName": "Bob", "lastName": "B", "enabled": true, "realmRoles": []string{"reader", "writer"},
			"credentials": []any{map[string]any{"type": "password", "value": "pw"}}}},
	}, nil), 201)
	tok, r := e.passwordGrant("scoped", "app", "", "bob", "pw")
	e.expect(r, 200)
	c := claims(t, tok.AccessToken)
	if c["orders"] != true || c["email"] != nil {
		t.Fatalf("imported scopes not applied: %v", c)
	}
	if rr := realmRoles(c); !slices.Equal(rr, []string{"reader"}) {
		t.Fatalf("scope mapping not applied: %v", rr)
	}

	rep, err := e.app.ExportRealm(t.Context(), "scoped")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sm := range rep.ScopeMappings {
		if sm.ClientScope == "orders" && slices.Equal(sm.Roles, []string{"reader"}) {
			found = true
		}
	}
	if !found || len(rep.ClientScopes) < 11 {
		t.Fatalf("export lacks scopes: %d scopes, mappings %v", len(rep.ClientScopes), rep.ScopeMappings)
	}
}

func newBrowser() *http.Client {
	jar, _ := cookiejarNew()
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// browserLogin runs the login form for client "web" and returns the code.
func (e *env) browserLogin(browser *http.Client, scope, user, pass string) string {
	e.t.Helper()
	page := e.expect(e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?"+url.Values{
		"client_id": {"web"}, "response_type": {"code"}, "scope": {scope}, "redirect_uri": {"http://app.test/cb"},
	}.Encode(), "", nil, nil), 200)
	action := formAction(e.t, page.body)
	r := e.expect(e.do(browser, "POST", action, "", nil, url.Values{"username": {user}, "password": {pass}}), 302)
	loc, _ := url.Parse(r.header.Get("Location"))
	return loc.Query().Get("code")
}
