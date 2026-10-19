package server

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestKeycloakCompatibility runs the scenario of scripts/compat/tokens.py and
// compares the normalised claims with testdata/keycloak, which was recorded
// from a real Keycloak 26.0.7. Regenerate the golden files with
//
//	scripts/compat/tokens.py --keycloak http://localhost:8180 --golden internal/server/testdata/keycloak
func TestKeycloakCompatibility(t *testing.T) {
	e := newEnv(t)
	admin := e.adminToken()
	const R = "/admin/realms/compat"
	e.expect(e.do(nil, "POST", "/admin/realms", admin, map[string]any{"realm": "compat", "enabled": true}, nil), 201)
	for _, c := range []map[string]any{
		{"clientId": "web", "secret": "web-secret", "redirectUris": []string{"http://app.test/*"}, "webOrigins": []string{"+"}, "directAccessGrantsEnabled": true},
		{"clientId": "svc", "secret": "svc-secret", "serviceAccountsEnabled": true, "standardFlowEnabled": false},
		{"clientId": "narrow", "secret": "narrow-secret", "directAccessGrantsEnabled": true, "fullScopeAllowed": false, "redirectUris": []string{"http://narrow.test/*"}},
	} {
		e.expect(e.do(nil, "POST", R+"/clients", admin, c, nil), 201)
	}
	uuid := func(clientID string) string {
		var cs []map[string]any
		e.expect(e.do(nil, "GET", R+"/clients?clientId="+clientID, admin, nil, nil), 200).json(&cs)
		return cs[0]["id"].(string)
	}
	web, narrow := uuid("web"), uuid("narrow")
	for _, name := range []string{"editor", "auditor"} {
		e.expect(e.do(nil, "POST", R+"/roles", admin, map[string]any{"name": name}, nil), 201)
	}
	e.expect(e.do(nil, "POST", R+"/clients/"+web+"/roles", admin, map[string]any{"name": "viewer"}, nil), 201)
	group := idFromLocation(t, e.expect(e.do(nil, "POST", R+"/groups", admin, map[string]any{"name": "staff"}, nil), 201))
	role := func(path string) map[string]any {
		var r map[string]any
		e.expect(e.do(nil, "GET", R+path, admin, nil, nil), 200).json(&r)
		return r
	}
	e.expect(e.do(nil, "POST", R+"/groups/"+group+"/role-mappings/realm", admin, []any{role("/roles/editor")}, nil), 204)
	user := idFromLocation(t, e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{
		"username": "alice", "email": "alice@example.com", "firstName": "Alice", "lastName": "Liddell",
		"enabled": true, "emailVerified": true,
		"credentials": []any{map[string]any{"type": "password", "value": "wonderland", "temporary": false}},
	}, nil), 201))
	e.expect(e.do(nil, "PUT", R+"/users/"+user+"/groups/"+group, admin, nil, nil), 204)
	e.expect(e.do(nil, "POST", R+"/users/"+user+"/role-mappings/clients/"+web, admin, []any{role("/clients/" + web + "/roles/viewer")}, nil), 204)
	auditor := role("/roles/auditor")
	e.expect(e.do(nil, "POST", R+"/users/"+user+"/role-mappings/realm", admin, []any{auditor}, nil), 204)
	e.expect(e.do(nil, "POST", R+"/clients/"+narrow+"/scope-mappings/realm", admin, []any{auditor}, nil), 204)
	e.expect(e.do(nil, "POST", R+"/clients/"+web+"/protocol-mappers/models", admin, map[string]any{
		"name": "tenant", "protocol": "openid-connect", "protocolMapper": "oidc-hardcoded-claim-mapper",
		"config": map[string]string{"claim.name": "tenant.id", "claim.value": "42", "jsonType.label": "long",
			"access.token.claim": "true", "id.token.claim": "true", "userinfo.token.claim": "true"},
	}, nil), 201)

	got := map[string]any{}
	tokenURL := "/realms/compat/protocol/openid-connect/token"
	for _, sc := range []struct{ name, client, secret, scope string }{
		{"default", "web", "web-secret", "openid"},
		{"optional-scopes", "web", "web-secret", "openid address phone microprofile-jwt"},
		{"no-openid", "web", "web-secret", ""},
		{"narrow", "narrow", "narrow-secret", "openid"},
	} {
		f := url.Values{"grant_type": {"password"}, "client_id": {sc.client}, "client_secret": {sc.secret},
			"username": {"alice"}, "password": {"wonderland"}}
		if sc.scope != "" {
			f.Set("scope", sc.scope)
		}
		var body map[string]any
		e.expect(e.do(nil, "POST", tokenURL, "", nil, f), 200).json(&body)
		got[sc.name+".access"] = normalize(e, decodeJWT(t, body["access_token"].(string)))
		if id, ok := body["id_token"].(string); ok {
			got[sc.name+".id"] = normalize(e, decodeJWT(t, id))
		}
		r := e.do(nil, "GET", "/realms/compat/protocol/openid-connect/userinfo", body["access_token"].(string), nil, nil)
		if r.status == 200 {
			var info map[string]any
			r.json(&info)
			got[sc.name+".userinfo"] = normalize(e, info)
		} else {
			got[sc.name+".userinfo"] = map[string]any{"status": float64(r.status)}
		}
		got[sc.name+".response"] = map[string]any{"scope": sortWords(body["scope"].(string)), "token_type": body["token_type"]}
	}

	var cc map[string]any
	e.expect(e.do(nil, "POST", tokenURL, "", nil, url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"}}), 200).json(&cc)
	got["client-credentials.access"] = normalize(e, decodeJWT(t, cc["access_token"].(string)))
	_, hasRefresh := cc["refresh_token"]
	got["client-credentials.response"] = map[string]any{"scope": sortWords(cc["scope"].(string)), "refresh": hasRefresh}

	r := e.do(nil, "POST", tokenURL, "", nil, url.Values{"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"},
		"username": {"alice"}, "password": {"wonderland"}, "scope": {"openid nope"}})
	var errBody map[string]any
	r.json(&errBody)
	got["invalid-scope"] = map[string]any{"status": float64(r.status), "error": errBody["error"]}

	for k, v := range securityScenarios(e, admin) {
		got[k] = v
	}
	for k, v := range authenticationScenarios(e, admin) {
		got[k] = v
	}

	files, err := filepath.Glob("testdata/keycloak/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".json")
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var want any
		json.Unmarshal(b, &want)
		wantJSON, _ := json.Marshal(want)
		gotJSON, _ := json.Marshal(got[name])
		if string(wantJSON) != string(gotJSON) {
			t.Errorf("%s differs from Keycloak\n keycloak: %s\n gocloak:  %s", name, wantJSON, gotJSON)
		}
	}
}

func decodeJWT(t testing.TB, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

var volatileClaims = map[string]bool{"exp": true, "iat": true, "jti": true, "sid": true, "auth_time": true, "sub": true,
	"at_hash": true, "session_state": true, "nonce": true, "clientHost": true, "clientAddress": true,
	"reuse_id": true, "lastFailure": true, "failedLoginNotBefore": true, "lastIPFailure": true}

// normalize mirrors normalise() in scripts/compat/tokens.py.
func normalize(e *env, claims map[string]any) any {
	var walk func(v any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := map[string]any{}
			for k, val := range x {
				if volatileClaims[k] {
					out[k] = "<volatile>"
				} else {
					out[k] = walk(val)
				}
			}
			return out
		case []any:
			items := make([]any, len(x))
			for i, it := range x {
				items[i] = walk(it)
			}
			sort.Slice(items, func(i, j int) bool {
				a, _ := json.Marshal(items[i])
				b, _ := json.Marshal(items[j])
				return string(a) < string(b)
			})
			return items
		case string:
			return strings.ReplaceAll(x, e.srv.URL, "{base}")
		}
		return v
	}
	out := walk(claims).(map[string]any)
	if s, ok := out["scope"].(string); ok {
		out["scope"] = sortWords(s)
	}
	return out
}

func sortWords(s string) string {
	w := strings.Fields(s)
	sort.Strings(w)
	return strings.Join(w, " ")
}

// securityScenarios mirrors security() in scripts/compat/tokens.py.
func securityScenarios(e *env, admin string) map[string]any {
	t := e.t
	const R = "/admin/realms/compat"
	tokenURL := "/realms/compat/protocol/openid-connect/token"
	out := map[string]any{}
	realm := func(settings map[string]any) {
		e.expect(e.do(nil, "PUT", R, admin, settings, nil), 204)
	}
	password := func(user, pw string, extra ...string) *response {
		f := url.Values{"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"}, "username": {user}, "password": {pw}}
		for i := 0; i+1 < len(extra); i += 2 {
			f.Set(extra[i], extra[i+1])
		}
		return e.do(nil, "POST", tokenURL, "", nil, f)
	}
	refresh := func(token string) *response {
		return e.do(nil, "POST", tokenURL, "", nil, url.Values{"grant_type": {"refresh_token"}, "client_id": {"web"},
			"client_secret": {"web-secret"}, "refresh_token": {token}})
	}
	outcome := func(r *response) map[string]any {
		var body map[string]any
		json.Unmarshal(r.body, &body)
		return map[string]any{"status": float64(r.status), "error": body["error"], "error_description": body["error_description"]}
	}
	body := func(r *response) map[string]any {
		var b map[string]any
		e.expect(r, 200).json(&b)
		return b
	}

	mallory := idFromLocation(t, e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "mallory",
		"email": "mallory@example.com", "firstName": "M", "lastName": "M", "enabled": true,
		"credentials": []any{map[string]any{"type": "password", "value": "pass1234", "temporary": false}}}, nil), 201))

	realm(map[string]any{"passwordPolicy": "length(8) and digits(1) and passwordHistory(1)"})
	for _, c := range []struct{ name, pw string }{{"short", "short"}, {"no-digit", "abcdefgh"}, {"history", "pass1234"}} {
		out["policy."+c.name] = outcome(e.do(nil, "PUT", R+"/users/"+mallory+"/reset-password", admin,
			map[string]any{"type": "password", "value": c.pw, "temporary": false}, nil))
	}
	realm(map[string]any{"passwordPolicy": ""})

	b := body(password("mallory", "pass1234"))
	out["refresh.claims"] = normalize(e, decodeJWT(t, b["refresh_token"].(string)))
	out["refresh.response"] = map[string]any{"refresh_expires_in": b["refresh_expires_in"].(float64) > 0, "not-before-policy": b["not-before-policy"]}
	b = body(password("mallory", "pass1234", "scope", "openid offline_access"))
	out["offline.claims"] = normalize(e, decodeJWT(t, b["refresh_token"].(string)))
	out["offline.response"] = map[string]any{"refresh_expires_in": b["refresh_expires_in"], "scope": sortWords(b["scope"].(string))}
	rb := body(refresh(b["refresh_token"].(string)))
	out["offline.refresh"] = map[string]any{"status": float64(200), "typ": decodeJWT(t, rb["refresh_token"].(string))["typ"]}

	realm(map[string]any{"revokeRefreshToken": true, "refreshTokenMaxReuse": 1})
	first := body(password("mallory", "pass1234"))["refresh_token"].(string)
	r := refresh(first)
	second := body(r)["refresh_token"].(string)
	var seq []any
	for _, res := range []*response{r, refresh(first), refresh(first), refresh(second)} {
		o := outcome(res)
		seq = append(seq, map[string]any{"status": o["status"], "error_description": o["error_description"]})
	}
	out["rotation"] = seq
	realm(map[string]any{"revokeRefreshToken": false})

	realm(map[string]any{"bruteForceProtected": true, "failureFactor": 2, "waitIncrementSeconds": 60, "quickLoginCheckMilliSeconds": 0})
	out["bruteforce.attempts"] = []any{outcome(password("mallory", "wrong")), outcome(password("mallory", "wrong")), outcome(password("mallory", "pass1234"))}
	var status map[string]any
	e.expect(e.do(nil, "GET", R+"/attack-detection/brute-force/users/"+mallory, admin, nil, nil), 200).json(&status)
	out["bruteforce.status"] = normalize(e, status)
	var user map[string]any
	e.expect(e.do(nil, "GET", R+"/users/"+mallory, admin, nil, nil), 200).json(&user)
	out["bruteforce.user-enabled"] = map[string]any{"enabled": user["enabled"]}
	e.expect(e.do(nil, "DELETE", R+"/attack-detection/brute-force/users/"+mallory, admin, nil, nil), 204)
	out["bruteforce.after-clear"] = map[string]any{"status": float64(password("mallory", "pass1234").status)}
	realm(map[string]any{"bruteForceProtected": false})
	return out
}

// authenticationScenarios mirrors authentication() in scripts/compat/tokens.py.
func authenticationScenarios(e *env, admin string) map[string]any {
	const R = "/admin/realms/compat"
	out := map[string]any{}
	statusBody := func(r *response) map[string]any {
		var body any
		json.Unmarshal(r.body, &body)
		return map[string]any{"status": float64(r.status), "body": body}
	}
	out["profile.single-error"] = statusBody(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "x", "email": "nope", "enabled": true}, nil))
	out["profile.multiple-errors"] = statusBody(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "ab", "email": "nope"}, nil))
	id := idFromLocation(e.t, e.expect(e.do(nil, "POST", R+"/users", admin, map[string]any{"username": "noprofile", "enabled": true,
		"credentials": []any{map[string]any{"type": "password", "value": "pw", "temporary": false}}}, nil), 201))
	out["profile.incomplete-login"] = statusBody(e.do(nil, "POST", "/realms/compat/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"password"}, "client_id": {"web"}, "client_secret": {"web-secret"}, "username": {"noprofile"}, "password": {"pw"}}))
	out["email.missing"] = statusBody(e.do(nil, "PUT", R+"/users/"+id+"/execute-actions-email", admin, []string{"UPDATE_PASSWORD"}, nil))
	var profile any
	e.expect(e.do(nil, "GET", R+"/users/profile", admin, nil, nil), 200).json(&profile)
	out["profile.default"] = profile
	var actions []map[string]any
	e.expect(e.do(nil, "GET", R+"/authentication/required-actions", admin, nil, nil), 200).json(&actions)
	var ra []any
	for _, a := range actions {
		ra = append(ra, map[string]any{"alias": a["alias"], "name": a["name"], "providerId": a["providerId"], "enabled": a["enabled"],
			"defaultAction": a["defaultAction"], "priority": a["priority"]})
	}
	out["required-actions"] = ra
	for _, alias := range []string{"browser", "direct grant", "registration", "reset credentials", "clients"} {
		var execs []map[string]any
		e.expect(e.do(nil, "GET", R+"/authentication/flows/"+url.PathEscape(alias)+"/executions", admin, nil, nil), 200).json(&execs)
		var list []any
		for _, ex := range execs {
			m := map[string]any{}
			for _, k := range []string{"level", "index", "displayName", "requirement", "providerId", "requirementChoices", "authenticationFlow"} {
				m[k] = ex[k]
			}
			list = append(list, m)
		}
		out["flow."+strings.ReplaceAll(alias, " ", "-")] = list
	}
	out["flow.builtin-edit"] = statusBody(e.do(nil, "POST", R+"/authentication/flows/browser/executions/execution", admin, map[string]string{"provider": "auth-otp-form"}, nil))
	return out
}
