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

func decodeJWT(t *testing.T, tok string) map[string]any {
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
	"at_hash": true, "session_state": true, "nonce": true, "clientHost": true, "clientAddress": true}

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
