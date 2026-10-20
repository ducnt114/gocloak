package server

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fakeConsoleJars writes minimal upstream admin UI and themes jars.
func fakeConsoleJars(t *testing.T) string {
	dir := t.TempDir()
	write := func(name string, files map[string]string) {
		var buf bytes.Buffer
		z := zip.NewWriter(&buf)
		for n, content := range files {
			w, _ := z.Create(n)
			w.Write([]byte(content))
		}
		z.Close()
		os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644)
	}
	write("keycloak-admin-ui-26.0.7.jar", map[string]string{
		"theme/keycloak.v2/admin/resources/.vite/manifest.json":   `{"src/main.tsx": {"file": "assets/main-1.js", "css": ["assets/main-1.css"], "isEntry": true}}`,
		"theme/keycloak.v2/admin/resources/assets/main-1.js":      `console.log("console")`,
		"theme/keycloak.v2/admin/resources/assets/types-1.js":     `const t="org.keycloak.keys.KeyProvider",d="fedToKeycloak",c="keycloak__form",l="[KEYCLOAK]",u="https://www.keycloak.org/docs";`,
		"theme/keycloak.v2/admin/resources/logo.svg":              `<svg>upstream</svg>`,
		"theme/keycloak.v2/admin/messages/messages_en.properties": "realmSettings=Realm settings\nkeycloakToFedSyncMessage=Sync Keycloak roles\n",
	})
	write("keycloak-themes-26.0.7.jar", map[string]string{
		"theme/keycloak/common/resources/vendor/react/react.production.min.js": "react",
		"theme/base/admin/messages/messages_en.properties":                     "cancel=Cancel\n",
	})
	return dir
}

// consoleLogin logs in to the admin console client with PKCE and returns
// its token and the browser.
func (e *env) consoleLogin(realm, user, pass string) (*tokens, *http.Client) {
	e.t.Helper()
	browser := newBrowser()
	verifier := strings.Repeat("c", 50)
	sum := sha256.Sum256([]byte(verifier))
	redirect := e.srv.URL + "/admin/" + realm + "/console/"
	page := e.expect(e.do(browser, "GET", "/realms/"+realm+"/protocol/openid-connect/auth?"+url.Values{
		"client_id": {"security-admin-console"}, "redirect_uri": {redirect}, "response_type": {"code"}, "scope": {"openid"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
	}.Encode(), "", nil, nil), 200)
	r := e.expect(e.do(browser, "POST", formAction(e.t, page.body), "", nil, url.Values{"username": {user}, "password": {pass}}), 302)
	loc, _ := url.Parse(r.header.Get("Location"))
	var tk tokens
	e.expect(e.do(nil, "POST", "/realms/"+realm+"/protocol/openid-connect/token", "", nil, url.Values{"grant_type": {"authorization_code"},
		"code": {loc.Query().Get("code")}, "redirect_uri": {redirect}, "client_id": {"security-admin-console"}, "code_verifier": {verifier}}), 200).json(&tk)
	return &tk, browser
}

func TestAdminConsolePages(t *testing.T) {
	jars := fakeConsoleJars(t)
	e := newEnvWith(t, func(c *Config) { c.AdminConsoleDir = jars })
	r := e.expect(e.do(newBrowser(), "GET", "/admin/", "", nil, nil), 302)
	if !strings.HasSuffix(r.header.Get("Location"), "/admin/master/console/") {
		t.Fatalf("redirect: %s", r.header.Get("Location"))
	}
	page := e.expect(e.do(nil, "GET", "/admin/master/console/", "", nil, nil), 200)
	body := string(page.body)
	for _, want := range []string{`"clientId":"security-admin-console"`, `"realm":"master"`, `/assets/main-1.js"`, `/assets/main-1.css"`,
		`"react":"/resources/`} {
		if !strings.Contains(body, want) {
			t.Fatalf("index lacks %s:\n%s", want, body)
		}
	}
	res := regexp1(`src="(/resources/[^"]+/assets/main-1.js)"`, body)
	if r := e.expect(e.do(nil, "GET", res, "", nil, nil), 200); string(r.body) != `console.log("console")` {
		t.Fatalf("asset: %s", r.body)
	}
	// the console speaks gocloak's names and shows gocloak's logo
	types := e.expect(e.do(nil, "GET", strings.Replace(res, "main-1.js", "types-1.js", 1), "", nil, nil), 200)
	if want := `const t="org.gocloak.keys.KeyProvider",d="fedToGocloak",c="gocloak__form",l="[GOCLOAK]",u="https://www.keycloak.org/docs";`; string(types.body) != want {
		t.Fatalf("rebranded asset:\n%s\nwant\n%s", types.body, want)
	}
	if logo := e.expect(e.do(nil, "GET", strings.Replace(res, "assets/main-1.js", "logo.svg", 1), "", nil, nil), 200); !strings.Contains(string(logo.body), "gocloak") {
		t.Fatalf("logo: %s", logo.body)
	}
	vendor := regexp1(`"react":"([^"]+)"`, body)
	e.expect(e.do(nil, "GET", vendor, "", nil, nil), 200)
	var msgs []map[string]string
	e.expect(e.do(nil, "GET", "/resources/master/admin/en", "", nil, nil), 200).json(&msgs)
	keys := map[string]string{}
	for _, m := range msgs {
		keys[m["key"]] = m["value"]
	}
	if keys["cancel"] != "Cancel" || keys["realmSettings"] != "Realm settings" || keys["locale_vi"] != "Tiếng Việt" ||
		keys["gocloakToFedSyncMessage"] != "Sync gocloak roles" {
		t.Fatalf("translations: %v", msgs)
	}
	var cfg map[string]any
	e.expect(e.do(nil, "GET", "/admin/master/console/config", "", nil, nil), 200).json(&cfg)
	if cfg["resource"] != "security-admin-console" || cfg["public-client"] != true {
		t.Fatalf("config: %v", cfg)
	}

	// without the jars the page explains how to install the console
	plain := newEnv(t)
	if r := plain.do(nil, "GET", "/admin/master/console/", "", nil, nil); r.status != 503 || !strings.Contains(string(r.body), "download-admin-console") {
		t.Fatalf("console not installed: %d %s", r.status, r.body)
	}
}

func regexp1(pattern, s string) string {
	m := regexpMust(pattern).FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

func TestAdminConsoleAPI(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()

	// JavaScript adapter iframes and the session cookie
	tk, browser := e.consoleLogin("master", "admin", "admin")
	u, _ := url.Parse(e.srv.URL + "/realms/master/")
	var session string
	for _, c := range browser.Jar.Cookies(u) {
		if c.Name == "GOCLOAK_SESSION" {
			session = c.Value
		}
	}
	if !strings.HasPrefix(session, "master/") || !strings.HasSuffix(session, "/"+claims(t, tk.AccessToken).String("sid")) {
		t.Fatalf("GOCLOAK_SESSION cookie: %q", session)
	}
	for _, p := range []string{"3p-cookies/step1.html", "3p-cookies/step2.html", "login-status-iframe.html"} {
		e.expect(e.do(nil, "GET", "/realms/master/protocol/openid-connect/"+p, "", nil, nil), 200)
	}
	init := "/realms/master/protocol/openid-connect/login-status-iframe.html/init?client_id=security-admin-console&origin="
	e.expect(e.do(nil, "GET", init+url.QueryEscape(e.srv.URL), "", nil, nil), 204)
	e.expect(e.do(nil, "GET", init+url.QueryEscape("https://evil.example"), "", nil, nil), 403)

	// whoami requires a console token
	var who map[string]any
	e.expect(e.do(nil, "GET", "/admin/master/console/whoami?currentRealm=demo", tk.AccessToken, nil, nil), 200).json(&who)
	access := who["realm_access"].(map[string]any)["demo"]
	if who["createRealm"] != true || who["realm"] != "master" || !slices.Contains(strs(access), "manage-users") {
		t.Fatalf("whoami: %v", who)
	}
	e.expect(e.do(nil, "GET", "/admin/master/console/whoami", admin, nil, nil), 403)

	var info map[string]any
	e.expect(e.do(nil, "GET", "/admin/serverinfo", tk.AccessToken, nil, nil), 200).json(&info)
	if info["systemInfo"] == nil || info["componentTypes"] == nil || info["themes"] == nil {
		t.Fatalf("serverinfo keys: %v", info)
	}
	ct := info["componentTypes"].(map[string]any)
	if len(ct["org.gocloak.storage.UserStorageProvider"].([]any)) != 1 {
		t.Fatalf("storage providers: %v", ct["org.gocloak.storage.UserStorageProvider"])
	}

	// ui-ext
	var names []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/master/ui-ext/realms/names?first=0&max=10", admin, nil, nil), 200).json(&names)
	if len(names) != 2 {
		t.Fatalf("realm names: %v", names)
	}
	var sessions []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/master/ui-ext/sessions?type=ALL", admin, nil, nil), 200).json(&sessions)
	if len(sessions) == 0 || sessions[0]["type"] != "REGULAR" {
		t.Fatalf("sessions: %v", sessions)
	}
	var flows []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/ui-ext/authentication-management/flows", admin, nil, nil), 200).json(&flows)
	for _, f := range flows {
		if f["alias"] == "browser" && f["usedBy"].(map[string]any)["type"] != "DEFAULT" {
			t.Fatalf("browser flow: %v", f)
		}
	}
	var available, effective []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/ui-ext/available-roles/users/"+aliceID+"?first=0&max=100", admin, nil, nil), 200).json(&available)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/ui-ext/effective-roles/users/"+aliceID, admin, nil, nil), 200).json(&effective)
	has := func(list []map[string]any, client, role string) bool {
		return slices.ContainsFunc(list, func(m map[string]any) bool { return m["client"] == client && m["role"] == role })
	}
	// only direct mappings are excluded from the available roles
	if !has(effective, "account", "view-profile") || !has(available, "account", "view-groups") {
		t.Fatalf("available %v\neffective %v", available, effective)
	}
	var bf []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/ui-ext/brute-force-user?briefRepresentation=true&first=0&max=10", admin, nil, nil), 200).json(&bf)
	if len(bf) != 1 || bf[0]["bruteForceStatus"] == nil {
		t.Fatalf("brute force users: %v", bf)
	}

	// lenient JSON, as the console sends it
	e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "bob", "enabled": true,
		"email": "bob@example.org", "firstName": "Bob", "lastName": "B", "attributes": map[string]any{"locale": ""}}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "spa", "publicClient": true,
		"attributes": map[string]any{"oauth2.device.authorization.grant.enabled": false, "pkce.code.challenge.method": "S256"}}, nil), 201)
	var list []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/", admin, nil, nil), 200).json(&list) // trailing slash
	if len(list) == 0 {
		t.Fatal("no clients")
	}

	// PUT ui-ext saves the realm and its user profile
	var profile map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/profile", admin, nil, nil), 200).json(&profile)
	profile["unmanagedAttributePolicy"] = "ENABLED"
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/ui-ext", admin, map[string]any{"displayName": "Demo!", "upConfig": profile}, nil), 204)
	var realm map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo", admin, nil, nil), 200).json(&realm)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/profile", admin, nil, nil), 200).json(&profile)
	if realm["displayName"] != "Demo!" || profile["unmanagedAttributePolicy"] != "ENABLED" {
		t.Fatalf("ui-ext update: %v %v", realm["displayName"], profile["unmanagedAttributePolicy"])
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+aliceID, admin, map[string]any{"attributes": map[string]any{"dept": "eng"}}, nil), 204)
	var unmanaged map[string][]string
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/unmanagedAttributes", admin, nil, nil), 200).json(&unmanaged)
	if !slices.Equal(unmanaged["dept"], []string{"eng"}) {
		t.Fatalf("unmanaged attributes: %v", unmanaged)
	}
}

func TestDefaultGroupsAndRoleComposites(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	var groups []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/groups", admin, nil, nil), 200).json(&groups)
	staff := groups[0]["id"].(string)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/default-groups/"+staff, admin, nil, nil), 204)
	var defaults []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/default-groups", admin, nil, nil), 200).json(&defaults)
	if len(defaults) != 1 || defaults[0]["path"] != "/staff" {
		t.Fatalf("default groups: %v", defaults)
	}
	id := idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{"username": "newbie", "enabled": true}, nil), 201))
	var ug []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+id+"/groups", admin, nil, nil), 200).json(&ug)
	if len(ug) != 1 {
		t.Fatalf("new user not in the default group: %v", ug)
	}
	var exp map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/partial-export?exportGroupsAndRoles=true", admin, nil, nil), 200).json(&exp)
	if !slices.Equal(strs(exp["defaultGroups"]), []string{"/staff"}) {
		t.Fatalf("exported default groups: %v", exp["defaultGroups"])
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/default-groups/"+staff, admin, nil, nil), 204)

	// composites by role id
	var realm map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo", admin, nil, nil), 200).json(&realm)
	def := realm["defaultRole"].(map[string]any)["id"].(string)
	var comps []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles-by-id/"+def+"/composites", admin, nil, nil), 200).json(&comps)
	if len(comps) != 4 {
		t.Fatalf("default role composites: %v", comps)
	}
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles-by-id/"+def+"/composites/realm", admin, nil, nil), 200).json(&comps)
	if len(comps) != 2 {
		t.Fatalf("realm composites: %v", comps)
	}
	var editor map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles/editor", admin, nil, nil), 200).json(&editor)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/roles-by-id/"+def+"/composites", admin, []any{editor}, nil), 204)
	e.expect(e.do(nil, "GET", "/admin/realms/demo/roles-by-id/"+def+"/composites", admin, nil, nil), 200).json(&comps)
	if len(comps) != 5 {
		t.Fatalf("after adding a composite: %v", comps)
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/roles-by-id/"+def+"/composites", admin, []any{editor}, nil), 204)
}

func TestClientCertificatesAndScopeEvaluation(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	var clients []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients?clientId=web", admin, nil, nil), 200).json(&clients)
	web := clients[0]["id"].(string)
	C := "/admin/realms/demo/clients/" + web + "/certificates/jwt.credential"
	var cert map[string]string
	e.expect(e.do(nil, "GET", C, admin, nil, nil), 200).json(&cert)
	if len(cert) != 0 {
		t.Fatalf("no certificate expected: %v", cert)
	}
	e.expect(e.do(nil, "POST", C+"/generate", admin, nil, nil), 200).json(&cert)
	if cert["privateKey"] == "" || cert["certificate"] == "" {
		t.Fatalf("generated: %v", cert)
	}
	// upload a JWKS (multipart, as the console sends it)
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	mw.WriteField("keystoreFormat", "JSON Web Key Set")
	fw, _ := mw.CreateFormFile("file", "jwks.json")
	jwks := e.do(nil, "GET", "/realms/demo/protocol/openid-connect/certs", "", nil, nil)
	fw.Write(jwks.body)
	mw.Close()
	req, _ := http.NewRequest("POST", e.srv.URL+C+"/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+admin)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("upload: %v %v", err, resp.Status)
	}
	cert = nil
	e.expect(e.do(nil, "GET", C, admin, nil, nil), 200).json(&cert)
	if cert["publicKey"] == "" || cert["kid"] == "" || cert["privateKey"] != "" {
		t.Fatalf("uploaded: public=%d kid=%q private=%d", len(cert["publicKey"]), cert["kid"], len(cert["privateKey"]))
	}

	// granted roles: everything with full scope
	var granted, notGranted []map[string]any
	ev := "/admin/realms/demo/clients/" + web + "/evaluate-scopes/scope-mappings/demo/"
	e.expect(e.do(nil, "GET", ev+"granted?scope=openid", admin, nil, nil), 200).json(&granted)
	e.expect(e.do(nil, "GET", ev+"not-granted?scope=openid", admin, nil, nil), 200).json(&notGranted)
	if len(granted) == 0 || len(notGranted) != 0 {
		t.Fatalf("full scope: %d granted, %d not granted", len(granted), len(notGranted))
	}
	var sessions []any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+web+"/offline-sessions", admin, nil, nil), 200).json(&sessions)
	var count map[string]int
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+web+"/session-count", admin, nil, nil), 200).json(&count)
}

func regexpMust(p string) *regexp.Regexp { return regexp.MustCompile(p) }
