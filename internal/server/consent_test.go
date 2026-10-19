package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestConsentScreen(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()
	e.expect(e.do(nil, "POST", "/admin/realms/demo/clients", admin, map[string]any{"clientId": "app", "name": "My App", "secret": "s",
		"redirectUris": []string{"http://app.test/*"}, "consentRequired": true, "directAccessGrantsEnabled": true,
		"attributes": map[string]string{"display.on.consent.screen": "true", "consent.screen.text": "App wants things"}}, nil), 201)
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/clients/"+clientUUID(e, admin, "app"), admin, nil, nil), 200).json(&rep)
	if rep["consentRequired"] != true {
		t.Fatalf("consentRequired: %v", rep["consentRequired"])
	}
	browser := newBrowser()
	auth := func(scope string, extra url.Values) *response {
		q := url.Values{"client_id": {"app"}, "response_type": {"code"}, "scope": {scope}, "redirect_uri": {"http://app.test/cb"}, "state": {"s1"}}
		for k, v := range extra {
			q[k] = v
		}
		return e.do(browser, "GET", "/realms/demo/protocol/openid-connect/auth?"+q.Encode(), "", nil, nil)
	}
	r := e.expect(auth("openid", nil), 200)
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"username": {"alice"}, "password": {"wonderland"}}), 200)
	page := string(r.body)
	for _, want := range []string{"Grant Access to My App", "User profile", "Email address", "User roles", "App wants things"} {
		if !strings.Contains(page, want) {
			t.Fatalf("consent page lacks %q: %s", want, page)
		}
	}
	if strings.Contains(page, "Phone number") {
		t.Fatal("optional scope on the consent page")
	}
	codeOf(t, e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"accept": {"Yes"}}))

	// granted scopes are not asked again, new ones are
	codeOf(t, auth("openid", nil))
	r = e.expect(auth("openid phone", nil), 200)
	if !strings.Contains(string(r.body), "Phone number") || strings.Contains(string(r.body), "User profile") {
		t.Fatalf("second consent page: %s", r.body)
	}
	r = e.expect(e.do(browser, "POST", formAction(t, r.body), "", nil, url.Values{"cancel": {"No"}}), 302)
	if loc := r.header.Get("Location"); !strings.HasPrefix(loc, "http://app.test/cb?error=access_denied") {
		t.Fatalf("denied: %s", loc)
	}
	// prompt=none cannot ask, prompt=consent always asks
	r = e.expect(auth("openid phone", url.Values{"prompt": {"none"}}), 302)
	if !strings.Contains(r.header.Get("Location"), "error=interaction_required") {
		t.Fatalf("prompt=none: %s", r.header.Get("Location"))
	}
	e.expect(auth("openid", url.Values{"prompt": {"consent"}}), 200)
	// no consent page in a direct grant
	_, pr := e.passwordGrant("demo", "app", "s", "alice", "wonderland")
	if pr.status != 400 || !strings.Contains(string(pr.body), "Client requires user consent") {
		t.Fatalf("password grant: %d %s", pr.status, pr.body)
	}

	var consents []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+aliceID+"/consents", admin, nil, nil), 200).json(&consents)
	if len(consents) != 1 || consents[0]["clientId"] != "app" {
		t.Fatalf("consents: %v", consents)
	}
	granted := strs(consents[0]["grantedClientScopes"])
	slices.Sort(granted)
	if !slices.Equal(granted, []string{"app", "email", "profile", "roles"}) {
		t.Fatalf("granted scopes: %v", granted)
	}

	// the account API shows and revokes the consent
	tk, _ := e.passwordGrant("demo", "web", "web-secret", "alice", "wonderland")
	req, _ := http.NewRequest("GET", e.srv.URL+"/realms/demo/account/applications", nil)
	req.Header.Set("Authorization", "Bearer "+tk.AccessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var apps []map[string]any
	(&response{body: body}).json(&apps)
	found := false
	for _, a := range apps {
		if a["clientId"] == "app" {
			found = true
			c, _ := a["consent"].(map[string]any)
			if a["userConsentRequired"] != true || c == nil || len(c["grantedScopes"].([]any)) != 4 {
				t.Fatalf("account application: %v", a)
			}
		}
	}
	if !found {
		t.Fatalf("applications: %v", apps)
	}
	// realm exports carry the consents
	exp, err := e.app.ExportRealm(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(exp)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	if !strings.Contains(string(b), `"clientConsents":[{"clientId":"app","grantedClientScopes":[`) {
		t.Fatalf("export without consents")
	}
	doc["realm"], doc["id"] = "demo2", nil
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo", admin, nil, nil), 204)
	e.expect(e.do(nil, "POST", "/admin/realms", admin, doc, nil), 201)
	e.expect(e.do(nil, "GET", "/admin/realms/demo2/users/"+aliceID+"/consents", admin, nil, nil), 200).json(&consents)
	if len(consents) != 1 || len(strs(consents[0]["grantedClientScopes"])) != 4 {
		t.Fatalf("imported consents: %v", consents)
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo2/users/"+aliceID+"/consents/app", admin, nil, nil), 204)
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo2/users/"+aliceID+"/consents/app", admin, nil, nil), 404)
}
