package server

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"testing"
)

func TestExportImportRoundTrip(t *testing.T) {
	e := newEnv(t)
	admin, aliceID := e.setupDemo()

	rep, err := e.app.ExportRealm(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(rep)
	var doc map[string]any
	json.Unmarshal(b, &doc)
	doc["realm"], doc["id"] = "demo2", nil
	// user ids are global; import the export of demo under another name
	// after deleting demo, as a migration would.
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo", admin, nil, nil), 204)
	e.expect(e.do(nil, "POST", "/admin/realms", admin, doc, nil), 201)

	tok, r := e.passwordGrant("demo2", "web", "web-secret", "alice", "wonderland")
	e.expect(r, 200)
	c := claims(t, tok.AccessToken)
	if c.String("sub") != aliceID {
		t.Fatalf("sub changed: %s != %s", c.String("sub"), aliceID)
	}
	if !slices.Contains(realmRoles(c), "editor") || !slices.Contains(realmRoles(c), "default-roles-demo") || slices.Contains(realmRoles(c), "default-roles-demo2") {
		t.Fatalf("roles after round trip: %v", realmRoles(c))
	}
	// the service account keeps working with the exported secret
	e.expect(e.do(nil, "POST", "/realms/demo2/protocol/openid-connect/token", "", nil, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"},
	}), 200)

	// exporting again gives the same users, clients and groups
	rep2, err := e.app.ExportRealm(context.Background(), "demo2")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Users) != len(rep.Users) || len(rep2.Clients) != len(rep.Clients) || len(rep2.Groups) != len(rep.Groups) {
		t.Fatalf("export differs: users %d/%d clients %d/%d groups %d/%d",
			len(rep2.Users), len(rep.Users), len(rep2.Clients), len(rep.Clients), len(rep2.Groups), len(rep.Groups))
	}
}

func TestPartialExport(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	var rep map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/partial-export?exportClients=true&exportGroupsAndRoles=true", admin, nil, nil), 200).json(&rep)
	if _, ok := rep["users"]; ok {
		t.Fatal("partial export must not include users")
	}
	found := false
	for _, c := range rep["clients"].([]any) {
		c := c.(map[string]any)
		if c["clientId"] == "web" {
			found = true
			if c["secret"] != "**********" {
				t.Fatalf("secret not masked: %v", c["secret"])
			}
		}
	}
	if !found || len(rep["groups"].([]any)) != 1 {
		t.Fatalf("unexpected partial export %v", rep)
	}
}

func TestRealmSettingsPartialUpdate(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	e.expect(e.do(nil, "PUT", "/admin/realms/demo", admin, map[string]any{"resetPasswordAllowed": true, "supportedLocales": []string{"en", "vi"}}, nil), 204)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo", admin, map[string]any{"displayName": "Demo"}, nil), 204)
	var rep map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo", admin, nil, nil), 200).json(&rep)
	if rep["resetPasswordAllowed"] != true || rep["displayName"] != "Demo" || len(rep["supportedLocales"].([]any)) != 2 {
		t.Fatalf("settings lost on partial update: %v", rep)
	}
}
