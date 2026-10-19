package server

import (
	"context"

	"github.com/go-ldap/ldap/v3"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	ldapAdmin  = "cn=admin,dc=example,dc=org"
	peopleDN   = "ou=people,dc=example,dc=org"
	groupsDN   = "ou=groups,dc=example,dc=org"
	ldapMapper = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
)

// seedDirectory starts a directory with three users and three groups
// (backend nested in devs).
func seedDirectory(t *testing.T) directory {
	d := newDirectory(t)
	d.Add("dc=example,dc=org", map[string][]string{"objectClass": {"dcObject", "organization"}, "dc": {"example"}, "o": {"Example"}})
	d.Add(peopleDN, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}})
	d.Add(groupsDN, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"groups"}})
	for _, u := range [][4]string{{"jdoe", "John", "Doe", "jdoe@example.org"}, {"asmith", "Ann", "Smith", "ann@example.org"}, {"bob", "Bob", "Builder", "bob@example.org"}} {
		addLDAPUser(d, u[0], u[1], u[2], u[3])
	}
	d.Add("cn=devs,"+groupsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"devs"},
		"member": {"uid=jdoe," + peopleDN, "cn=backend," + groupsDN}})
	d.Add("cn=backend,"+groupsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"backend"}, "member": {"uid=asmith," + peopleDN}})
	d.Add("cn=admins,"+groupsDN, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"admins"}, "member": {"uid=jdoe," + peopleDN}})
	return d
}

func addLDAPUser(d directory, uid, first, last, mail string) {
	d.Add("uid="+uid+","+peopleDN, map[string][]string{"objectClass": {"inetOrgPerson", "organizationalPerson", "person"},
		"uid": {uid}, "cn": {first}, "sn": {last}, "mail": {mail}, "userPassword": {uid + "-pw"}})
}

// addLDAP registers the directory as user storage provider of realm demo.
func (e *env) addLDAP(admin string, d directory, extra map[string]string) string {
	e.t.Helper()
	realm := map[string]any{}
	e.expect(e.do(nil, "GET", "/admin/realms/demo", admin, nil, nil), 200).json(&realm)
	cfg := map[string][]string{"enabled": {"true"}, "vendor": {"other"}, "connectionUrl": {d.URL()}, "bindDn": {ldapAdmin},
		"bindCredential": {"secret"}, "usersDn": {peopleDN}, "usernameLDAPAttribute": {"uid"}, "rdnLDAPAttribute": {"uid"},
		"uuidLDAPAttribute": {"entryUUID"}, "userObjectClasses": {"inetOrgPerson, organizationalPerson"}, "editMode": {"WRITABLE"},
		"authType": {"simple"}, "searchScope": {"1"}, "syncRegistrations": {"true"}}
	for k, v := range extra {
		cfg[k] = []string{v}
	}
	return idFromLocation(e.t, e.expect(e.do(nil, "POST", "/admin/realms/demo/components", admin, map[string]any{
		"name": "ldap", "providerId": "ldap", "providerType": "org.keycloak.storage.UserStorageProvider", "parentId": realm["id"], "config": cfg,
	}, nil), 201))
}

func (e *env) userByName(admin, username string) map[string]any {
	e.t.Helper()
	var users []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users?exact=true&username="+url.QueryEscape(username), admin, nil, nil), 200).json(&users)
	if len(users) != 1 {
		return nil
	}
	return users[0]
}

func TestLDAPProviderAndLogin(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	d := seedDirectory(t)
	cid := e.addLDAP(admin, d, nil)

	var mappers []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/components?parent="+cid, admin, nil, nil), 200).json(&mappers)
	if len(mappers) != 7 {
		t.Fatalf("default mappers: %v", mappers)
	}
	var comp map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/components/"+cid, admin, nil, nil), 200).json(&comp)
	if strs(comp["config"].(map[string]any)["bindCredential"])[0] != "**********" {
		t.Fatalf("bind credential not masked: %v", comp["config"])
	}

	// connection test
	test := map[string]string{"action": "testAuthentication", "connectionUrl": d.URL(), "bindDn": ldapAdmin, "bindCredential": "secret"}
	e.expect(e.do(nil, "POST", "/admin/realms/demo/testLDAPConnection", admin, test, nil), 204)
	test["bindCredential"] = "**********"
	test["componentId"] = cid
	e.expect(e.do(nil, "POST", "/admin/realms/demo/testLDAPConnection", admin, test, nil), 204)
	test["bindCredential"] = "wrong"
	if r := e.expect(e.do(nil, "POST", "/admin/realms/demo/testLDAPConnection", admin, test, nil), 400); !strings.Contains(string(r.body), "AuthenticationFailure") {
		t.Fatalf("bad credentials: %s", r.body)
	}

	// login imports the user; the password is checked with an LDAP bind
	if _, r := e.passwordGrant("demo", "web", "web-secret", "jdoe", "wrong"); r.status != 401 {
		t.Fatalf("wrong password: %d", r.status)
	}
	tk, r := e.passwordGrant("demo", "web", "web-secret", "jdoe", "jdoe-pw")
	e.expect(r, 200)
	c := claims(t, tk.AccessToken)
	if c.String("preferred_username") != "jdoe" || c.String("email") != "jdoe@example.org" || c.String("given_name") != "John" {
		t.Fatalf("claims: %v", c)
	}
	jdoe := e.userByName(admin, "jdoe")
	if jdoe["federationLink"] != cid || strs(jdoe["attributes"].(map[string]any)["LDAP_ENTRY_DN"])[0] != "uid=jdoe,"+peopleDN {
		t.Fatalf("imported user: %v", jdoe)
	}
	var types []string
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+jdoe["id"].(string)+"/configured-user-storage-credential-types", admin, nil, nil), 200).json(&types)
	if !slices.Equal(types, []string{"password"}) {
		t.Fatalf("credential types: %v", types)
	}

	// login by email, for a user that appears in LDAP later
	addLDAPUser(d, "carol", "Carol", "Danvers", "carol@example.org")
	if _, r := e.passwordGrant("demo", "web", "web-secret", "carol@example.org", "carol-pw"); r.status != 200 {
		t.Fatalf("login by email: %d %s", r.status, r.body)
	}

	// changes in LDAP are read at login (always.read.value.from.ldap)
	d.Set("uid=jdoe,"+peopleDN, map[string][]string{"cn": {"Johnny"}})
	tk, _ = e.passwordGrant("demo", "web", "web-secret", "jdoe", "jdoe-pw")
	if claims(t, tk.AccessToken).String("given_name") != "Johnny" {
		t.Fatalf("first name not refreshed")
	}

	// WRITABLE: profile and password changes go to LDAP
	id := jdoe["id"].(string)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id, admin, map[string]any{"firstName": "Jon", "email": "jon@example.org"}, nil), 204)
	if en := d.Get("uid=jdoe," + peopleDN); en.Get("cn")[0] != "Jon" || en.Get("mail")[0] != "jon@example.org" {
		t.Fatalf("ldap entry after update: %v", en.Attrs)
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id+"/reset-password", admin, map[string]any{"type": "password", "value": "New-pw-1", "temporary": false}, nil), 204)
	if !ldapBind(t, d, "uid=jdoe,"+peopleDN, "New-pw-1") {
		t.Fatalf("password not written to LDAP")
	}
	var creds []any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+id+"/credentials", admin, nil, nil), 200).json(&creds)
	if len(creds) != 0 {
		t.Fatalf("password stored locally: %v", creds)
	}
	if _, r := e.passwordGrant("demo", "web", "web-secret", "jdoe", "New-pw-1"); r.status != 200 {
		t.Fatalf("login with the new password: %d", r.status)
	}

	// syncRegistrations: new users are created in LDAP
	nid := idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/users", admin, map[string]any{
		"username": "neo", "email": "neo@example.org", "firstName": "Thomas", "lastName": "Anderson", "enabled": true,
		"credentials": []map[string]any{{"type": "password", "value": "Matrix-1"}},
	}, nil), 201))
	en := d.Get("uid=neo," + peopleDN)
	if en == nil || en.Get("cn")[0] != "Thomas" || en.Get("sn")[0] != "Anderson" || !ldapBind(t, d, "uid=neo,"+peopleDN, "Matrix-1") {
		t.Fatalf("registered entry: %+v", en)
	}
	if u := e.userByName(admin, "neo"); u["federationLink"] != cid {
		t.Fatalf("registered user not linked: %v", u)
	}
	// deleting the user deletes the entry (WRITABLE)
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/users/"+nid, admin, nil, nil), 204)
	if d.Get("uid=neo,"+peopleDN) != nil {
		t.Fatal("entry left in LDAP")
	}

	// an entry removed from LDAP removes the imported user at login
	d.Remove("uid=carol," + peopleDN)
	if _, r := e.passwordGrant("demo", "web", "web-secret", "carol", "carol-pw"); r.status != 401 {
		t.Fatalf("removed user logged in: %d", r.status)
	}
	if e.userByName(admin, "carol") != nil {
		t.Fatal("removed user still imported")
	}

	// admins may not rename users unless the realm allows it
	r = e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id, admin, map[string]any{"username": "johnd"}, nil), 400)
	if !strings.Contains(string(r.body), "error-user-attribute-read-only") {
		t.Fatalf("rename: %s", r.body)
	}
}

func TestLDAPSyncAndEditModes(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	d := seedDirectory(t)
	cid := e.addLDAP(admin, d, map[string]string{"editMode": "READ_ONLY", "syncRegistrations": "false"})

	var res map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/sync?action=triggerFullSync", admin, nil, nil), 200).json(&res)
	if res["added"] != 3.0 || res["status"] != "3 imported users, 0 updated users" {
		t.Fatalf("full sync: %v", res)
	}
	addLDAPUser(d, "dave", "Dave", "Grohl", "dave@example.org")
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/sync?action=triggerChangedUsersSync", admin, nil, nil), 200).json(&res)
	if res["added"] != 1.0 {
		t.Fatalf("changed sync: %v", res)
	}
	d.Remove("uid=bob," + peopleDN)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/sync?action=triggerFullSync", admin, nil, nil), 200).json(&res)
	if res["removed"] != 1.0 || res["updated"] != 3.0 || !strings.HasSuffix(res["status"].(string), ", 1 removed users") {
		t.Fatalf("full sync with removal: %v", res)
	}

	// READ_ONLY: mapped attributes and the password cannot change
	jdoe := e.userByName(admin, "jdoe")
	id := jdoe["id"].(string)
	r := e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id, admin, map[string]any{"firstName": "Jon"}, nil), 400)
	if !strings.Contains(string(r.body), `"field":"firstName"`) || !strings.Contains(string(r.body), "error-user-attribute-read-only") {
		t.Fatalf("read only update: %s", r.body)
	}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id+"/reset-password", admin, map[string]any{"type": "password", "value": "New-pw-1"}, nil), 400)
	// unmapped changes are fine
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id, admin, map[string]any{"enabled": false}, nil), 204)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id, admin, map[string]any{"enabled": true}, nil), 204)

	// UNSYNCED: changes stay local, the local password wins
	var comp map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/components/"+cid, admin, nil, nil), 200).json(&comp)
	comp["config"].(map[string]any)["editMode"] = []string{"UNSYNCED"}
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/components/"+cid, admin, comp, nil), 204)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+id+"/reset-password", admin, map[string]any{"type": "password", "value": "Local-pw-1", "temporary": false}, nil), 204)
	if !ldapBind(t, d, "uid=jdoe,"+peopleDN, "jdoe-pw") {
		t.Fatal("UNSYNCED password written to LDAP")
	}
	if _, r := e.passwordGrant("demo", "web", "web-secret", "jdoe", "Local-pw-1"); r.status != 200 {
		t.Fatalf("local password login: %d %s", r.status, r.body)
	}

	// remove / unlink imported users
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/unlink-users", admin, nil, nil), 204)
	if u := e.userByName(admin, "asmith"); u == nil || u["federationLink"] != nil {
		t.Fatalf("unlinked user: %v", u)
	}
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/sync?action=triggerFullSync", admin, nil, nil), 200).json(&res)
	if res["failed"] != 3.0 {
		t.Fatalf("sync over unlinked users: %v", res)
	}

	// deleting the provider deletes its mappers
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/components/"+cid, admin, nil, nil), 204)
	var left []any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/components?type="+ldapMapper, admin, nil, nil), 200).json(&left)
	if len(left) != 0 {
		t.Fatalf("mappers left: %v", left)
	}
}

func TestLDAPGroupAndRoleMappers(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	d := seedDirectory(t)
	cid := e.addLDAP(admin, d, nil)
	mapper := func(name, provider string, cfg map[string][]string) string {
		return idFromLocation(t, e.expect(e.do(nil, "POST", "/admin/realms/demo/components", admin, map[string]any{
			"name": name, "providerId": provider, "providerType": ldapMapper, "parentId": cid, "config": cfg}, nil), 201))
	}
	bad := e.expect(e.do(nil, "POST", "/admin/realms/demo/components", admin, map[string]any{
		"name": "g", "providerId": "group-ldap-mapper", "providerType": ldapMapper, "parentId": cid, "config": map[string][]string{}}, nil), 400)
	if !strings.Contains(string(bad.body), "Missing configuration for LDAP Groups DN") {
		t.Fatalf("validation: %s", bad.body)
	}
	gm := mapper("groups", "group-ldap-mapper", map[string][]string{"groups.dn": {groupsDN}, "mode": {"LDAP_ONLY"},
		"membership.attribute.type": {"DN"}, "preserve.group.inheritance": {"true"}})
	var res map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/mappers/"+gm+"/sync?direction=fedToKeycloak", admin, nil, nil), 200).json(&res)
	if res["added"] != 3.0 || res["status"] != "3 imported groups, 0 updated groups, 0 removed groups" {
		t.Fatalf("group sync: %v", res)
	}
	var backend map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/group-by-path/devs/backend", admin, nil, nil), 200).json(&backend)

	mapper("roles", "role-ldap-mapper", map[string][]string{"roles.dn": {groupsDN}, "mode": {"READ_ONLY"}, "use.realm.roles.mapping": {"true"}})
	mapper("hardcoded", "hardcoded-ldap-role-mapper", map[string][]string{"role": {"editor"}})

	tk, r := e.passwordGrant("demo", "web", "web-secret", "jdoe", "jdoe-pw")
	e.expect(r, 200)
	roles := realmRoles(claims(t, tk.AccessToken))
	for _, want := range []string{"admins", "devs", "editor"} {
		if !slices.Contains(roles, want) {
			t.Fatalf("role %s missing: %v", want, roles)
		}
	}
	tk, _ = e.passwordGrant("demo", "web", "web-secret", "asmith", "asmith-pw")
	asmith := e.userByName(admin, "asmith")
	var groups []map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/users/"+asmith["id"].(string)+"/groups", admin, nil, nil), 200).json(&groups)
	if len(groups) != 1 || groups[0]["path"] != "/devs/backend" {
		t.Fatalf("asmith groups: %v", groups)
	}

	// LDAP_ONLY: membership changes are written to LDAP
	var admins map[string]any
	e.expect(e.do(nil, "GET", "/admin/realms/demo/group-by-path/admins", admin, nil, nil), 200).json(&admins)
	e.expect(e.do(nil, "PUT", "/admin/realms/demo/users/"+asmith["id"].(string)+"/groups/"+admins["id"].(string), admin, nil, nil), 204)
	if !slices.Contains(d.Get("cn=admins,"+groupsDN).Get("member"), "uid=asmith,"+peopleDN) {
		t.Fatalf("membership not written: %v", d.Get("cn=admins,"+groupsDN).Attrs)
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo/users/"+asmith["id"].(string)+"/groups/"+backend["id"].(string), admin, nil, nil), 204)
	if m := d.Get("cn=backend," + groupsDN).Get("member"); len(m) != 1 || m[0] != "cn=empty-membership-placeholder" {
		t.Fatalf("membership not removed: %v", m)
	}

	// keycloakToFed creates LDAP groups for local ones
	e.expect(e.do(nil, "POST", "/admin/realms/demo/groups", admin, map[string]any{"name": "ops"}, nil), 201)
	e.expect(e.do(nil, "POST", "/admin/realms/demo/user-storage/"+cid+"/mappers/"+gm+"/sync?direction=keycloakToFed", admin, nil, nil), 200).json(&res)
	if d.Get("cn=ops,"+groupsDN) == nil {
		t.Fatalf("group not created in LDAP: %v", res)
	}
}

func TestLDAPPeriodicSyncAndExport(t *testing.T) {
	e := newEnv(t)
	admin, _ := e.setupDemo()
	d := seedDirectory(t)
	cid := e.addLDAP(admin, d, map[string]string{"fullSyncPeriod": "1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go e.app.Fed.RunPeriodicSync(ctx, 50*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for e.userByName(admin, "bob") == nil {
		if time.Now().After(deadline) {
			t.Fatal("periodic sync did not import users")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()

	// a realm export keeps the provider, its mappers and the user links
	var exp map[string]any
	e.expect(e.do(nil, "POST", "/admin/realms/demo/partial-export", admin, nil, nil), 200).json(&exp)
	storage := exp["components"].(map[string]any)["org.keycloak.storage.UserStorageProvider"].([]any)[0].(map[string]any)
	if storage["id"] != cid || len(storage["subComponents"].(map[string]any)[ldapMapper].([]any)) != 7 ||
		strs(storage["config"].(map[string]any)["bindCredential"])[0] != "**********" {
		t.Fatalf("exported provider: %v", storage)
	}
	full, err := e.app.ExportRealm(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	e.expect(e.do(nil, "DELETE", "/admin/realms/demo", admin, nil, nil), 204)
	if d.Get("uid=bob,"+peopleDN) == nil {
		t.Fatal("deleting the realm touched LDAP")
	}
	e.expect(e.do(nil, "POST", "/admin/realms", admin, full, nil), 201)
	if u := e.userByName(admin, "bob"); u == nil || u["federationLink"] != cid {
		t.Fatalf("imported user: %v", u)
	}
	if _, r := e.passwordGrant("demo", "web", "web-secret", "bob", "bob-pw"); r.status != 200 {
		t.Fatalf("login in the imported realm: %d %s", r.status, r.body)
	}
}

// ldapBind checks a password with a bind.
func ldapBind(t *testing.T, d directory, dn, password string) bool {
	t.Helper()
	c, err := ldap.DialURL(d.URL())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.Bind(dn, password) == nil
}
