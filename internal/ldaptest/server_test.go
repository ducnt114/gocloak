package ldaptest

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestDirectory(t *testing.T) {
	s := Start(t, "cn=admin,dc=example,dc=org", "secret")
	s.Add("ou=people,dc=example,dc=org", map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}})
	s.Add("uid=jdoe,ou=people,dc=example,dc=org", map[string][]string{"objectClass": {"inetOrgPerson", "organizationalPerson"},
		"uid": {"jdoe"}, "cn": {"John"}, "sn": {"Doe"}, "mail": {"jdoe@example.org"}, "userPassword": {"pw"}})
	c, err := ldap.DialURL(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind("uid=jdoe,ou=people,dc=example,dc=org", "bad"); err == nil {
		t.Fatal("bad password accepted")
	}
	if err := c.Bind("cn=admin,dc=example,dc=org", "secret"); err != nil {
		t.Fatal(err)
	}
	for filter, want := range map[string]int{
		"(&(objectClass=inetOrgPerson)(uid=JDOE))": 1, "(|(mail=x)(sn=d*))": 1, "(!(uid=jdoe))": 1, "(mail=*@example.org)": 1,
		"(entryUUID=*)": 2, "(&(uid=jdoe)(!(cn=John)))": 0,
	} {
		res, err := c.Search(ldap.NewSearchRequest("dc=example,dc=org", ldap.ScopeWholeSubtree, 0, 0, 0, false, filter, nil, nil))
		if err != nil || len(res.Entries) != want {
			t.Fatalf("%s: %v %d", filter, err, len(res.Entries))
		}
	}
	mod := ldap.NewModifyRequest("uid=jdoe,ou=people,dc=example,dc=org", nil)
	mod.Replace("cn", []string{"Johnny"})
	if err := c.Modify(mod); err != nil {
		t.Fatal(err)
	}
	pw := ldap.NewModifyRequest("uid=jdoe,ou=people,dc=example,dc=org", nil)
	pw.Replace("userPassword", []string{"new"})
	if err := c.Modify(pw); err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("uid=jdoe,ou=people,dc=example,dc=org", "new"); err != nil {
		t.Fatal(err)
	}
	add := ldap.NewAddRequest("uid=ann,ou=people,dc=example,dc=org", nil)
	add.Attribute("objectClass", []string{"inetOrgPerson"})
	add.Attribute("uid", []string{"ann"})
	add.Attribute("sn", []string{"Smith"})
	if err := c.Add(add); err != nil {
		t.Fatal(err)
	}
	if e := s.Get("uid=ann,ou=people,dc=example,dc=org"); e == nil || e.Get("sn")[0] != "Smith" || e.Get("entryUUID") == nil {
		t.Fatalf("added entry: %+v", e)
	}
	if err := c.Del(ldap.NewDelRequest("uid=ann,ou=people,dc=example,dc=org", nil)); err != nil || s.Get("uid=ann,ou=people,dc=example,dc=org") != nil {
		t.Fatalf("delete: %v", err)
	}
	if s.Get("uid=jdoe,ou=people,dc=example,dc=org").Get("cn")[0] != "Johnny" {
		t.Fatal("modify not applied")
	}
}
