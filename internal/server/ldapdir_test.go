package server

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/ducnt114/gocloak/internal/ldaptest"
)

// directory is the LDAP server of the LDAP tests: the in-memory one, or a
// real server (OpenLDAP in CI) when GOCLOAK_TEST_LDAP_URL is set. A real
// server must have the base dc=example,dc=org with admin cn=admin and
// password GOCLOAK_TEST_LDAP_PASSWORD (default "secret").
type directory interface {
	URL() string
	Add(dn string, attrs map[string][]string)
	Get(dn string) *ldaptest.Entry
	Set(dn string, attrs map[string][]string)
	Remove(dn string)
}

type memDir struct{ *ldaptest.Server }

func (d memDir) URL() string                              { return d.Server.URL }
func (d memDir) Add(dn string, attrs map[string][]string) { d.Server.Add(dn, attrs) }

// newDirectory starts or connects to the test directory, emptied below the
// base DN.
func newDirectory(t *testing.T) directory {
	u := os.Getenv("GOCLOAK_TEST_LDAP_URL")
	if u == "" {
		return memDir{ldaptest.Start(t, ldapAdmin, "secret")}
	}
	pw := os.Getenv("GOCLOAK_TEST_LDAP_PASSWORD")
	if pw == "" {
		pw = "secret"
	}
	var c *ldap.Conn
	var err error
	for deadline := time.Now().Add(60 * time.Second); ; time.Sleep(time.Second) {
		if c, err = ldap.DialURL(u); err == nil {
			if err = c.Bind(ldapAdmin, pw); err == nil {
				break
			}
			c.Close()
		}
		if time.Now().After(deadline) {
			t.Fatalf("LDAP server %s: %v", u, err)
		}
	}
	t.Cleanup(func() { c.Close() })
	d := &realDir{t: t, c: c, url: u}
	d.clear("dc=example,dc=org")
	return d
}

// realDir is a directory on a real LDAP server.
type realDir struct {
	t   *testing.T
	c   *ldap.Conn
	url string
}

func (d *realDir) URL() string { return d.url }

func (d *realDir) clear(base string) {
	res, err := d.c.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, 0, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return
	}
	if err != nil {
		d.t.Fatal(err)
	}
	var dns []string
	for _, e := range res.Entries {
		if !strings.EqualFold(e.DN, base) && !strings.EqualFold(e.DN, ldapAdmin) {
			dns = append(dns, e.DN)
		}
	}
	// children first
	sort.Slice(dns, func(i, j int) bool { return strings.Count(dns[i], ",") > strings.Count(dns[j], ",") })
	for _, dn := range dns {
		if err := d.c.Del(ldap.NewDelRequest(dn, nil)); err != nil {
			d.t.Fatalf("delete %s: %v", dn, err)
		}
	}
}

func (d *realDir) Add(dn string, attrs map[string][]string) {
	req := ldap.NewAddRequest(dn, nil)
	for k, v := range attrs {
		req.Attribute(k, v)
	}
	if err := d.c.Add(req); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
		d.t.Fatalf("add %s: %v", dn, err)
	}
}

func (d *realDir) Get(dn string) *ldaptest.Entry {
	res, err := d.c.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, 0, 0, 0, false, "(objectClass=*)", []string{"*", "+"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil
		}
		d.t.Fatal(err)
	}
	if len(res.Entries) == 0 {
		return nil
	}
	e := &ldaptest.Entry{DN: res.Entries[0].DN, Attrs: map[string][]string{}}
	for _, a := range res.Entries[0].Attributes {
		e.Attrs[a.Name] = a.Values
	}
	return e
}

func (d *realDir) Set(dn string, attrs map[string][]string) {
	req := ldap.NewModifyRequest(dn, nil)
	for k, v := range attrs {
		req.Replace(k, v)
	}
	if err := d.c.Modify(req); err != nil {
		d.t.Fatalf("modify %s: %v", dn, err)
	}
}

func (d *realDir) Remove(dn string) {
	if err := d.c.Del(ldap.NewDelRequest(dn, nil)); err != nil {
		d.t.Fatalf("delete %s: %v", dn, err)
	}
}
