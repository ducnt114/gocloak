// Package ldaptest is an in-memory LDAP directory for tests: simple bind,
// search with full filter support, add, modify, delete, and operational
// attributes (entryUUID, createTimestamp, modifyTimestamp). Passwords are
// plain userPassword values.
package ldaptest

import (
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
	"github.com/hashicorp/go-hclog"
	"github.com/jimlambrt/gldap"
)

// Entry is a directory entry. Attribute names keep their case; lookups
// ignore it.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// Get returns the values of an attribute.
func (e *Entry) Get(name string) []string {
	for k, v := range e.Attrs {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return nil
}

func (e *Entry) set(name string, values []string) {
	for k := range e.Attrs {
		if strings.EqualFold(k, name) {
			delete(e.Attrs, k)
		}
	}
	if len(values) > 0 {
		e.Attrs[name] = values
	}
}

// Server is a running directory.
type Server struct {
	URL      string
	AdminDN  string
	Password string

	// StableUUIDs derives entryUUID from the DN, so that a restarted
	// directory keeps its ids.
	StableUUIDs bool
	// Log, when set, receives a line per operation.
	Log func(format string, args ...any)

	srv     *gldap.Server
	mu      sync.Mutex
	entries map[string]*Entry // by normalized DN
	binds   int
}

// NormalizeDN lowercases a DN and removes spaces around separators.
func NormalizeDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		parts[i] = strings.ToLower(strings.TrimSpace(k)) + "=" + strings.ToLower(strings.TrimSpace(v))
	}
	return strings.Join(parts, ",")
}

// Start runs a directory on a free local port for a test; the admin DN
// binds with password and may do anything.
func Start(t testing.TB, adminDN, password string) *Server {
	t.Helper()
	s, err := Listen("127.0.0.1:0", adminDN, password)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// Listen runs a directory on addr ("host:0" picks a free port).
func Listen(addr, adminDN, password string) (*Server, error) {
	s := &Server{AdminDN: adminDN, Password: password, entries: map[string]*Entry{}}
	srv, err := gldap.NewServer(gldap.WithLogger(hclog.New(&hclog.LoggerOptions{Output: io.Discard})))
	if err != nil {
		return nil, err
	}
	mux, _ := gldap.NewMux()
	mux.Bind(s.bind)
	mux.Search(s.search)
	mux.Add(s.add)
	mux.Modify(s.modify)
	mux.Delete(s.delete)
	mux.DefaultRoute(func(w *gldap.ResponseWriter, r *gldap.Request) {
		w.Write(r.NewResponse(gldap.WithResponseCode(gldap.ResultUnwillingToPerform)))
	})
	srv.Router(mux)
	if strings.HasSuffix(addr, ":0") {
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		addr = l.Addr().String()
		l.Close()
	}
	go srv.Run(addr)
	for i := 0; i < 200 && !srv.Ready(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !srv.Ready() {
		return nil, fmt.Errorf("ldaptest: server on %s did not start", addr)
	}
	s.srv, s.URL = srv, "ldap://"+addr
	return s, nil
}

// Close stops the server.
func (s *Server) Close() { s.srv.Stop() }

func now() string { return time.Now().UTC().Format("20060102150405Z") }

// Add stores an entry (with its operational attributes).
func (s *Server) Add(dn string, attrs map[string][]string) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addLocked(dn, attrs)
}

func (s *Server) addLocked(dn string, attrs map[string][]string) *Entry {
	e := &Entry{DN: dn, Attrs: map[string][]string{}}
	for k, v := range attrs {
		e.Attrs[k] = append([]string(nil), v...)
	}
	if e.Get("entryUUID") == nil {
		e.Attrs["entryUUID"] = []string{s.newUUID(dn)}
	}
	t := now()
	e.Attrs["createTimestamp"], e.Attrs["modifyTimestamp"] = []string{t}, []string{t}
	s.entries[NormalizeDN(dn)] = e
	return e
}

func (s *Server) newUUID(dn string) string {
	if s.StableUUIDs {
		return uuid.NewSHA1(uuid.NameSpaceOID, []byte(NormalizeDN(dn))).String()
	}
	return uuid.NewString()
}

// Get returns a copy of an entry, or nil.
func (s *Server) Get(dn string) *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[NormalizeDN(dn)]
	if e == nil {
		return nil
	}
	c := &Entry{DN: e.DN, Attrs: map[string][]string{}}
	for k, v := range e.Attrs {
		c.Attrs[k] = append([]string(nil), v...)
	}
	return c
}

// Set replaces attributes of an entry and bumps modifyTimestamp.
func (s *Server) Set(dn string, attrs map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[NormalizeDN(dn)]
	for k, v := range attrs {
		e.set(k, v)
	}
	e.Attrs["modifyTimestamp"] = []string{now()}
}

// Remove deletes an entry.
func (s *Server) Remove(dn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, NormalizeDN(dn))
}

// Binds counts successful binds (connections and password checks).
func (s *Server) Binds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds
}

// ---------------------------------------------------------------- operations

func (s *Server) bind(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewBindResponse(gldap.WithResponseCode(gldap.ResultInvalidCredentials))
	defer w.Write(resp)
	m, err := r.GetSimpleBindMessage()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ok := false
	switch {
	case m.UserName == "" && m.Password == "":
		ok = true // anonymous
	case NormalizeDN(m.UserName) == NormalizeDN(s.AdminDN):
		ok = string(m.Password) == s.Password
	default:
		if e := s.entries[NormalizeDN(m.UserName)]; e != nil && m.Password != "" {
			for _, p := range e.Get("userPassword") {
				ok = ok || p == string(m.Password)
			}
		}
	}
	if ok {
		s.binds++
		resp.SetResultCode(gldap.ResultSuccess)
	}
	s.logf("bind %q ok=%v", m.UserName, ok)
}

func (s *Server) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

func inScope(dn, base string, scope gldap.Scope) bool {
	dn, base = NormalizeDN(dn), NormalizeDN(base)
	switch scope {
	case gldap.BaseObject:
		return dn == base
	case gldap.SingleLevel:
		_, parent, _ := strings.Cut(dn, ",")
		return parent == base
	default:
		return base == "" || dn == base || strings.HasSuffix(dn, ","+base)
	}
}

func (s *Server) search(w *gldap.ResponseWriter, r *gldap.Request) {
	done := r.NewSearchDoneResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer func() { w.Write(done) }()
	m, err := r.GetSearchMessage()
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		return
	}
	if m.BaseDN == "" && m.Scope == gldap.BaseObject {
		e := r.NewSearchResponseEntry("")
		e.AddAttribute("supportedExtension", []string{string(gldap.ExtendedOperationWhoAmI)})
		e.AddAttribute("supportedControl", []string{"1.2.840.113556.1.4.319"})
		e.AddAttribute("vendorName", []string{"gocloak ldaptest"})
		w.Write(e)
		return
	}
	s.logf("search base=%q scope=%d filter=%s attrs=%v controls=%d", m.BaseDN, m.Scope, m.Filter, m.Attributes, len(m.Controls))
	f, err := ldap.CompileFilter(m.Filter)
	if err != nil {
		done.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.mu.Lock()
	if s.entries[NormalizeDN(m.BaseDN)] == nil && m.BaseDN != "" && !s.hasChildren(m.BaseDN) {
		s.mu.Unlock()
		done.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	var found []*Entry
	for _, e := range s.entries {
		if inScope(e.DN, m.BaseDN, m.Scope) && match(f, e) {
			found = append(found, e)
		}
	}
	sort.Slice(found, func(i, j int) bool { return found[i].DN < found[j].DN })
	for _, e := range found {
		re := r.NewSearchResponseEntry(e.DN)
		for k, v := range e.Attrs {
			if strings.EqualFold(k, "userPassword") {
				continue
			}
			re.AddAttribute(k, v)
		}
		w.Write(re)
	}
	s.mu.Unlock()
}

func (s *Server) hasChildren(dn string) bool {
	for _, e := range s.entries {
		if strings.HasSuffix(NormalizeDN(e.DN), ","+NormalizeDN(dn)) {
			return true
		}
	}
	return false
}

func (s *Server) add(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewResponse(gldap.WithResponseCode(gldap.ResultSuccess), gldap.WithApplicationCode(gldap.ApplicationAddResponse))
	defer w.Write(resp)
	m, err := r.GetAddMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries[NormalizeDN(m.DN)] != nil {
		resp.SetResultCode(gldap.ResultEntryAlreadyExists)
		return
	}
	attrs := map[string][]string{}
	for _, a := range m.Attributes {
		attrs[a.Type] = berValues(a.Vals)
	}
	s.addLocked(m.DN, attrs)
}

func (s *Server) modify(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewModifyResponse(gldap.WithResponseCode(gldap.ResultSuccess))
	defer w.Write(resp)
	m, err := r.GetModifyMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[NormalizeDN(m.DN)]
	if e == nil {
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	for _, c := range m.Changes {
		name, vals := c.Modification.Type, berValues(c.Modification.Vals)
		switch c.Operation {
		case ldap.AddAttribute:
			e.set(name, append(e.Get(name), vals...))
		case ldap.DeleteAttribute:
			if len(vals) == 0 {
				e.set(name, nil)
				continue
			}
			var keep []string
			for _, v := range e.Get(name) {
				if !containsFold(vals, v) {
					keep = append(keep, v)
				}
			}
			e.set(name, keep)
		case ldap.ReplaceAttribute:
			e.set(name, vals)
		}
	}
	e.Attrs["modifyTimestamp"] = []string{now()}
}

func (s *Server) delete(w *gldap.ResponseWriter, r *gldap.Request) {
	resp := r.NewResponse(gldap.WithResponseCode(gldap.ResultSuccess), gldap.WithApplicationCode(gldap.ApplicationDelResponse))
	defer w.Write(resp)
	m, err := r.GetDeleteMessage()
	if err != nil {
		resp.SetResultCode(gldap.ResultProtocolError)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries[NormalizeDN(m.DN)] == nil {
		resp.SetResultCode(gldap.ResultNoSuchObject)
		return
	}
	delete(s.entries, NormalizeDN(m.DN))
}

// berValues works around gldap returning modify values with their BER
// octet string header.
func berValues(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = v
		if len(v) >= 2 && v[0] == 0x04 {
			if p, err := ber.DecodePacketErr([]byte(v)); err == nil && p.Data.Len()+2 <= len(v) {
				out[i] = p.Data.String()
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- filters

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func packetString(p *ber.Packet) string {
	if s, ok := p.Value.(string); ok {
		return s
	}
	return p.Data.String()
}

// match evaluates a compiled filter on an entry.
func match(f *ber.Packet, e *Entry) bool {
	switch f.Tag {
	case ldap.FilterAnd:
		for _, c := range f.Children {
			if !match(c, e) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range f.Children {
			if match(c, e) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(f.Children) == 1 && !match(f.Children[0], e)
	case ldap.FilterPresent:
		name := packetString(f)
		return strings.EqualFold(name, "objectClass") || len(e.Get(name)) > 0
	case ldap.FilterEqualityMatch, ldap.FilterApproxMatch:
		values := e.Get(packetString(f.Children[0]))
		want := packetString(f.Children[1])
		if strings.EqualFold(packetString(f.Children[0]), "member") || strings.EqualFold(packetString(f.Children[0]), "uniqueMember") {
			for _, v := range values {
				if NormalizeDN(v) == NormalizeDN(want) {
					return true
				}
			}
			return false
		}
		return containsFold(values, want)
	case ldap.FilterGreaterOrEqual, ldap.FilterLessOrEqual:
		want := packetString(f.Children[1])
		for _, v := range e.Get(packetString(f.Children[0])) {
			if (f.Tag == ldap.FilterGreaterOrEqual && v >= want) || (f.Tag == ldap.FilterLessOrEqual && v <= want) {
				return true
			}
		}
		return false
	case ldap.FilterSubstrings:
		for _, v := range e.Get(packetString(f.Children[0])) {
			if substrings(strings.ToLower(v), f.Children[1].Children) {
				return true
			}
		}
		return false
	}
	panic(fmt.Sprintf("ldaptest: unsupported filter tag %d", f.Tag))
}

func substrings(v string, parts []*ber.Packet) bool {
	for _, p := range parts {
		s := strings.ToLower(packetString(p))
		switch p.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(v, s) {
				return false
			}
			v = v[len(s):]
		case ldap.FilterSubstringsAny:
			i := strings.Index(v, s)
			if i < 0 {
				return false
			}
			v = v[i+len(s):]
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(v, s) {
				return false
			}
		}
	}
	return true
}

// Entries returns copies of all entries, sorted by DN.
func (s *Server) Entries() []*Entry {
	s.mu.Lock()
	var dns []string
	for _, e := range s.entries {
		dns = append(dns, e.DN)
	}
	s.mu.Unlock()
	sort.Strings(dns)
	out := make([]*Entry, 0, len(dns))
	for _, dn := range dns {
		out = append(out, s.Get(dn))
	}
	return out
}
