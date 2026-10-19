package federation

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"
)

// conn is a bound connection to a provider's directory.
type conn struct {
	*ldap.Conn
	cfg *Config
}

// dial connects to the directory (trying each URL of connectionUrl) and
// binds with the provider's credentials.
func dial(cfg *Config) (*conn, error) {
	c, err := dialOnly(cfg, cfg.ConnectionURL)
	if err != nil {
		return nil, err
	}
	if cfg.AuthType == "simple" {
		if err := c.Bind(cfg.BindDN, cfg.BindCredential); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

func dialOnly(cfg *Config, urls string) (*conn, error) {
	var lastErr error
	for _, u := range strings.Fields(urls) {
		d := &net.Dialer{Timeout: cfg.ConnectionTimeout}
		c, err := ldap.DialURL(u, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(&tls.Config{ServerName: hostOf(u)}))
		if err != nil {
			lastErr = err
			continue
		}
		c.SetTimeout(cfg.ReadTimeout)
		if cfg.StartTLS && strings.HasPrefix(strings.ToLower(u), "ldap://") {
			if err := c.StartTLS(&tls.Config{ServerName: hostOf(u)}); err != nil {
				c.Close()
				lastErr = err
				continue
			}
		}
		return &conn{Conn: c, cfg: cfg}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no connection URL")
	}
	return nil, lastErr
}

func hostOf(u string) string {
	u = u[strings.Index(u, "://")+3:]
	if i := strings.IndexAny(u, "/"); i >= 0 {
		u = u[:i]
	}
	if h, _, err := net.SplitHostPort(u); err == nil {
		return h
	}
	return u
}

// checkPassword binds as dn with password on a new connection.
func checkPassword(cfg *Config, dn, password string) (bool, error) {
	if password == "" {
		return false, nil // an empty password would be an anonymous bind
	}
	c, err := dialOnly(cfg, cfg.ConnectionURL)
	if err != nil {
		return false, err
	}
	defer c.Close()
	if err := c.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// userFilter is the filter of the provider's users, combined with extra.
func (cfg *Config) userFilter(extra string) string {
	var b strings.Builder
	b.WriteString("(&")
	for _, oc := range cfg.UserObjectClasses {
		b.WriteString("(objectclass=" + ldap.EscapeFilter(oc) + ")")
	}
	b.WriteString(cfg.CustomFilter)
	b.WriteString(extra)
	b.WriteString(")")
	return b.String()
}

func (cfg *Config) scope() int {
	if cfg.SearchScope == 2 {
		return ldap.ScopeWholeSubtree
	}
	return ldap.ScopeSingleLevel
}

// search runs a search, with paging when the provider enables it.
func (c *conn) search(base string, scope int, filter string, attrs []string) ([]*ldap.Entry, error) {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	var res *ldap.SearchResult
	var err error
	if c.cfg.Pagination {
		res, err = c.SearchWithPaging(req, uint32(c.cfg.BatchSize))
	} else {
		res, err = c.Search(req)
	}
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return nil, nil
		}
		return nil, err
	}
	return res.Entries, nil
}

// searchUsers finds the provider's users matching extra.
func (c *conn) searchUsers(extra string, attrs []string) ([]*ldap.Entry, error) {
	return c.search(c.cfg.UsersDN, c.cfg.scope(), c.cfg.userFilter(extra), attrs)
}

func eq(attr, value string) string { return "(" + attr + "=" + ldap.EscapeFilter(value) + ")" }

// uuidFilter matches an entry by its UUID attribute (objectGUID is binary).
func (cfg *Config) uuidFilter(id string) string {
	if strings.EqualFold(cfg.UUIDAttr, "objectGUID") {
		if b, err := guidBytes(id); err == nil {
			var sb strings.Builder
			for _, x := range b {
				fmt.Fprintf(&sb, "\\%02x", x)
			}
			return "(" + cfg.UUIDAttr + "=" + sb.String() + ")"
		}
	}
	return eq(cfg.UUIDAttr, id)
}

// entryUUID reads the UUID of an entry; AD's objectGUID is formatted as
// Keycloak does.
func (cfg *Config) entryUUID(e *ldap.Entry) string {
	if strings.EqualFold(cfg.UUIDAttr, "objectGUID") {
		if b := e.GetRawAttributeValue(cfg.UUIDAttr); len(b) == 16 {
			return formatGUID(b)
		}
	}
	return e.GetAttributeValue(cfg.UUIDAttr)
}

// formatGUID turns AD's little-endian GUID bytes into the usual string.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%s-%s", binary.LittleEndian.Uint32(b[0:4]), binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

func guidBytes(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(raw) != 16 {
		return nil, errors.New("invalid GUID")
	}
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], binary.BigEndian.Uint32(raw[0:4]))
	binary.LittleEndian.PutUint16(b[4:6], binary.BigEndian.Uint16(raw[4:6]))
	binary.LittleEndian.PutUint16(b[6:8], binary.BigEndian.Uint16(raw[6:8]))
	copy(b[8:], raw[8:])
	return b, nil
}

// entryByDN reads one entry.
func (c *conn) entryByDN(dn string, attrs []string) (*ldap.Entry, error) {
	entries, err := c.search(dn, ldap.ScopeBaseObject, "(objectclass=*)", attrs)
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	return entries[0], nil
}

// setPassword changes a user's password: unicodePwd on Active Directory,
// the password modify extended operation when enabled, else userPassword.
func (c *conn) setPassword(dn, password string) error {
	switch {
	case c.cfg.ActiveDirectory():
		quoted := utf16.Encode([]rune("\"" + password + "\""))
		b := make([]byte, len(quoted)*2)
		for i, r := range quoted {
			binary.LittleEndian.PutUint16(b[i*2:], r)
		}
		req := ldap.NewModifyRequest(dn, nil)
		req.Replace("unicodePwd", []string{string(b)})
		return c.Modify(req)
	case c.cfg.UsePasswordModifyExtOp:
		_, err := c.PasswordModify(ldap.NewPasswordModifyRequest(dn, "", password))
		return err
	}
	req := ldap.NewModifyRequest(dn, nil)
	req.Replace("userPassword", []string{password})
	return c.Modify(req)
}

// generalizedTime formats a time for LDAP filters.
func generalizedTime(t time.Time) string { return t.UTC().Format("20060102150405Z") }

// parseGeneralizedTime reads createTimestamp style values.
func parseGeneralizedTime(s string) (time.Time, bool) {
	for _, layout := range []string{"20060102150405Z", "20060102150405.0Z", "20060102150405.000Z", "20060102150405Z0700", "20060102150405-0700"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
