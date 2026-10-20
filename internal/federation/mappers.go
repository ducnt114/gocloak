package federation

import (
	"encoding/base64"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

// mapper is an LDAP mapper component.
type mapper struct{ *model.Component }

func (m mapper) bool(key string) bool { return m.Get(key) == "true" }

// attrMapper reports whether the mapper maps one LDAP attribute to one user
// property or attribute.
func (m mapper) attrMapper() bool {
	return m.ProviderID == "user-attribute-ldap-mapper" || m.ProviderID == "certificate-ldap-mapper"
}

// ldapAttrs lists the LDAP attributes the mappers read.
func ldapAttrs(cfg *Config, mappers []mapper) []string {
	set := map[string]bool{cfg.UsernameAttr: true, cfg.RDNAttr: true, cfg.UUIDAttr: true, "objectclass": true}
	for _, m := range mappers {
		switch {
		case m.attrMapper():
			set[m.Get("ldap.attribute")] = true
		case m.ProviderID == "full-name-ldap-mapper":
			set[fullNameAttr(m)] = true
		case m.ProviderID == "msad-user-account-control-mapper":
			set["userAccountControl"], set["pwdLastSet"] = true, true
		case m.ProviderID == "msad-lds-user-account-control-mapper":
			set["msDS-UserAccountDisabled"], set["pwdLastSet"] = true, true
		}
	}
	delete(set, "")
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func fullNameAttr(m mapper) string {
	if a := m.Get("ldap.full.name.attribute"); a != "" {
		return a
	}
	return "cn"
}

// values reads an attribute; the " " placeholder of mandatory attributes
// counts as empty, binary values are base64 encoded.
func values(e *ldap.Entry, attr string, binary bool) []string {
	if binary {
		var out []string
		for _, v := range e.GetRawAttributeValues(attr) {
			out = append(out, base64.StdEncoding.EncodeToString(v))
		}
		return out
	}
	var out []string
	for _, v := range e.GetEqualFoldAttributeValues(attr) {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func first(v []string) string {
	if len(v) > 0 {
		return v[0]
	}
	return ""
}

// setModel sets a user property or attribute and reports a change.
func setModel(u *model.User, name string, vals []string) bool {
	v := first(vals)
	switch name {
	case "username":
		v = strings.ToLower(v)
		if v == "" || u.Username == v {
			return false
		}
		u.Username = v
	case "email":
		v = strings.ToLower(v)
		if u.Email == v {
			return false
		}
		u.Email = v
	case "firstName":
		if u.FirstName == v {
			return false
		}
		u.FirstName = v
	case "lastName":
		if u.LastName == v {
			return false
		}
		u.LastName = v
	default:
		if u.Attributes == nil {
			u.Attributes = map[string][]string{}
		}
		if len(vals) == 0 {
			if _, ok := u.Attributes[name]; !ok {
				return false
			}
			delete(u.Attributes, name)
			return true
		}
		if slices.Equal(u.Attributes[name], vals) {
			return false
		}
		u.Attributes[name] = vals
	}
	return true
}

// modelValues reads a user property or attribute.
func modelValues(u *model.User, name string) []string {
	switch name {
	case "username":
		return nonEmpty(u.Username)
	case "email":
		return nonEmpty(u.Email)
	case "firstName":
		return nonEmpty(u.FirstName)
	case "lastName":
		return nonEmpty(u.LastName)
	}
	return u.Attributes[name]
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// importEntry copies LDAP values into the user. With proxyOnly, only the
// mappers that always read from LDAP apply (refresh at login).
func importEntry(cfg *Config, u *model.User, e *ldap.Entry, mappers []mapper, proxyOnly bool) bool {
	changed := false
	for _, m := range mappers {
		switch m.ProviderID {
		case "user-attribute-ldap-mapper", "certificate-ldap-mapper":
			if proxyOnly && !m.bool("always.read.value.from.ldap") {
				continue
			}
			vals := values(e, m.Get("ldap.attribute"), m.bool("is.binary.attribute"))
			if len(vals) == 0 && m.Get("attribute.default.value") != "" {
				vals = []string{m.Get("attribute.default.value")}
			}
			name := m.Get("user.model.attribute")
			if name == "username" && proxyOnly {
				continue
			}
			changed = setModel(u, name, vals) || changed
		case "full-name-ldap-mapper":
			if m.bool("write.only") {
				continue
			}
			full := strings.TrimSpace(first(values(e, fullNameAttr(m), false)))
			firstName, lastName := full, ""
			if i := strings.LastIndex(full, " "); i > 0 {
				firstName, lastName = full[:i], full[i+1:]
			}
			changed = setModel(u, "firstName", nonEmpty(firstName)) || changed
			changed = setModel(u, "lastName", nonEmpty(lastName)) || changed
		case "msad-user-account-control-mapper":
			if proxyOnly && m.Get("always.read.enabled.value.from.ldap") == "false" {
				continue
			}
			if uac, err := strconv.Atoi(e.GetAttributeValue("userAccountControl")); err == nil {
				enabled := uac&2 == 0
				changed = changed || u.Enabled != enabled
				u.Enabled = enabled
			}
			if !proxyOnly && e.GetAttributeValue("pwdLastSet") == "0" && !slices.Contains(u.RequiredActions, "UPDATE_PASSWORD") {
				u.RequiredActions = append(u.RequiredActions, "UPDATE_PASSWORD")
				changed = true
			}
		case "msad-lds-user-account-control-mapper":
			if v := e.GetAttributeValue("msDS-UserAccountDisabled"); v != "" {
				enabled := !strings.EqualFold(v, "true")
				changed = changed || u.Enabled != enabled
				u.Enabled = enabled
			}
		}
	}
	if setModel(u, AttrLDAPID, []string{cfg.entryUUID(e)}) {
		changed = true
	}
	if setModel(u, AttrLDAPDN, []string{e.DN}) {
		changed = true
	}
	return changed
}

// newEntry builds the attributes of a user written to LDAP.
func newEntry(cfg *Config, u *model.User, mappers []mapper) map[string][]string {
	attrs := map[string][]string{"objectclass": cfg.UserObjectClasses}
	for _, m := range mappers {
		switch m.ProviderID {
		case "user-attribute-ldap-mapper", "certificate-ldap-mapper":
			attr := m.Get("ldap.attribute")
			if m.bool("read.only") && m.Get("user.model.attribute") != "username" {
				continue
			}
			vals := modelValues(u, m.Get("user.model.attribute"))
			if len(vals) == 0 && m.bool("is.mandatory.in.ldap") {
				vals = []string{" "} // placeholder for mandatory attributes
			}
			if len(vals) > 0 {
				attrs[attr] = vals
			}
		case "full-name-ldap-mapper":
			if m.bool("read.only") {
				continue
			}
			attrs[fullNameAttr(m)] = []string{fullName(u)}
		case "hardcoded-ldap-attribute-mapper":
			if a := m.Get("ldap.attribute.name"); a != "" {
				attrs[a] = []string{m.Get("ldap.attribute.value")}
			}
		case "msad-user-account-control-mapper":
			uac := 512 // NORMAL_ACCOUNT
			if !u.Enabled {
				uac |= 2
			}
			attrs["userAccountControl"] = []string{strconv.Itoa(uac)}
		}
	}
	if len(attrs[cfg.RDNAttr]) == 0 {
		attrs[cfg.RDNAttr] = []string{u.Username}
	}
	return attrs
}

func fullName(u *model.User) string {
	name := strings.TrimSpace(u.FirstName + " " + u.LastName)
	if name == "" {
		return u.Username
	}
	return name
}

// userDN is the DN of a new user entry.
func userDN(cfg *Config, attrs map[string][]string) string {
	return ldap.EscapeDN(cfg.RDNAttr) + "=" + ldap.EscapeDN(first(attrs[cfg.RDNAttr])) + "," + cfg.UsersDN
}

// changes lists the LDAP modifications for an update of a user; a change
// of a read-only mapped value is a profile error.
func changes(cfg *Config, old, u *model.User, mappers []mapper) (map[string][]string, userprofile.Errors) {
	mods := map[string][]string{}
	var errs userprofile.Errors
	readOnly := func(field string) {
		errs = append(errs, userprofile.FieldError{Field: field, ErrorMessage: "error-user-attribute-read-only", Params: []any{field}})
	}
	for _, m := range mappers {
		switch m.ProviderID {
		case "user-attribute-ldap-mapper", "certificate-ldap-mapper":
			name := m.Get("user.model.attribute")
			before, after := modelValues(old, name), modelValues(u, name)
			if slices.Equal(before, after) {
				continue
			}
			if m.bool("read.only") || !cfg.Writable() {
				readOnly(name)
				continue
			}
			if len(after) == 0 && m.bool("is.mandatory.in.ldap") {
				after = []string{" "}
			}
			mods[m.Get("ldap.attribute")] = after
		case "full-name-ldap-mapper":
			if old.FirstName == u.FirstName && old.LastName == u.LastName {
				continue
			}
			if m.bool("read.only") || !cfg.Writable() {
				readOnly("firstName")
				continue
			}
			mods[fullNameAttr(m)] = []string{fullName(u)}
		case "msad-user-account-control-mapper":
			if old.Enabled != u.Enabled && cfg.Writable() {
				mods["userAccountControl"] = nil // filled from the current entry
			}
		}
	}
	return mods, errs
}
