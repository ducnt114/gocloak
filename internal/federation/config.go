// Package federation implements user federation with LDAP, as the "ldap"
// user storage provider: users are looked up in the directory and
// imported, passwords are checked with an LDAP bind, and in WRITABLE mode
// changes are written back. The provider and its mappers are components.
package federation

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// Component types and provider ids.
const (
	ProviderType = "org.gocloak.storage.UserStorageProvider"
	MapperType   = "org.gocloak.storage.ldap.mappers.LDAPStorageMapper"
	ProviderLDAP = "ldap"

	// Attributes of imported users.
	AttrLDAPID = "LDAP_ID"
	AttrLDAPDN = "LDAP_ENTRY_DN"
)

// Edit modes.
const (
	ReadOnly = "READ_ONLY"
	Writable = "WRITABLE"
	Unsynced = "UNSYNCED"
)

// Config is the parsed configuration of an LDAP provider component.
type Config struct {
	ID, Name                 string
	Enabled                  bool
	Priority                 int
	Vendor                   string
	ConnectionURL            string
	BindDN, BindCredential   string
	AuthType                 string // simple or none
	StartTLS                 bool
	UsersDN                  string
	UsernameAttr, RDNAttr    string
	UUIDAttr                 string
	UserObjectClasses        []string
	CustomFilter             string
	SearchScope              int // 1 one level, 2 subtree
	EditMode                 string
	ImportEnabled            bool
	SyncRegistrations        bool
	TrustEmail               bool
	Pagination               bool
	BatchSize                int
	FullSyncPeriod           int // seconds, -1 disabled
	ChangedSyncPeriod        int
	LastSync                 int64 // unix seconds
	UsePasswordModifyExtOp   bool
	ValidatePasswordPolicy   bool
	ConnectionTimeout        time.Duration
	ReadTimeout              time.Duration
	RemoveInvalidUsers       bool
	AllowKerberos, UseKrbPwd bool
}

func boolCfg(c *model.Component, key string, def bool) bool {
	switch c.Get(key) {
	case "true":
		return true
	case "false":
		return false
	}
	return def
}

func intCfg(c *model.Component, key string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(c.Get(key))); err == nil {
		return n
	}
	return def
}

// ParseConfig reads an LDAP provider component.
func ParseConfig(c *model.Component) *Config {
	cfg := &Config{
		ID: c.ID, Name: c.Name,
		Enabled:                boolCfg(c, "enabled", true),
		Priority:               intCfg(c, "priority", 0),
		Vendor:                 c.Get("vendor"),
		ConnectionURL:          strings.TrimSpace(c.Get("connectionUrl")),
		BindDN:                 c.Get("bindDn"),
		BindCredential:         c.Get("bindCredential"),
		AuthType:               c.Get("authType"),
		StartTLS:               boolCfg(c, "startTls", false),
		UsersDN:                c.Get("usersDn"),
		UsernameAttr:           c.Get("usernameLDAPAttribute"),
		RDNAttr:                c.Get("rdnLDAPAttribute"),
		UUIDAttr:               c.Get("uuidLDAPAttribute"),
		CustomFilter:           strings.TrimSpace(c.Get("customUserSearchFilter")),
		SearchScope:            intCfg(c, "searchScope", 1),
		EditMode:               c.Get("editMode"),
		ImportEnabled:          boolCfg(c, "importEnabled", true),
		SyncRegistrations:      boolCfg(c, "syncRegistrations", false),
		TrustEmail:             boolCfg(c, "trustEmail", false),
		Pagination:             boolCfg(c, "pagination", false),
		BatchSize:              intCfg(c, "batchSizeForSync", 1000),
		FullSyncPeriod:         intCfg(c, "fullSyncPeriod", -1),
		ChangedSyncPeriod:      intCfg(c, "changedSyncPeriod", -1),
		LastSync:               int64(intCfg(c, "lastSync", 0)),
		UsePasswordModifyExtOp: boolCfg(c, "usePasswordModifyExtendedOp", false),
		ValidatePasswordPolicy: boolCfg(c, "validatePasswordPolicy", false),
		ConnectionTimeout:      time.Duration(intCfg(c, "connectionTimeout", 10000)) * time.Millisecond,
		ReadTimeout:            time.Duration(intCfg(c, "readTimeout", 30000)) * time.Millisecond,
		RemoveInvalidUsers:     boolCfg(c, "removeInvalidUsersEnabled", true),
		AllowKerberos:          boolCfg(c, "allowKerberosAuthentication", false),
		UseKrbPwd:              boolCfg(c, "useKerberosForPasswordAuthentication", false),
	}
	if cfg.AuthType == "" {
		cfg.AuthType = "simple"
		if cfg.BindDN == "" {
			cfg.AuthType = "none"
		}
	}
	for _, oc := range strings.Split(c.Get("userObjectClasses"), ",") {
		if oc = strings.TrimSpace(oc); oc != "" {
			cfg.UserObjectClasses = append(cfg.UserObjectClasses, oc)
		}
	}
	if cfg.UsernameAttr == "" {
		cfg.UsernameAttr = "uid"
	}
	if cfg.RDNAttr == "" {
		cfg.RDNAttr = cfg.UsernameAttr
	}
	if cfg.UUIDAttr == "" {
		cfg.UUIDAttr = "entryUUID"
		if cfg.ActiveDirectory() {
			cfg.UUIDAttr = "objectGUID"
		}
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 1000
	}
	return cfg
}

// ActiveDirectory reports whether the vendor is Microsoft AD.
func (c *Config) ActiveDirectory() bool { return c.Vendor == "ad" }

// Writable reports whether changes are written to LDAP.
func (c *Config) Writable() bool { return c.EditMode == Writable }

// ValidateConfig checks a provider configuration when it is saved.
func ValidateConfig(c *model.Component) string {
	switch c.Get("editMode") {
	case ReadOnly, Writable, Unsynced:
	case "":
		return "Edit Mode is mandatory"
	default:
		return "Invalid Edit Mode"
	}
	if c.Get("customUserSearchFilter") != "" {
		f := strings.TrimSpace(c.Get("customUserSearchFilter"))
		if !strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")") {
			return "Custom User LDAP Filter must start with '(' and end with ')'"
		}
	}
	return ""
}

// PrepareProvider fills the defaults of a new provider.
func PrepareProvider(c *model.Component) {
	if c.Get("krbPrincipalAttribute") == "" {
		attr := "krb5PrincipalName"
		if c.Get("vendor") == "ad" {
			attr = "userPrincipalName"
		}
		c.Set("krbPrincipalAttribute", attr)
	}
}

// DefaultMappers are the mappers created with a new provider.
func DefaultMappers(c *model.Component) []*model.Component {
	cfg := ParseConfig(c)
	readOnly := strconv.FormatBool(cfg.EditMode != Writable)
	alwaysRead := strconv.FormatBool(cfg.EditMode != Unsynced)
	ad := cfg.ActiveDirectory()
	attr := func(name, ldapAttr, modelAttr, ro, always, mandatory string) *model.Component {
		return &model.Component{Name: name, ProviderID: "user-attribute-ldap-mapper", ProviderType: MapperType, ParentID: c.ID,
			Config: map[string][]string{"ldap.attribute": {ldapAttr}, "user.model.attribute": {modelAttr}, "read.only": {ro},
				"always.read.value.from.ldap": {always}, "is.mandatory.in.ldap": {mandatory}}}
	}
	firstName := "cn"
	if ad || strings.EqualFold(cfg.RDNAttr, "cn") {
		firstName = "givenName"
	}
	created, modified := "createTimestamp", "modifyTimestamp"
	if ad {
		created, modified = "whenCreated", "whenChanged"
	}
	out := []*model.Component{
		attr("username", cfg.UsernameAttr, "username", readOnly, "false", "true"),
		attr("first name", firstName, "firstName", readOnly, alwaysRead, "true"),
		attr("last name", "sn", "lastName", readOnly, alwaysRead, "true"),
		attr("email", "mail", "email", readOnly, "false", "false"),
		attr("creation date", created, "createTimestamp", "true", alwaysRead, "false"),
		attr("modify date", modified, "modifyTimestamp", "true", alwaysRead, "false"),
		{Name: "Kerberos principal attribute mapper", ProviderID: "kerberos-principal-attribute-mapper", ProviderType: MapperType,
			ParentID: c.ID, Config: map[string][]string{}},
	}
	if strings.EqualFold(cfg.RDNAttr, "cn") && !strings.EqualFold(cfg.UsernameAttr, "cn") {
		out = append(out, attr("username-cn", "cn", "username", readOnly, "false", "true"))
	}
	if ad {
		out = append(out, &model.Component{Name: "MSAD account controls", ProviderID: "msad-user-account-control-mapper",
			ProviderType: MapperType, ParentID: c.ID, Config: map[string][]string{"always.read.enabled.value.from.ldap": {"true"}}})
	}
	return out
}

// MapperProviders are the supported LDAP mapper types.
var MapperProviders = map[string]bool{
	"user-attribute-ldap-mapper": true, "full-name-ldap-mapper": true, "group-ldap-mapper": true,
	"role-ldap-mapper": true, "hardcoded-ldap-role-mapper": true, "hardcoded-ldap-group-mapper": true,
	"hardcoded-ldap-attribute-mapper": true, "certificate-ldap-mapper": true, "msad-user-account-control-mapper": true,
	"msad-lds-user-account-control-mapper": true, "kerberos-principal-attribute-mapper": true,
}

// ValidateMapper checks an LDAP mapper when it is saved, filling defaults.
// plain marks errors rendered as {"error": ...}.
func ValidateMapper(ctx context.Context, st *store.Store, realm *model.Realm, c *model.Component) (msg string, plain bool) {
	missing := func(key, label string) bool {
		if strings.TrimSpace(c.Get(key)) == "" {
			msg = "Missing configuration for " + label
			return true
		}
		return false
	}
	filterOK := func(key string) bool {
		f := strings.TrimSpace(c.Get(key))
		if f != "" && (!strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")")) {
			msg = `Custom configured LDAP filter does not start with "(" or does not end with ")".`
			return false
		}
		return true
	}
	switch c.ProviderID {
	case "user-attribute-ldap-mapper", "certificate-ldap-mapper":
		if missing("user.model.attribute", "User Model Attribute") || missing("ldap.attribute", "LDAP Attribute") {
			return msg, false
		}
	case "full-name-ldap-mapper":
		if missing("ldap.full.name.attribute", "LDAP Full Name Attribute") {
			return msg, false
		}
	case "hardcoded-ldap-attribute-mapper":
		if c.Get("ldap.attribute.name") == "" {
			return "'LDAP Attribute Name' is required", false
		}
		if c.Get("ldap.attribute.value") == "" {
			return "'LDAP Attribute Value' is required", false
		}
	case "hardcoded-ldap-role-mapper":
		if c.Get("role") == "" {
			return "Role cant be null", false
		}
		if _, err := findRoleRef(ctx, st, realm, c.Get("role")); err != nil {
			return "There is no role corresponding to configured value", false
		}
	case "hardcoded-ldap-group-mapper":
		if c.Get("group") == "" {
			return "Group cant be null", false
		}
		if _, err := findGroup(ctx, st, realm.ID, splitPath(c.Get("group"))); err != nil {
			return "There is no group corresponding to configured value", false
		}
	case "group-ldap-mapper":
		if missing("groups.dn", "LDAP Groups DN") || missing("mode", "Mode") {
			return msg, false
		}
		if t := c.Get("membership.attribute.type"); t != "" && t != "DN" && t != "UID" {
			return "Invalid provider type or no such provider", true
		}
		if !filterOK("groups.ldap.filter") {
			return msg, false
		}
		if c.Get("groups.path") == "" {
			c.Set("groups.path", "/")
		}
		if names := splitPath(c.Get("groups.path")); len(names) > 0 {
			if _, err := findGroup(ctx, st, realm.ID, names); err != nil {
				return "Groups path group does not exist - please create the group on specified path first", false
			}
		}
	case "role-ldap-mapper":
		if missing("roles.dn", "LDAP Roles DN") || missing("mode", "Mode") {
			return msg, false
		}
		if t := c.Get("membership.attribute.type"); t != "" && t != "DN" && t != "UID" {
			return "Invalid provider type or no such provider", true
		}
		if !filterOK("roles.ldap.filter") {
			return msg, false
		}
		if c.Get("use.realm.roles.mapping") != "true" && c.Get("client.id") == "" {
			return "Client ID needs to be provided in config when Realm Roles Mapping is not used.", false
		}
	}
	return "", false
}
