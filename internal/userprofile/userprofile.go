// Package userprofile implements Keycloak's declarative user profile: the
// attributes a realm's users have, who may view and edit them, which are
// required, and how they are validated. Error messages use Keycloak's keys
// (error-invalid-email, error-user-attribute-required, ...).
package userprofile

import (
	"encoding/json"
	"fmt"
	"math"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Contexts in which a profile is evaluated.
const (
	ContextAdmin = "admin" // the admin REST API
	ContextUser  = "user"  // the user's own forms: registration, update profile, account console
)

// Unmanaged attribute policies.
const (
	UnmanagedDisabled  = ""
	UnmanagedEnabled   = "ENABLED"
	UnmanagedAdminView = "ADMIN_VIEW"
	UnmanagedAdminEdit = "ADMIN_EDIT"
)

// Config is UPConfig, the JSON stored by Keycloak and served at
// /admin/realms/{realm}/users/profile.
type Config struct {
	Attributes               []Attribute `json:"attributes"`
	Groups                   []Group     `json:"groups,omitempty"`
	UnmanagedAttributePolicy string      `json:"unmanagedAttributePolicy,omitempty"`
}

// Attribute is a declared user attribute.
type Attribute struct {
	Name        string                    `json:"name"`
	DisplayName string                    `json:"displayName,omitempty"`
	Validations map[string]map[string]any `json:"validations,omitempty"`
	Annotations map[string]any            `json:"annotations,omitempty"`
	Required    *Required                 `json:"required,omitempty"`
	Permissions *Permissions              `json:"permissions,omitempty"`
	Selector    *Selector                 `json:"selector,omitempty"`
	Group       string                    `json:"group,omitempty"`
	Multivalued bool                      `json:"multivalued"`
}

// Required says in which contexts (roles "admin" / "user") or for which
// requested scopes an attribute is required.
type Required struct {
	Roles  []string `json:"roles,omitempty"`
	Scopes []string `json:"scopes,omitempty"`
}

// Permissions lists the contexts that may view and edit an attribute.
type Permissions struct {
	View []string `json:"view"`
	Edit []string `json:"edit"`
}

// Selector limits an attribute to requests with some scopes.
type Selector struct {
	Scopes []string `json:"scopes,omitempty"`
}

// Group groups attributes in forms.
type Group struct {
	Name               string         `json:"name"`
	DisplayHeader      string         `json:"displayHeader,omitempty"`
	DisplayDescription string         `json:"displayDescription,omitempty"`
	Annotations        map[string]any `json:"annotations,omitempty"`
}

// FieldError is a validation error, in the shape of Keycloak's admin API
// error response.
type FieldError struct {
	Field        string `json:"field"`
	ErrorMessage string `json:"errorMessage"`
	Params       []any  `json:"params"`
}

func (e FieldError) Error() string { return e.Field + ": " + e.ErrorMessage }

// Errors is a list of validation errors.
type Errors []FieldError

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, f := range e {
		parts[i] = f.Error()
	}
	return strings.Join(parts, "; ")
}

// Core attributes stored as columns rather than in user attributes.
var Core = []string{"username", "email", "firstName", "lastName"}

// IsCore reports whether name is a core attribute.
func IsCore(name string) bool { return slices.Contains(Core, name) }

func both() *Permissions {
	return &Permissions{View: []string{"admin", "user"}, Edit: []string{"admin", "user"}}
}

// Default returns Keycloak's default profile. The master realm requires
// nothing; other realms require email, first and last name from users.
func Default(master bool) *Config {
	req := &Required{Roles: []string{"user"}}
	if master {
		req = nil
	}
	return &Config{
		Attributes: []Attribute{
			{Name: "username", DisplayName: "${username}", Permissions: both(), Validations: map[string]map[string]any{
				"length": {"min": 3, "max": 255}, "username-prohibited-characters": {}, "up-username-not-idn-homograph": {}}},
			{Name: "email", DisplayName: "${email}", Permissions: both(), Required: req, Validations: map[string]map[string]any{
				"email": {}, "length": {"max": 255}}},
			{Name: "firstName", DisplayName: "${firstName}", Permissions: both(), Required: req, Validations: map[string]map[string]any{
				"length": {"max": 255}, "person-name-prohibited-characters": {}}},
			{Name: "lastName", DisplayName: "${lastName}", Permissions: both(), Required: req, Validations: map[string]map[string]any{
				"length": {"max": 255}, "person-name-prohibited-characters": {}}},
		},
		Groups: []Group{{Name: "user-metadata", DisplayHeader: "User metadata", DisplayDescription: "Attributes, which refer to user metadata"}},
	}
}

// Parse decodes and checks a profile configuration.
func Parse(b []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("invalid user profile configuration: %w", err)
	}
	return &c, c.Check()
}

// Check validates the configuration itself.
func (c *Config) Check() error {
	seen := map[string]bool{}
	for _, a := range c.Attributes {
		if a.Name == "" {
			return fmt.Errorf("attribute name is required")
		}
		if seen[a.Name] {
			return fmt.Errorf("duplicate attribute %q", a.Name)
		}
		seen[a.Name] = true
		for v := range a.Validations {
			if validators[v] == nil {
				return fmt.Errorf("unknown validator %q for attribute %q", v, a.Name)
			}
		}
		if p, ok := a.Validations["pattern"]; ok {
			if _, err := regexp.Compile(fmt.Sprint(p["pattern"])); err != nil {
				return fmt.Errorf("invalid pattern for attribute %q", a.Name)
			}
		}
	}
	for _, n := range []string{"username", "email"} {
		if !seen[n] {
			return fmt.Errorf("the %s attribute must be declared", n)
		}
	}
	switch c.UnmanagedAttributePolicy {
	case UnmanagedDisabled, UnmanagedEnabled, UnmanagedAdminView, UnmanagedAdminEdit:
	default:
		return fmt.Errorf("invalid unmanagedAttributePolicy %q", c.UnmanagedAttributePolicy)
	}
	return nil
}

// Attribute returns a declared attribute, or nil.
func (c *Config) Attribute(name string) *Attribute {
	for i := range c.Attributes {
		if c.Attributes[i].Name == name {
			return &c.Attributes[i]
		}
	}
	return nil
}

// CanView reports whether an attribute is visible in a context.
func (c *Config) CanView(name, context string) bool {
	if a := c.Attribute(name); a != nil {
		return a.Permissions == nil || slices.Contains(a.Permissions.View, context) || slices.Contains(a.Permissions.Edit, context)
	}
	switch c.UnmanagedAttributePolicy {
	case UnmanagedEnabled:
		return true
	case UnmanagedAdminView, UnmanagedAdminEdit:
		return context == ContextAdmin
	}
	return false
}

// CanEdit reports whether an attribute may be written in a context.
func (c *Config) CanEdit(name, context string) bool {
	if a := c.Attribute(name); a != nil {
		return a.Permissions == nil || slices.Contains(a.Permissions.Edit, context)
	}
	switch c.UnmanagedAttributePolicy {
	case UnmanagedEnabled:
		return true
	case UnmanagedAdminEdit:
		return context == ContextAdmin
	}
	return false
}

func (a *Attribute) required(context string, scopes []string) bool {
	if a.Required == nil {
		return false
	}
	if len(a.Required.Roles) > 0 && !slices.Contains(a.Required.Roles, context) {
		return false
	}
	if len(a.Required.Scopes) > 0 {
		for _, s := range a.Required.Scopes {
			if slices.Contains(scopes, s) {
				return true
			}
		}
		return false
	}
	return true
}

func (a *Attribute) selected(scopes []string) bool {
	if a.Selector == nil || len(a.Selector.Scopes) == 0 {
		return true
	}
	for _, s := range a.Selector.Scopes {
		if slices.Contains(scopes, s) {
			return true
		}
	}
	return false
}

// Validate checks the attribute values of a user (core attributes
// included, by name) in a context. scopes are the requested scopes, for
// scope-dependent attributes.
func (c *Config) Validate(values map[string][]string, context string, scopes []string) Errors {
	var errs Errors
	for i := range c.Attributes {
		a := &c.Attributes[i]
		if !a.selected(scopes) {
			continue
		}
		vals := nonEmpty(values[a.Name])
		if len(vals) == 0 {
			if a.required(context, scopes) {
				errs = append(errs, FieldError{a.Name, "error-user-attribute-required", []any{a.Name}})
			}
			continue
		}
		if !a.Multivalued && len(vals) > 1 {
			errs = append(errs, FieldError{a.Name, "error-invalid-multivalued-size", []any{a.Name, 0, 1}})
			continue
		}
		for _, name := range sortedKeys(a.Validations) {
			if e := validators[name](a.Name, vals, a.Validations[name]); e != nil {
				errs = append(errs, *e)
				break
			}
		}
	}
	return errs
}

func nonEmpty(v []string) []string {
	var out []string
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(m map[string]map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// Keycloak reports length errors before format errors.
	slices.SortFunc(keys, func(a, b string) int {
		if a == "length" {
			return -1
		}
		if b == "length" {
			return 1
		}
		return strings.Compare(a, b)
	})
	return keys
}

// ---------------------------------------------------------------- validators

type validator func(field string, values []string, cfg map[string]any) *FieldError

var validators = map[string]validator{
	"length":                            validateLength,
	"email":                             validateEmail,
	"pattern":                           validatePattern,
	"username-prohibited-characters":    prohibited(usernameProhibited, "error-username-invalid-character"),
	"person-name-prohibited-characters": prohibited(personNameProhibited, "error-person-name-invalid-character"),
	"up-username-not-idn-homograph":     validateNotHomograph,
	"integer":                           validateNumber(false),
	"double":                            validateNumber(true),
	"uri":                               validateURI,
	"options":                           validateOptions,
	"local-date":                        validateDate,
	"multivalued":                       validateMultivalued,
}

func num(cfg map[string]any, key string) (float64, bool) {
	switch v := cfg[key].(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case string:
		f, err := strconv.ParseFloat(v, 64)
		return f, err == nil
	}
	return 0, false
}

func intParam(f float64) any {
	if f == math.Trunc(f) {
		return int(f)
	}
	return f
}

func validateLength(field string, values []string, cfg map[string]any) *FieldError {
	min, hasMin := num(cfg, "min")
	max, hasMax := num(cfg, "max")
	for _, v := range values {
		if cfg["trim-disabled"] != true && cfg["trim-disabled"] != "true" {
			v = strings.TrimSpace(v)
		}
		n := float64(utf8.RuneCountInString(v))
		if (hasMin && n < min) || (hasMax && n > max) {
			params := []any{field}
			if hasMin {
				params = append(params, intParam(min))
			}
			if hasMax {
				params = append(params, intParam(max))
			}
			return &FieldError{field, "error-invalid-length", params}
		}
	}
	return nil
}

var emailLocal = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.-]+$`)

func validateEmail(field string, values []string, _ map[string]any) *FieldError {
	for _, v := range values {
		addr, err := mail.ParseAddress(v)
		at := strings.LastIndexByte(v, '@')
		if err != nil || addr.Address != v || at <= 0 || !emailLocal.MatchString(v[:at]) || !strings.Contains(v[at:], ".") {
			return &FieldError{field, "error-invalid-email", []any{field, v}}
		}
	}
	return nil
}

func validatePattern(field string, values []string, cfg map[string]any) *FieldError {
	pattern := fmt.Sprint(cfg["pattern"])
	re, err := regexp.Compile(pattern)
	if err != nil {
		return &FieldError{field, "error-pattern-no-match", []any{field, pattern}}
	}
	msg, _ := cfg["error-message"].(string)
	if msg == "" {
		msg = "error-pattern-no-match"
	}
	for _, v := range values {
		if !re.MatchString(v) {
			return &FieldError{field, msg, []any{field, pattern}}
		}
	}
	return nil
}

const personNameProhibited = `<>&"$%!#?§;*~/\|^=[]{}()`

// usernameProhibited mirrors Keycloak's UsernameProhibitedCharactersValidator.
const usernameProhibited = `<>&"'$%!#?§;*~/\|^=[]{}()`

func prohibited(chars, msg string) validator {
	return func(field string, values []string, _ map[string]any) *FieldError {
		for _, v := range values {
			for _, r := range v {
				if strings.ContainsRune(chars, r) || unicode.IsControl(r) || (field == "username" && unicode.IsSpace(r)) {
					return &FieldError{field, msg, []any{field}}
				}
			}
		}
		return nil
	}
}

// validateNotHomograph rejects usernames mixing scripts that could imitate
// another username (a simplified form of Keycloak's IDN homograph check).
func validateNotHomograph(field string, values []string, _ map[string]any) *FieldError {
	for _, v := range values {
		latin, other := false, false
		for _, r := range v {
			switch {
			case r < utf8.RuneSelf:
			case unicode.Is(unicode.Latin, r):
				latin = true
			case unicode.IsLetter(r):
				other = true
			}
		}
		if latin && other {
			return &FieldError{field, "error-username-invalid-character", []any{field}}
		}
	}
	return nil
}

func validateNumber(float bool) validator {
	return func(field string, values []string, cfg map[string]any) *FieldError {
		min, hasMin := num(cfg, "min")
		max, hasMax := num(cfg, "max")
		for _, v := range values {
			var n float64
			var err error
			if float {
				n, err = strconv.ParseFloat(v, 64)
			} else {
				var i int64
				i, err = strconv.ParseInt(v, 10, 64)
				n = float64(i)
			}
			if err != nil {
				return &FieldError{field, "error-invalid-number", []any{field}}
			}
			if (hasMin && n < min) || (hasMax && n > max) {
				return &FieldError{field, "error-number-out-of-range", []any{field, intParam(min), intParam(max)}}
			}
		}
		return nil
	}
}

func validateURI(field string, values []string, _ map[string]any) *FieldError {
	for _, v := range values {
		if u, err := url.Parse(v); err != nil || u.Scheme == "" {
			return &FieldError{field, "error-invalid-uri", []any{field, v}}
		}
	}
	return nil
}

func validateOptions(field string, values []string, cfg map[string]any) *FieldError {
	opts, _ := cfg["options"].([]any)
	allowed := map[string]bool{}
	for _, o := range opts {
		allowed[fmt.Sprint(o)] = true
	}
	for _, v := range values {
		if !allowed[v] {
			return &FieldError{field, "error-invalid-value", []any{field, v}}
		}
	}
	return nil
}

func validateDate(field string, values []string, _ map[string]any) *FieldError {
	for _, v := range values {
		if _, err := time.Parse("2006-01-02", v); err != nil {
			return &FieldError{field, "error-invalid-date", []any{field, v}}
		}
	}
	return nil
}

func validateMultivalued(field string, values []string, cfg map[string]any) *FieldError {
	min, hasMin := num(cfg, "min")
	max, hasMax := num(cfg, "max")
	n := float64(len(values))
	if (hasMin && n < min) || (hasMax && n > max) {
		return &FieldError{field, "error-invalid-multivalued-size", []any{field, intParam(min), intParam(max)}}
	}
	return nil
}
