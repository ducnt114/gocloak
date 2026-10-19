// Package policy parses and enforces Keycloak password policies, such as
// "length(8) and digits(1) and notUsername(undefined) and passwordHistory(3)".
package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Policy is a parsed password policy.
type Policy struct {
	MinLength       int
	MaxLength       int
	Digits          int
	LowerCase       int
	UpperCase       int
	SpecialChars    int
	NotUsername     bool
	NotEmail        bool
	NotContainsName bool
	Regex           []*regexp.Regexp
	History         int
	ExpireDays      int
	HashAlgorithm   string
	HashIterations  int
}

// Error is a policy violation, with Keycloak's message key and text.
type Error struct {
	Key     string
	Message string
	Args    []any // arguments of the message, for translations
}

func (e *Error) Error() string { return e.Message }

// Parse parses a policy string. Unknown policies are rejected, so that a
// policy written for Keycloak is never silently weakened.
func Parse(s string) (*Policy, error) {
	p := &Policy{}
	s = strings.TrimSpace(s)
	if s == "" {
		return p, nil
	}
	for _, part := range strings.Split(s, " and ") {
		part = strings.TrimSpace(part)
		name, arg := part, ""
		if i := strings.IndexByte(part, '('); i >= 0 && strings.HasSuffix(part, ")") {
			name, arg = part[:i], part[i+1:len(part)-1]
		}
		num := func(def int) (int, error) {
			if arg == "" || arg == "undefined" {
				return def, nil
			}
			n, err := strconv.Atoi(arg)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("Invalid config for %s: %s", name, arg)
			}
			return n, nil
		}
		var err error
		switch name {
		case "length":
			p.MinLength, err = num(8)
		case "maxLength":
			p.MaxLength, err = num(64)
		case "digits":
			p.Digits, err = num(1)
		case "lowerCase":
			p.LowerCase, err = num(1)
		case "upperCase":
			p.UpperCase, err = num(1)
		case "specialChars":
			p.SpecialChars, err = num(1)
		case "notUsername":
			p.NotUsername = true
		case "notEmail":
			p.NotEmail = true
		case "notContainsUsername":
			p.NotContainsName = true
		case "passwordHistory":
			p.History, err = num(3)
		case "forceExpiredPasswordChange":
			p.ExpireDays, err = num(365)
		case "hashAlgorithm":
			if arg == "" || arg == "undefined" {
				arg = "argon2"
			}
			switch arg {
			case "argon2", "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512":
				p.HashAlgorithm = arg
			default:
				err = fmt.Errorf("Invalid config for hashAlgorithm: %s", arg)
			}
		case "hashIterations":
			p.HashIterations, err = num(0)
		case "regexPattern":
			var re *regexp.Regexp
			if re, err = regexp.Compile(arg); err == nil {
				p.Regex = append(p.Regex, re)
			} else {
				err = fmt.Errorf("Invalid config for regexPattern: %s", arg)
			}
		default:
			return nil, fmt.Errorf("Password policy not found: %s", name)
		}
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Subject is the user a password is checked for.
type Subject struct {
	Username string
	Email    string
}

// Validate checks a new password against the policy, except history, which
// needs the stored hashes (see CheckHistory).
func (p *Policy) Validate(pw string, u Subject) *Error {
	n := utf8.RuneCountInString(pw)
	count := func(f func(rune) bool) int {
		c := 0
		for _, r := range pw {
			if f(r) {
				c++
			}
		}
		return c
	}
	switch {
	case p.MinLength > 0 && n < p.MinLength:
		return &Error{"invalidPasswordMinLengthMessage", fmt.Sprintf("Invalid password: minimum length %d.", p.MinLength), []any{p.MinLength}}
	case p.MaxLength > 0 && n > p.MaxLength:
		return &Error{"invalidPasswordMaxLengthMessage", fmt.Sprintf("Invalid password: maximum length %d.", p.MaxLength), []any{p.MaxLength}}
	case p.Digits > 0 && count(unicode.IsDigit) < p.Digits:
		return &Error{"invalidPasswordMinDigitsMessage", fmt.Sprintf("Invalid password: must contain at least %d numerical digits.", p.Digits), []any{p.Digits}}
	case p.LowerCase > 0 && count(unicode.IsLower) < p.LowerCase:
		return &Error{"invalidPasswordMinLowerCaseCharsMessage", fmt.Sprintf("Invalid password: must contain at least %d lower case characters.", p.LowerCase), []any{p.LowerCase}}
	case p.UpperCase > 0 && count(unicode.IsUpper) < p.UpperCase:
		return &Error{"invalidPasswordMinUpperCaseCharsMessage", fmt.Sprintf("Invalid password: must contain at least %d upper case characters.", p.UpperCase), []any{p.UpperCase}}
	case p.SpecialChars > 0 && count(func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) < p.SpecialChars:
		return &Error{"invalidPasswordMinSpecialCharsMessage", fmt.Sprintf("Invalid password: must contain at least %d special characters.", p.SpecialChars), []any{p.SpecialChars}}
	case p.NotUsername && u.Username != "" && strings.EqualFold(pw, u.Username):
		return &Error{"invalidPasswordNotUsernameMessage", "Invalid password: must not be equal to the username.", nil}
	case p.NotContainsName && u.Username != "" && strings.Contains(strings.ToLower(pw), strings.ToLower(u.Username)):
		return &Error{"invalidPasswordNotContainsUsernameMessage", "Invalid password: Can not contain the username.", nil}
	case p.NotEmail && u.Email != "" && strings.EqualFold(pw, u.Email):
		return &Error{"invalidPasswordNotEmailMessage", "Invalid password: must not be equal to the email.", nil}
	}
	for _, re := range p.Regex {
		if !re.MatchString(pw) {
			return &Error{"invalidPasswordRegexPatternMessage", "Invalid password: fails to match regex pattern(s).", nil}
		}
	}
	return nil
}

// HistoryError is the violation reported when a password was used recently.
func (p *Policy) HistoryError() *Error {
	return &Error{"invalidPasswordHistoryMessage", fmt.Sprintf("Invalid password: must not be equal to any of last %d passwords.", p.History), []any{p.History}}
}
