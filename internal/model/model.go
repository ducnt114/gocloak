// Package model holds the core domain types of gocloak. They mirror the
// entities Keycloak keeps in its database (realms, clients, users, roles,
// groups, sessions...), trimmed down to the fields gocloak implements.
package model

import "time"

// Realm is an isolated tenant: it owns users, clients, roles and groups.
type Realm struct {
	ID                     string
	Name                   string
	DisplayName            string
	Enabled                bool
	AccessTokenLifespan    int // seconds
	AccessCodeLifespan     int // seconds
	SSOSessionIdleTimeout  int // seconds
	SSOSessionMaxLifespan  int // seconds
	LoginWithEmailAllowed  bool
	DuplicateEmailsAllowed bool
	RegistrationAllowed    bool
	DefaultRoleID          string
	Attributes             map[string]string
	Settings               RealmSettings
	CreatedAt              time.Time
}

// RealmSettings holds realm configuration that does not need a column of
// its own. It is stored as one JSON document; JSON names follow Keycloak's
// RealmRepresentation so the import/export code can map them one to one.
type RealmSettings struct {
	SSLRequired                 string   `json:"sslRequired,omitempty"`
	RegistrationEmailAsUsername bool     `json:"registrationEmailAsUsername,omitempty"`
	RememberMe                  bool     `json:"rememberMe,omitempty"`
	VerifyEmail                 bool     `json:"verifyEmail,omitempty"`
	ResetPasswordAllowed        bool     `json:"resetPasswordAllowed,omitempty"`
	EditUsernameAllowed         bool     `json:"editUsernameAllowed,omitempty"`
	RevokeRefreshToken          bool     `json:"revokeRefreshToken,omitempty"`
	RefreshTokenMaxReuse        int      `json:"refreshTokenMaxReuse,omitempty"`
	OfflineSessionIdleTimeout   int      `json:"offlineSessionIdleTimeout,omitempty"`
	NotBefore                   int64    `json:"notBefore,omitempty"`
	LoginTheme                  string   `json:"loginTheme,omitempty"`
	AccountTheme                string   `json:"accountTheme,omitempty"`
	EmailTheme                  string   `json:"emailTheme,omitempty"`
	InternationalizationEnabled bool     `json:"internationalizationEnabled,omitempty"`
	SupportedLocales            []string `json:"supportedLocales,omitempty"`
	DefaultLocale               string   `json:"defaultLocale,omitempty"`
}

// Client is an application that can request authentication.
type Client struct {
	ID                        string
	RealmID                   string
	ClientID                  string
	Name                      string
	Description               string
	Enabled                   bool
	PublicClient              bool
	BearerOnly                bool
	Secret                    string
	RootURL                   string
	BaseURL                   string
	RedirectURIs              []string
	WebOrigins                []string
	StandardFlowEnabled       bool
	DirectAccessGrantsEnabled bool
	ServiceAccountsEnabled    bool
	FullScopeAllowed          bool
	Protocol                  string
	Attributes                map[string]string
}

// User is a realm user. Service account users are linked to a client.
type User struct {
	ID                     string
	RealmID                string
	Username               string
	Email                  string
	EmailVerified          bool
	FirstName              string
	LastName               string
	Enabled                bool
	CreatedTimestamp       int64 // millis, like Keycloak
	Attributes             map[string][]string
	RequiredActions        []string
	ServiceAccountClientID string // client UUID
	NotBefore              int64
}

// Credential types.
const (
	CredentialPassword = "password"
)

// Credential is a stored secret for a user (currently only passwords).
// SecretData and CredentialData use the same JSON layout as Keycloak so that
// realm exports can be imported without re-hashing.
type Credential struct {
	ID             string
	UserID         string
	Type           string
	UserLabel      string
	SecretData     string
	CredentialData string
	CreatedDate    int64 // millis
	Priority       int
}

// Role is either a realm role (ClientID == "") or a client role.
type Role struct {
	ID          string
	RealmID     string
	ClientID    string // client UUID, empty for realm roles
	Name        string
	Description string
	Composite   bool
	Attributes  map[string][]string
}

// Group is a (possibly nested) collection of users sharing role mappings.
type Group struct {
	ID         string
	RealmID    string
	ParentID   string
	Name       string
	Attributes map[string][]string
}

// UserSession is an SSO session created on successful login.
type UserSession struct {
	ID          string
	RealmID     string
	UserID      string
	IPAddress   string
	Started     time.Time
	LastRefresh time.Time
	RememberMe  bool
	// Clients maps client UUIDs that participated in this session.
	Clients map[string]bool
}

// AuthSession tracks an in-flight browser login (between /auth and the
// final redirect back to the client).
type AuthSession struct {
	ID        string
	RealmID   string
	ClientID  string // client UUID
	Params    map[string]string
	UserID    string // set once the user has authenticated
	ExpiresAt time.Time
}

// AuthCode is a one-time authorization code.
type AuthCode struct {
	Code                string
	RealmID             string
	ClientID            string // client UUID
	UserID              string
	SessionID           string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

// RealmKey is an RSA signing key of a realm.
type RealmKey struct {
	ID         string // kid
	RealmID    string
	Algorithm  string
	PrivatePEM string
	Active     bool
	Priority   int
	CreatedAt  time.Time
}
