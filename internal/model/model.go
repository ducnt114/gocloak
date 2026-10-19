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
// Use DefaultRealmSettings for new realms: zero is a meaningful value for
// several fields.
type RealmSettings struct {
	SSLRequired                 string   `json:"sslRequired,omitempty"`
	RegistrationEmailAsUsername bool     `json:"registrationEmailAsUsername"`
	RememberMe                  bool     `json:"rememberMe"`
	VerifyEmail                 bool     `json:"verifyEmail"`
	ResetPasswordAllowed        bool     `json:"resetPasswordAllowed"`
	EditUsernameAllowed         bool     `json:"editUsernameAllowed"`
	LoginTheme                  string   `json:"loginTheme,omitempty"`
	AccountTheme                string   `json:"accountTheme,omitempty"`
	EmailTheme                  string   `json:"emailTheme,omitempty"`
	InternationalizationEnabled bool     `json:"internationalizationEnabled"`
	SupportedLocales            []string `json:"supportedLocales,omitempty"`
	DefaultLocale               string   `json:"defaultLocale,omitempty"`

	// Tokens and sessions.
	RevokeRefreshToken               bool   `json:"revokeRefreshToken"`
	RefreshTokenMaxReuse             int    `json:"refreshTokenMaxReuse"`
	OfflineSessionIdleTimeout        int    `json:"offlineSessionIdleTimeout"`
	OfflineSessionMaxLifespanEnabled bool   `json:"offlineSessionMaxLifespanEnabled"`
	OfflineSessionMaxLifespan        int    `json:"offlineSessionMaxLifespan"`
	NotBefore                        int64  `json:"notBefore"`
	DefaultSignatureAlgorithm        string `json:"defaultSignatureAlgorithm,omitempty"`

	// Brute force detection.
	BruteForceProtected          bool   `json:"bruteForceProtected"`
	PermanentLockout             bool   `json:"permanentLockout"`
	MaxTemporaryLockouts         int    `json:"maxTemporaryLockouts"`
	BruteForceStrategy           string `json:"bruteForceStrategy,omitempty"`
	FailureFactor                int    `json:"failureFactor"`
	WaitIncrementSeconds         int    `json:"waitIncrementSeconds"`
	QuickLoginCheckMilliSeconds  int64  `json:"quickLoginCheckMilliSeconds"`
	MinimumQuickLoginWaitSeconds int    `json:"minimumQuickLoginWaitSeconds"`
	MaxFailureWaitSeconds        int    `json:"maxFailureWaitSeconds"`
	MaxDeltaTimeSeconds          int    `json:"maxDeltaTimeSeconds"`

	// Credentials.
	PasswordPolicy string `json:"passwordPolicy,omitempty"`

	// Events.
	EventsEnabled             bool     `json:"eventsEnabled"`
	EventsExpiration          int64    `json:"eventsExpiration,omitempty"`
	EventsListeners           []string `json:"eventsListeners,omitempty"`
	EnabledEventTypes         []string `json:"enabledEventTypes,omitempty"`
	AdminEventsEnabled        bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`
}

// DefaultRealmSettings returns Keycloak's defaults for a new realm.
func DefaultRealmSettings() RealmSettings {
	return RealmSettings{
		SSLRequired:                  "external",
		OfflineSessionIdleTimeout:    2592000,
		OfflineSessionMaxLifespan:    5184000,
		DefaultSignatureAlgorithm:    "RS256",
		BruteForceStrategy:           "MULTIPLE",
		FailureFactor:                30,
		WaitIncrementSeconds:         60,
		QuickLoginCheckMilliSeconds:  1000,
		MinimumQuickLoginWaitSeconds: 60,
		MaxFailureWaitSeconds:        900,
		MaxDeltaTimeSeconds:          43200,
		EventsListeners:              []string{"jboss-logging"},
	}
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
	// ClientAuthenticatorType is client-secret, client-secret-jwt or client-jwt.
	ClientAuthenticatorType string
	NotBefore               int64
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
	// Notes are read by session note protocol mappers (e.g. AUTH_TIME) and
	// hold refresh token reuse counters.
	Notes map[string]string
	// Offline sessions back offline tokens and survive SSO logout.
	Offline bool
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

// ClientScope is a reusable set of protocol mappers and role scope mappings
// that clients include by default or on request (the "scope" parameter).
type ClientScope struct {
	ID          string
	RealmID     string
	Name        string
	Description string
	Protocol    string
	Attributes  map[string]string
}

// IncludeInTokenScope reports whether the scope name is listed in the
// "scope" claim of issued tokens.
func (s *ClientScope) IncludeInTokenScope() bool {
	return s.Attributes["include.in.token.scope"] != "false"
}

// ProtocolMapper adds or changes claims of issued tokens. It belongs to a
// client or a client scope (OwnerID).
type ProtocolMapper struct {
	ID       string
	RealmID  string
	OwnerID  string
	Name     string
	Protocol string
	Type     string // Keycloak provider id, e.g. oidc-usermodel-attribute-mapper
	Config   map[string]string
}

// ClientScopeLink attaches a client scope to a client or realm.
type ClientScopeLink struct {
	ScopeID string
	Default bool // default scope (always applied) vs optional (on request)
}

// Event is a login/user event (Keycloak's EventRepresentation).
type Event struct {
	ID        string
	RealmID   string
	Type      string
	Time      int64 // millis
	ClientID  string
	UserID    string
	SessionID string
	IPAddress string
	Error     string
	Details   map[string]string
}

// AdminEvent records a change made through the admin API.
type AdminEvent struct {
	ID             string
	RealmID        string
	Time           int64 // millis
	OperationType  string
	ResourceType   string
	ResourcePath   string
	Representation string
	AuthRealmID    string
	AuthClientID   string
	AuthUserID     string
	AuthIP         string
	Error          string
}

// LoginFailure is the brute force detection state of a user.
type LoginFailure struct {
	RealmID              string
	UserID               string
	NumFailures          int
	NumTemporaryLockouts int
	LastFailure          int64 // millis
	LastIP               string
	FailedLoginNotBefore int64 // unix seconds
}

// Component is a configurable provider instance, such as a key provider.
// Config is multivalued, as in Keycloak.
type Component struct {
	ID           string
	RealmID      string
	Name         string
	ProviderID   string
	ProviderType string
	ParentID     string
	SubType      string
	Config       map[string][]string
}

// Get returns the first value of a config key.
func (c *Component) Get(key string) string {
	if v := c.Config[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Set replaces a config key.
func (c *Component) Set(key, value string) {
	if c.Config == nil {
		c.Config = map[string][]string{}
	}
	c.Config[key] = []string{value}
}
