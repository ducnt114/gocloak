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

	// Authentication.
	BrowserFlow                     string `json:"browserFlow,omitempty"`
	RegistrationFlow                string `json:"registrationFlow,omitempty"`
	DirectGrantFlow                 string `json:"directGrantFlow,omitempty"`
	ResetCredentialsFlow            string `json:"resetCredentialsFlow,omitempty"`
	ClientAuthenticationFlow        string `json:"clientAuthenticationFlow,omitempty"`
	FirstBrokerLoginFlow            string `json:"firstBrokerLoginFlow,omitempty"`
	DockerAuthenticationFlow        string `json:"dockerAuthenticationFlow,omitempty"`
	SSOSessionIdleTimeoutRememberMe int    `json:"ssoSessionIdleTimeoutRememberMe"`
	SSOSessionMaxLifespanRememberMe int    `json:"ssoSessionMaxLifespanRememberMe"`
	ActionTokenGeneratedByAdmin     int    `json:"actionTokenGeneratedByAdminLifespan"`
	ActionTokenGeneratedByUser      int    `json:"actionTokenGeneratedByUserLifespan"`
	// SMTPServer holds Keycloak's smtpServer settings (host, port, from, auth, user, password, ssl, starttls...).
	SMTPServer map[string]string `json:"smtpServer,omitempty"`

	// OTP policy.
	OTPPolicyType            string   `json:"otpPolicyType,omitempty"`
	OTPPolicyAlgorithm       string   `json:"otpPolicyAlgorithm,omitempty"`
	OTPPolicyInitialCounter  int      `json:"otpPolicyInitialCounter"`
	OTPPolicyDigits          int      `json:"otpPolicyDigits"`
	OTPPolicyLookAheadWindow int      `json:"otpPolicyLookAheadWindow"`
	OTPPolicyPeriod          int      `json:"otpPolicyPeriod"`
	OTPPolicyCodeReusable    bool     `json:"otpPolicyCodeReusable"`
	OTPSupportedApplications []string `json:"otpSupportedApplications,omitempty"`

	// WebAuthn policies (two-factor and passwordless), flat as in Keycloak.
	WebAuthnPolicyRpEntityName                                string   `json:"webAuthnPolicyRpEntityName"`
	WebAuthnPolicySignatureAlgorithms                         []string `json:"webAuthnPolicySignatureAlgorithms"`
	WebAuthnPolicyRpId                                        string   `json:"webAuthnPolicyRpId"`
	WebAuthnPolicyAttestationConveyancePreference             string   `json:"webAuthnPolicyAttestationConveyancePreference"`
	WebAuthnPolicyAuthenticatorAttachment                     string   `json:"webAuthnPolicyAuthenticatorAttachment"`
	WebAuthnPolicyRequireResidentKey                          string   `json:"webAuthnPolicyRequireResidentKey"`
	WebAuthnPolicyUserVerificationRequirement                 string   `json:"webAuthnPolicyUserVerificationRequirement"`
	WebAuthnPolicyCreateTimeout                               int      `json:"webAuthnPolicyCreateTimeout"`
	WebAuthnPolicyAvoidSameAuthenticatorRegister              bool     `json:"webAuthnPolicyAvoidSameAuthenticatorRegister"`
	WebAuthnPolicyAcceptableAaguids                           []string `json:"webAuthnPolicyAcceptableAaguids"`
	WebAuthnPolicyExtraOrigins                                []string `json:"webAuthnPolicyExtraOrigins"`
	WebAuthnPolicyPasswordlessRpEntityName                    string   `json:"webAuthnPolicyPasswordlessRpEntityName"`
	WebAuthnPolicyPasswordlessSignatureAlgorithms             []string `json:"webAuthnPolicyPasswordlessSignatureAlgorithms"`
	WebAuthnPolicyPasswordlessRpId                            string   `json:"webAuthnPolicyPasswordlessRpId"`
	WebAuthnPolicyPasswordlessAttestationConveyancePreference string   `json:"webAuthnPolicyPasswordlessAttestationConveyancePreference"`
	WebAuthnPolicyPasswordlessAuthenticatorAttachment         string   `json:"webAuthnPolicyPasswordlessAuthenticatorAttachment"`
	WebAuthnPolicyPasswordlessRequireResidentKey              string   `json:"webAuthnPolicyPasswordlessRequireResidentKey"`
	WebAuthnPolicyPasswordlessUserVerificationRequirement     string   `json:"webAuthnPolicyPasswordlessUserVerificationRequirement"`
	WebAuthnPolicyPasswordlessCreateTimeout                   int      `json:"webAuthnPolicyPasswordlessCreateTimeout"`
	WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister  bool     `json:"webAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister"`
	WebAuthnPolicyPasswordlessAcceptableAaguids               []string `json:"webAuthnPolicyPasswordlessAcceptableAaguids"`
	WebAuthnPolicyPasswordlessExtraOrigins                    []string `json:"webAuthnPolicyPasswordlessExtraOrigins"`

	// Events.
	EventsEnabled             bool     `json:"eventsEnabled"`
	EventsExpiration          int64    `json:"eventsExpiration,omitempty"`
	EventsListeners           []string `json:"eventsListeners,omitempty"`
	EnabledEventTypes         []string `json:"enabledEventTypes,omitempty"`
	AdminEventsEnabled        bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`
}

// WebAuthnPolicy is one of the two WebAuthn policies of a realm.
type WebAuthnPolicy struct {
	RpEntityName                    string
	SignatureAlgorithms             []string
	RpID                            string
	AttestationConveyancePreference string
	AuthenticatorAttachment         string
	RequireResidentKey              string
	UserVerificationRequirement     string
	CreateTimeout                   int
	AvoidSameAuthenticatorRegister  bool
	AcceptableAaguids               []string
	ExtraOrigins                    []string
}

// WebAuthn returns the two-factor or the passwordless WebAuthn policy.
func (s *RealmSettings) WebAuthn(passwordless bool) WebAuthnPolicy {
	if passwordless {
		return WebAuthnPolicy{s.WebAuthnPolicyPasswordlessRpEntityName, s.WebAuthnPolicyPasswordlessSignatureAlgorithms,
			s.WebAuthnPolicyPasswordlessRpId, s.WebAuthnPolicyPasswordlessAttestationConveyancePreference,
			s.WebAuthnPolicyPasswordlessAuthenticatorAttachment, s.WebAuthnPolicyPasswordlessRequireResidentKey,
			s.WebAuthnPolicyPasswordlessUserVerificationRequirement, s.WebAuthnPolicyPasswordlessCreateTimeout,
			s.WebAuthnPolicyPasswordlessAvoidSameAuthenticatorRegister, s.WebAuthnPolicyPasswordlessAcceptableAaguids,
			s.WebAuthnPolicyPasswordlessExtraOrigins}
	}
	return WebAuthnPolicy{s.WebAuthnPolicyRpEntityName, s.WebAuthnPolicySignatureAlgorithms, s.WebAuthnPolicyRpId,
		s.WebAuthnPolicyAttestationConveyancePreference, s.WebAuthnPolicyAuthenticatorAttachment,
		s.WebAuthnPolicyRequireResidentKey, s.WebAuthnPolicyUserVerificationRequirement, s.WebAuthnPolicyCreateTimeout,
		s.WebAuthnPolicyAvoidSameAuthenticatorRegister, s.WebAuthnPolicyAcceptableAaguids, s.WebAuthnPolicyExtraOrigins}
}

// DefaultRealmSettings returns Keycloak's defaults for a new realm.
func DefaultRealmSettings() RealmSettings {
	d := RealmSettings{
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
		BrowserFlow:                  "browser",
		RegistrationFlow:             "registration",
		DirectGrantFlow:              "direct grant",
		ResetCredentialsFlow:         "reset credentials",
		ClientAuthenticationFlow:     "clients",
		FirstBrokerLoginFlow:         "first broker login",
		DockerAuthenticationFlow:     "docker auth",
		ActionTokenGeneratedByAdmin:  43200,
		ActionTokenGeneratedByUser:   300,
		OTPPolicyType:                "totp",
		OTPPolicyAlgorithm:           "HmacSHA1",
		OTPPolicyDigits:              6,
		OTPPolicyLookAheadWindow:     1,
		OTPPolicyPeriod:              30,
		OTPSupportedApplications:     []string{"totpAppFreeOTPName", "totpAppGoogleName", "totpAppMicrosoftAuthenticatorName"},
	}
	for _, p := range []struct {
		name                                            *string
		algs, aaguids, origins                          *[]string
		attestation, attachment, resident, verification *string
	}{
		{&d.WebAuthnPolicyRpEntityName, &d.WebAuthnPolicySignatureAlgorithms, &d.WebAuthnPolicyAcceptableAaguids, &d.WebAuthnPolicyExtraOrigins,
			&d.WebAuthnPolicyAttestationConveyancePreference, &d.WebAuthnPolicyAuthenticatorAttachment, &d.WebAuthnPolicyRequireResidentKey, &d.WebAuthnPolicyUserVerificationRequirement},
		{&d.WebAuthnPolicyPasswordlessRpEntityName, &d.WebAuthnPolicyPasswordlessSignatureAlgorithms, &d.WebAuthnPolicyPasswordlessAcceptableAaguids, &d.WebAuthnPolicyPasswordlessExtraOrigins,
			&d.WebAuthnPolicyPasswordlessAttestationConveyancePreference, &d.WebAuthnPolicyPasswordlessAuthenticatorAttachment, &d.WebAuthnPolicyPasswordlessRequireResidentKey, &d.WebAuthnPolicyPasswordlessUserVerificationRequirement},
	} {
		*p.name = "keycloak"
		*p.algs = []string{"ES256", "RS256"}
		*p.aaguids, *p.origins = []string{}, []string{}
		*p.attestation, *p.attachment, *p.resident, *p.verification = "not specified", "not specified", "not specified", "not specified"
	}
	return d
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
	// FlowOverrides binds flows by id for this client ("browser", "direct_grant").
	FlowOverrides map[string]string
	// FrontchannelLogout makes logout notify the client through the browser
	// (SAML clients default to it).
	FrontchannelLogout bool
	// AdminURL is the client's management endpoint; SAML clients use it as
	// the default assertion consumer and logout URL.
	AdminURL string
	// ConsentRequired makes users grant the client's scopes on a consent page.
	ConsentRequired bool
}

// UserConsent is what a user granted a client: client scope ids, and the
// client's own id when it has a consent text of its own.
type UserConsent struct {
	UserID   string
	ClientID string // client UUID
	Scopes   []string
	Created  int64 // millis
	Updated  int64
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
	// FederationLink is the id of the user storage component (LDAP) the
	// user was imported from.
	FederationLink string
	NotBefore      int64
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

// Required action providers, authentication flows and their executions.

// RequiredActionProvider configures a required action in a realm.
type RequiredActionProvider struct {
	RealmID       string
	Alias         string
	Name          string
	ProviderID    string
	Enabled       bool
	DefaultAction bool
	Priority      int
	Config        map[string]string
}

// AuthFlow is an authentication flow (top level or sub flow).
type AuthFlow struct {
	ID          string
	RealmID     string
	Alias       string
	Description string
	ProviderID  string // basic-flow, form-flow or client-flow
	TopLevel    bool
	BuiltIn     bool
}

// Execution requirements.
const (
	Required    = "REQUIRED"
	Alternative = "ALTERNATIVE"
	Conditional = "CONDITIONAL"
	Disabled    = "DISABLED"
)

// AuthExecution is a step of a flow: an authenticator, or a sub flow.
type AuthExecution struct {
	ID            string
	RealmID       string
	FlowID        string
	Authenticator string
	SubFlowID     string
	Requirement   string
	Priority      int
	ConfigID      string
}

// AuthenticatorConfig holds the settings of an execution.
type AuthenticatorConfig struct {
	ID      string
	RealmID string
	Alias   string
	Config  map[string]string
}

// IdentityProvider is an external identity provider users can log in with.
type IdentityProvider struct {
	InternalID                string
	RealmID                   string
	Alias                     string
	DisplayName               string
	ProviderID                string // oidc, keycloak-oidc, oauth2, google, github, microsoft, gitlab, facebook
	Enabled                   bool
	TrustEmail                bool
	StoreToken                bool
	AddReadTokenRoleOnCreate  bool
	LinkOnly                  bool
	HideOnLogin               bool
	AuthenticateByDefault     bool
	FirstBrokerLoginFlowAlias string
	PostBrokerLoginFlowAlias  string
	GUIOrder                  string
	Config                    map[string]string
}

// IdentityProviderMapper imports data from an identity provider.
type IdentityProviderMapper struct {
	ID       string
	RealmID  string
	IdPAlias string
	Name     string
	Type     string
	Config   map[string]string
}

// FederatedIdentity links a user to an account at an identity provider.
type FederatedIdentity struct {
	UserID            string
	RealmID           string
	IdentityProvider  string // alias
	FederatedUserID   string
	FederatedUsername string
	Token             string // stored token response, when the provider stores tokens
}

// ResourceServer is a client with authorization services enabled.
type ResourceServer struct {
	ClientID                      string // client UUID
	RealmID                       string
	PolicyEnforcementMode         string // ENFORCING, PERMISSIVE, DISABLED
	DecisionStrategy              string // UNANIMOUS, AFFIRMATIVE, CONSENSUS
	AllowRemoteResourceManagement bool
}

// AuthzScope is a scope of a resource server.
type AuthzScope struct {
	ID, ResourceServerID, Name, DisplayName, IconURI string
}

// AuthzResource is a protected resource.
type AuthzResource struct {
	ID, ResourceServerID, Name, DisplayName, Type string
	Owner                                         string // client UUID (the resource server) or user id
	OwnerManagedAccess                            bool
	IconURI                                       string
	URIs                                          []string
	Attributes                                    map[string][]string
	ScopeIDs                                      []string
}

// AuthzPolicy is a policy or a permission (types resource and scope).
type AuthzPolicy struct {
	ID, ResourceServerID, Name, Description string
	Type                                    string
	Logic                                   string // POSITIVE, NEGATIVE
	DecisionStrategy                        string
	Owner                                   string
	Config                                  map[string]string
	ResourceIDs, ScopeIDs, AssociatedIDs    []string
}

// PermissionTicket is a UMA permission request on a user's resource.
type PermissionTicket struct {
	ID, ResourceServerID, ResourceID, ScopeID string
	Owner, Requester                          string
	CreatedTimestamp, GrantedTimestamp        int64 // millis; granted when > 0
}
