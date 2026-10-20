package service

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

// Required action aliases.
const (
	ActionConfigureTOTP       = "CONFIGURE_TOTP"
	ActionTermsAndConditions  = "TERMS_AND_CONDITIONS"
	ActionUpdateProfile       = "UPDATE_PROFILE"
	ActionVerifyEmail         = "VERIFY_EMAIL"
	ActionVerifyProfile       = "VERIFY_PROFILE"
	ActionUpdateEmail         = "UPDATE_EMAIL"
	ActionWebAuthnRegister    = "webauthn-register"
	ActionWebAuthnPasswordles = "webauthn-register-passwordless"
)

// DefaultRequiredActions are Keycloak 26's required action providers.
var DefaultRequiredActions = []model.RequiredActionProvider{
	{Alias: ActionConfigureTOTP, Name: "Configure OTP", Enabled: true, Priority: 10},
	{Alias: ActionTermsAndConditions, Name: "Terms and Conditions", Enabled: false, Priority: 20},
	{Alias: ActionUpdatePassword, Name: "Update Password", Enabled: true, Priority: 30},
	{Alias: ActionUpdateProfile, Name: "Update Profile", Enabled: true, Priority: 40},
	{Alias: ActionVerifyEmail, Name: "Verify Email", Enabled: true, Priority: 50},
	{Alias: "delete_account", Name: "Delete Account", Enabled: false, Priority: 60},
	{Alias: ActionWebAuthnRegister, Name: "Webauthn Register", Enabled: true, Priority: 70},
	{Alias: ActionWebAuthnPasswordles, Name: "Webauthn Register Passwordless", Enabled: true, Priority: 80},
	{Alias: ActionVerifyProfile, Name: "Verify Profile", Enabled: true, Priority: 90},
	{Alias: "delete_credential", Name: "Delete Credential", Enabled: true, Priority: 100},
	{Alias: "update_user_locale", Name: "Update User Locale", Enabled: true, Priority: 1000},
}

// UnregisteredRequiredActions can be registered by admins.
var UnregisteredRequiredActions = []model.RequiredActionProvider{
	{Alias: ActionUpdateEmail, Name: "Update Email"},
}

// flowDef describes a built-in flow; an execution has either an
// authenticator or a sub flow (or both, for form flows).
type flowDef struct {
	alias, description, provider string
	executions                   []execDef
}

type execDef struct {
	authenticator, requirement string
	sub                        *flowDef
	config                     *model.AuthenticatorConfig
}

func otpSubflow(alias, otpAuthenticator string) *flowDef {
	return &flowDef{alias, "Flow to determine if the OTP is required for the authentication", "basic-flow", []execDef{
		{authenticator: "conditional-user-configured", requirement: model.Required},
		{authenticator: otpAuthenticator, requirement: model.Required},
	}}
}

// builtinFlows mirrors the flows Keycloak 26 creates in every realm.
var builtinFlows = []flowDef{
	{"browser", "Browser based authentication", "basic-flow", []execDef{
		{authenticator: "auth-cookie", requirement: model.Alternative},
		{authenticator: "auth-spnego", requirement: model.Disabled},
		{authenticator: "identity-provider-redirector", requirement: model.Alternative},
		{requirement: model.Alternative, sub: &flowDef{"Organization", "", "basic-flow", []execDef{
			{requirement: model.Conditional, sub: &flowDef{"Browser - Conditional Organization", "Flow to determine if the organization identity-first login is to be used", "basic-flow", []execDef{
				{authenticator: "conditional-user-configured", requirement: model.Required},
				{authenticator: "organization", requirement: model.Alternative},
			}}},
		}}},
		{requirement: model.Alternative, sub: &flowDef{"forms", "Username, password, otp and other auth forms.", "basic-flow", []execDef{
			{authenticator: "auth-username-password-form", requirement: model.Required},
			{requirement: model.Conditional, sub: otpSubflow("Browser - Conditional OTP", "auth-otp-form")},
		}}},
	}},
	{"direct grant", "OpenID Connect Resource Owner Grant", "basic-flow", []execDef{
		{authenticator: "direct-grant-validate-username", requirement: model.Required},
		{authenticator: "direct-grant-validate-password", requirement: model.Required},
		{requirement: model.Conditional, sub: otpSubflow("Direct Grant - Conditional OTP", "direct-grant-validate-otp")},
	}},
	{"registration", "Registration flow", "basic-flow", []execDef{
		{authenticator: "registration-page-form", requirement: model.Required, sub: &flowDef{"registration form", "Registration form", "form-flow", []execDef{
			{authenticator: "registration-user-creation", requirement: model.Required},
			{authenticator: "registration-password-action", requirement: model.Required},
			{authenticator: "registration-recaptcha-action", requirement: model.Disabled},
			{authenticator: "registration-terms-and-conditions", requirement: model.Disabled},
		}}},
	}},
	{"reset credentials", "Reset credentials for a user if they forgot their password or something", "basic-flow", []execDef{
		{authenticator: "reset-credentials-choose-user", requirement: model.Required},
		{authenticator: "reset-credential-email", requirement: model.Required},
		{authenticator: "reset-password", requirement: model.Required},
		{requirement: model.Conditional, sub: otpSubflow("Reset - Conditional OTP", "reset-otp")},
	}},
	{"clients", "Base authentication for clients", "client-flow", []execDef{
		{authenticator: "client-secret", requirement: model.Alternative},
		{authenticator: "client-jwt", requirement: model.Alternative},
		{authenticator: "client-secret-jwt", requirement: model.Alternative},
		{authenticator: "client-x509", requirement: model.Alternative},
	}},
	{"first broker login", "Actions taken after first broker login with identity provider account, which is not yet linked to any gocloak account", "basic-flow", []execDef{
		{authenticator: "idp-review-profile", requirement: model.Required,
			config: &model.AuthenticatorConfig{Alias: "review profile config", Config: map[string]string{"update.profile.on.first.login": "missing"}}},
		{requirement: model.Required, sub: &flowDef{"User creation or linking", "Flow for the existing/non-existing user alternatives", "basic-flow", []execDef{
			{authenticator: "idp-create-user-if-unique", requirement: model.Alternative,
				config: &model.AuthenticatorConfig{Alias: "create unique user config", Config: map[string]string{"require.password.update.after.registration": "false"}}},
			{requirement: model.Alternative, sub: &flowDef{"Handle Existing Account", "Handle what to do if there is existing account with same email/username like authenticated identity provider", "basic-flow", []execDef{
				{authenticator: "idp-confirm-link", requirement: model.Required},
				{requirement: model.Required, sub: &flowDef{"Account verification options", "Method with which to verity the existing account", "basic-flow", []execDef{
					{authenticator: "idp-email-verification", requirement: model.Alternative},
					{requirement: model.Alternative, sub: &flowDef{"Verify Existing Account by Re-authentication", "Reauthentication of existing account", "basic-flow", []execDef{
						{authenticator: "idp-username-password-form", requirement: model.Required},
						{requirement: model.Conditional, sub: otpSubflow("First broker login - Conditional OTP", "auth-otp-form")},
					}}},
				}}},
			}}},
		}}},
		{requirement: model.Conditional, sub: &flowDef{"First Broker Login - Conditional Organization", "Flow to determine if the authenticator that adds organization members is to be used", "basic-flow", []execDef{
			{authenticator: "conditional-user-configured", requirement: model.Required},
			{authenticator: "idp-add-organization-member", requirement: model.Required},
		}}},
	}},
	{"docker auth", "Used by Docker clients to authenticate against the IDP", "basic-flow", []execDef{
		{authenticator: "docker-http-basic-authenticator", requirement: model.Required},
	}},
}

func (s *Service) createFlow(ctx context.Context, st *store.Store, realmID string, def *flowDef, topLevel bool) (*model.AuthFlow, error) {
	f := &model.AuthFlow{ID: NewID(), RealmID: realmID, Alias: def.alias, Description: def.description,
		ProviderID: def.provider, TopLevel: topLevel, BuiltIn: true}
	if err := st.CreateFlow(ctx, f); err != nil {
		return nil, err
	}
	for i, e := range def.executions {
		ex := &model.AuthExecution{ID: NewID(), RealmID: realmID, FlowID: f.ID, Authenticator: e.authenticator,
			Requirement: e.requirement, Priority: (i + 1) * 10}
		if e.sub != nil {
			sub, err := s.createFlow(ctx, st, realmID, e.sub, false)
			if err != nil {
				return nil, err
			}
			ex.SubFlowID = sub.ID
		}
		if e.config != nil {
			cfg := &model.AuthenticatorConfig{ID: NewID(), RealmID: realmID, Alias: e.config.Alias, Config: e.config.Config}
			if err := st.CreateAuthConfig(ctx, cfg); err != nil {
				return nil, err
			}
			ex.ConfigID = cfg.ID
		}
		if err := st.CreateExecution(ctx, ex); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// ProvisionAuthentication creates the built-in flows and required actions.
func (s *Service) ProvisionAuthentication(ctx context.Context, st *store.Store, realm *model.Realm) error {
	for i := range builtinFlows {
		if _, err := s.createFlow(ctx, st, realm.ID, &builtinFlows[i], true); err != nil {
			return err
		}
	}
	for _, a := range DefaultRequiredActions {
		a.RealmID, a.ProviderID = realm.ID, a.Alias
		if err := st.CreateRequiredAction(ctx, &a); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------- user profile

// User profile component, as stored by Keycloak.
const (
	UserProfileProviderType = "org.gocloak.userprofile.UserProfileProvider"
	UserProfileProviderID   = "declarative-user-profile"
	UserProfileConfigKey    = "kc.user.profile.config"
)

// UserProfile returns the realm's user profile configuration.
func (s *Service) UserProfile(ctx context.Context, st *store.Store, realm *model.Realm) (*userprofile.Config, error) {
	comps, err := st.ListComponents(ctx, realm.ID, UserProfileProviderType)
	if err != nil {
		return nil, err
	}
	for _, c := range comps {
		if raw := c.Get(UserProfileConfigKey); raw != "" {
			return userprofile.Parse([]byte(raw))
		}
	}
	return userprofile.Default(realm.Name == MasterRealm), nil
}

// SetUserProfile stores the realm's user profile configuration.
func (s *Service) SetUserProfile(ctx context.Context, st *store.Store, realm *model.Realm, cfg *userprofile.Config) error {
	if err := cfg.Check(); err != nil {
		return validationf("%s", err.Error())
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	comps, err := st.ListComponents(ctx, realm.ID, UserProfileProviderType)
	if err != nil {
		return err
	}
	if len(comps) > 0 {
		comps[0].Set(UserProfileConfigKey, string(b))
		return st.UpdateComponent(ctx, comps[0])
	}
	return st.CreateComponent(ctx, &model.Component{ID: NewID(), RealmID: realm.ID, Name: UserProfileProviderID,
		ProviderID: UserProfileProviderID, ProviderType: UserProfileProviderType, ParentID: realm.ID,
		Config: map[string][]string{UserProfileConfigKey: {string(b)}}})
}

// ProfileValues returns a user's attributes with the core attributes, as
// the user profile sees them.
func ProfileValues(u *model.User) map[string][]string {
	v := map[string][]string{}
	for k, vals := range u.Attributes {
		v[k] = vals
	}
	set := func(k, val string) {
		if val != "" {
			v[k] = []string{val}
		} else {
			delete(v, k)
		}
	}
	set("username", u.Username)
	set("email", u.Email)
	set("firstName", u.FirstName)
	set("lastName", u.LastName)
	return v
}

// ProfileIncomplete reports whether the user misses attributes the profile
// requires from users, which triggers VERIFY_PROFILE at login.
func (s *Service) ProfileIncomplete(ctx context.Context, realm *model.Realm, u *model.User) (bool, error) {
	if u.ServiceAccountClientID != "" {
		return false, nil
	}
	ra, err := s.Store.GetRequiredAction(ctx, realm.ID, ActionVerifyProfile)
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil || !ra.Enabled {
		return false, err
	}
	cfg, err := s.UserProfile(ctx, s.Store, realm)
	if err != nil {
		return false, err
	}
	return len(cfg.Validate(ProfileValues(u), userprofile.ContextUser, nil)) > 0, nil
}
