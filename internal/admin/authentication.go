package admin

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// providerInfo describes an authenticator, form or client authenticator.
type providerInfo struct {
	displayName string
	description string
	choices     []string
}

var (
	reqOnly        = []string{model.Required}
	reqAltDisabled = []string{model.Required, model.Alternative, model.Disabled}
	reqDisabled    = []string{model.Required, model.Disabled}
	flowChoices    = []string{model.Required, model.Alternative, model.Disabled, model.Conditional}
)

// providers lists the providers gocloak knows, with Keycloak's names.
var providers = map[string]providerInfo{
	"auth-cookie":                         {"Cookie", "Validates the SSO cookie set by the auth server.", reqAltDisabled},
	"auth-spnego":                         {"Kerberos", "Initiates the SPNEGO protocol. Most often used with Kerberos.", reqAltDisabled},
	"identity-provider-redirector":        {"Identity Provider Redirector", "Redirects to default Identity Provider or Identity Provider specified with kc_idp_hint query parameter", reqAltDisabled},
	"organization":                        {"Organization Identity-First Login", "If organizations are enabled, automatically redirects users to the corresponding identity provider.", reqAltDisabled},
	"auth-username-password-form":         {"Username Password Form", "Validates a username and password from login form.", reqOnly},
	"auth-username-form":                  {"Username Form", "Selects a user from his username.", reqOnly},
	"auth-password-form":                  {"Password Form", "Validates a password from login form.", reqAltDisabled},
	"auth-otp-form":                       {"OTP Form", "Validates a OTP on a separate OTP form.", reqAltDisabled},
	"webauthn-authenticator":              {"WebAuthn Authenticator", "Authenticator for WebAuthn. Usually used for WebAuthn two-factor authentication", reqAltDisabled},
	"webauthn-authenticator-passwordless": {"WebAuthn Passwordless Authenticator", "Authenticator for Passwordless WebAuthn authentication", reqAltDisabled},
	"conditional-user-configured":         {"Condition - user configured", "Executes the current flow only if authenticators are configured", reqDisabled},
	"conditional-user-role":               {"Condition - user role", "Flow is executed only if user has the given role.", reqDisabled},
	"conditional-user-attribute":          {"Condition - user attribute", "Flow is executed only if the user attribute exists and has the expected value", reqDisabled},
	"deny-access-authenticator":           {"Deny access", "Access will be always denied.", reqDisabled},
	"allow-access-authenticator":          {"Allow access", "Authenticator will always successfully authenticate. Useful for example in the conditional flows to be used after satisfying the previous conditions", reqDisabled},
	"direct-grant-validate-username":      {"Username Validation", "Validates the username supplied as a 'username' form parameter in direct grant request", reqOnly},
	"direct-grant-validate-password":      {"Password", "Validates the password supplied as a 'password' form parameter in direct grant request", reqAltDisabled},
	"direct-grant-validate-otp":           {"OTP", "Validates the one time password supplied as a 'totp' form parameter in direct grant request", reqAltDisabled},
	"reset-credentials-choose-user":       {"Choose User", "Choose a user to reset credentials for", reqOnly},
	"reset-credential-email":              {"Send Reset Email", "Send email to user and wait for response.", reqOnly},
	"reset-password":                      {"Reset Password", "Sets the Update Password required action if execution is REQUIRED.  Will also set it if execution is OPTIONAL and the password is currently configured for it.", reqAltDisabled},
	"reset-otp":                           {"Reset OTP", "Removes existing OTP configurations (if chosen) and sets the 'Configure OTP' required action.", reqAltDisabled},
	"registration-page-form":              {"Registration Page", "This is the controller for the registration page", reqDisabled},
	"idp-review-profile":                  {"Review Profile", "User reviews and updates profile data retrieved from Identity Provider in the displayed form", reqAltDisabled},
	"idp-create-user-if-unique":           {"Create User If Unique", "Detect if there is existing gocloak account with same email like identity provider. If no, create new user", reqAltDisabled},
	"idp-confirm-link":                    {"Confirm link existing account", "Show the form where user confirms if he wants to link identity provider with existing account or rather edit user profile data retrieved from identity provider to avoid conflict", reqAltDisabled},
	"idp-email-verification":              {"Verify existing account by Email", "Email verification of existing gocloak user, that wants to link his user account with identity provider", reqAltDisabled},
	"idp-username-password-form":          {"Username Password Form for identity provider reauthentication", "Validates a password from login form. Username may be already known from identity provider authentication", reqOnly},
	"idp-add-organization-member":         {"Organization Member Onboard", "Adds a federated user as a member of an organization", reqAltDisabled},
	"docker-http-basic-authenticator":     {"Docker Authenticator", "Uses HTTP Basic authentication to validate docker users, returning a docker error token on auth failure", reqOnly},
	// the "saml ecp" flow of Keycloak realms (exports); ECP itself is not supported
	"http-basic-authenticator": {"HTTP Basic Authentication", "Validates username and password from Authorization HTTP header", reqAltDisabled},
}

var formActions = map[string]providerInfo{
	"registration-user-creation":        {"Registration User Profile Creation", "This action must always be first! Validates the username and user profile of the user in validation phase.  In success phase, this will create the user in the database including his user profile.", reqDisabled},
	"registration-password-action":      {"Password Validation", "Validates that password matches password confirmation field.  It also will store password in user's credential store.", reqDisabled},
	"registration-recaptcha-action":     {"reCAPTCHA", "Adds Google reCAPTCHA to the form.", reqDisabled},
	"registration-terms-and-conditions": {"Terms and conditions", "Asks the user to accept terms and conditions before submitting its registration form.", reqDisabled},
}

var clientAuthenticators = map[string]providerInfo{
	"client-secret":     {"Client Id and Secret", "Validates client based on 'client_id' and 'client_secret' sent either in request parameters or in 'Authorization: Basic' header", reqAltDisabled},
	"client-jwt":        {"Signed Jwt", "Validates client based on signed JWT issued by client and signed with the Client private key", reqAltDisabled},
	"client-secret-jwt": {"Signed Jwt with Client Secret", "Validates client based on signed JWT issued by client and signed with the Client Secret", reqAltDisabled},
	"client-x509":       {"X509 Certificate", "Validates client based on a X509 Certificate", reqAltDisabled},
}

func lookupProvider(id string) (providerInfo, bool) {
	for _, m := range []map[string]providerInfo{providers, formActions, clientAuthenticators} {
		if p, ok := m[id]; ok {
			return p, true
		}
	}
	return providerInfo{}, false
}

// ---------------------------------------------------------------- representations

type flowRep struct {
	ID                       string    `json:"id,omitempty"`
	Alias                    string    `json:"alias"`
	Description              string    `json:"description"`
	ProviderID               string    `json:"providerId"`
	TopLevel                 bool      `json:"topLevel"`
	BuiltIn                  bool      `json:"builtIn"`
	AuthenticationExecutions []execRep `json:"authenticationExecutions"`
}

type execRep struct {
	Authenticator       string `json:"authenticator,omitempty"`
	AuthenticatorConfig string `json:"authenticatorConfig,omitempty"`
	AuthenticatorFlow   bool   `json:"authenticatorFlow"`
	Requirement         string `json:"requirement"`
	Priority            int    `json:"priority"`
	AutheticatorFlow    bool   `json:"autheticatorFlow"` // sic, as in Keycloak
	FlowAlias           string `json:"flowAlias,omitempty"`
	UserSetupAllowed    bool   `json:"userSetupAllowed"`
}

type authConfigRep struct {
	ID     string `json:"id,omitempty"`
	Alias  string `json:"alias"`
	Config strMap `json:"config"`
}

type requiredActionRep struct {
	Alias         string `json:"alias"`
	Name          string `json:"name"`
	ProviderID    string `json:"providerId"`
	Enabled       bool   `json:"enabled"`
	DefaultAction bool   `json:"defaultAction"`
	Priority      int    `json:"priority"`
	Config        strMap `json:"config"`
}

func requiredActionToRep(a *model.RequiredActionProvider) requiredActionRep {
	return requiredActionRep{a.Alias, a.Name, a.ProviderID, a.Enabled, a.DefaultAction, a.Priority, a.Config}
}

func flowToRep(ctx context.Context, st *store.Store, f *model.AuthFlow) (flowRep, error) {
	rep := flowRep{ID: f.ID, Alias: f.Alias, Description: f.Description, ProviderID: f.ProviderID, TopLevel: f.TopLevel,
		BuiltIn: f.BuiltIn, AuthenticationExecutions: []execRep{}}
	execs, err := st.ListExecutions(ctx, f.ID)
	if err != nil {
		return rep, err
	}
	for _, ex := range execs {
		er := execRep{Authenticator: ex.Authenticator, Requirement: ex.Requirement, Priority: ex.Priority}
		if ex.SubFlowID != "" {
			sub, err := st.GetFlow(ctx, f.RealmID, ex.SubFlowID)
			if err != nil {
				return rep, err
			}
			er.AuthenticatorFlow, er.AutheticatorFlow, er.FlowAlias = true, true, sub.Alias
		}
		if ex.ConfigID != "" {
			if c, err := st.GetAuthConfig(ctx, f.RealmID, ex.ConfigID); err == nil {
				er.AuthenticatorConfig = c.Alias
			}
		}
		rep.AuthenticationExecutions = append(rep.AuthenticationExecutions, er)
	}
	return rep, nil
}

// executionInfo is an entry of GET /authentication/flows/{alias}/executions.
type executionInfo struct {
	ID                   string   `json:"id"`
	Requirement          string   `json:"requirement"`
	DisplayName          string   `json:"displayName"`
	Alias                string   `json:"alias,omitempty"`
	Description          string   `json:"description,omitempty"`
	RequirementChoices   []string `json:"requirementChoices"`
	Configurable         bool     `json:"configurable"`
	AuthenticationFlow   bool     `json:"authenticationFlow,omitempty"`
	ProviderID           string   `json:"providerId,omitempty"`
	AuthenticationConfig string   `json:"authenticationConfig,omitempty"`
	FlowID               string   `json:"flowId,omitempty"`
	Level                int      `json:"level"`
	Index                int      `json:"index"`
	Priority             int      `json:"priority"`
}

func (h *Handler) executionInfos(ctx context.Context, realm *model.Realm, flowID string, level int, out *[]executionInfo) error {
	execs, err := h.Svc.Store.ListExecutions(ctx, flowID)
	if err != nil {
		return err
	}
	for i, ex := range execs {
		info := executionInfo{ID: ex.ID, Requirement: ex.Requirement, Level: level, Index: i, Priority: ex.Priority,
			ProviderID: ex.Authenticator, AuthenticationConfig: ex.ConfigID}
		if p, ok := lookupProvider(ex.Authenticator); ok {
			info.DisplayName, info.Description, info.RequirementChoices = p.displayName, p.description, p.choices
		} else {
			info.DisplayName, info.RequirementChoices = ex.Authenticator, reqAltDisabled
		}
		if ex.SubFlowID != "" {
			sub, err := h.Svc.Store.GetFlow(ctx, realm.ID, ex.SubFlowID)
			if err != nil {
				return err
			}
			info.AuthenticationFlow, info.FlowID, info.DisplayName, info.Description = true, sub.ID, sub.Alias, sub.Description
			info.RequirementChoices = flowChoices
			if sub.ProviderID == "form-flow" {
				info.RequirementChoices = reqDisabled
			}
			*out = append(*out, info)
			if err := h.executionInfos(ctx, realm, sub.ID, level+1, out); err != nil {
				return err
			}
			continue
		}
		*out = append(*out, info)
	}
	return nil
}

// ---------------------------------------------------------------- flows

func (h *Handler) listFlows(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	flows, err := h.Svc.Store.ListFlows(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	out := []flowRep{}
	for _, f := range flows {
		if !f.TopLevel {
			continue
		}
		rep, err := flowToRep(r.Context(), h.Svc.Store, f)
		if err != nil {
			return err
		}
		out = append(out, rep)
	}
	return ok(w, out)
}

func (h *Handler) flowByAlias(r *http.Request, realm *model.Realm) (*model.AuthFlow, error) {
	f, err := h.Svc.Store.GetFlowByAlias(r.Context(), realm.ID, r.PathValue("flowAlias"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Flow")
	}
	return f, err
}

func (h *Handler) getFlow(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	f, err := h.Svc.Store.GetFlow(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Could not find flow with id")
	}
	if err != nil {
		return err
	}
	rep, err := flowToRep(r.Context(), h.Svc.Store, f)
	if err != nil {
		return err
	}
	return ok(w, rep)
}

func (h *Handler) createFlow(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	var rep flowRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Alias == "" {
		return badRequestPlain("Flow alias is required")
	}
	if rep.ProviderID == "" {
		rep.ProviderID = "basic-flow"
	}
	f := &model.AuthFlow{ID: service.NewID(), RealmID: realm.ID, Alias: rep.Alias, Description: rep.Description,
		ProviderID: rep.ProviderID, TopLevel: true}
	if err := h.Svc.Store.CreateFlow(r.Context(), f); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Flow " + rep.Alias + " already exists")
		}
		return err
	}
	return createdAt(w, r, "/authentication/flows/"+f.ID)
}

// createdAt writes 201 with a Location relative to the realm's admin URL.
func createdAt(w http.ResponseWriter, r *http.Request, rel string) error {
	u := requestURL(r)
	i := strings.Index(u, "/admin/realms/")
	rest := u[i+len("/admin/realms/"):]
	realm, _, _ := strings.Cut(rest, "/")
	w.Header().Set("Location", u[:i]+"/admin/realms/"+realm+rel)
	w.WriteHeader(http.StatusCreated)
	return nil
}

func (h *Handler) updateFlow(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	f, err := h.Svc.Store.GetFlow(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Could not find flow with id")
	}
	if err != nil {
		return err
	}
	var rep flowRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Alias != "" && rep.Alias != f.Alias {
		if f.BuiltIn {
			return badRequestPlain("Can't rename built in flow")
		}
		f.Alias = rep.Alias
	}
	f.Description = rep.Description
	if err := h.Svc.Store.UpdateFlow(r.Context(), f); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Flow " + rep.Alias + " already exists")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteFlow(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	f, err := h.Svc.Store.GetFlow(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Could not find flow with id")
	}
	if err != nil {
		return err
	}
	if f.BuiltIn {
		return badRequestPlain("Can't delete built in flow")
	}
	s := realm.Settings
	for _, bound := range []string{s.BrowserFlow, s.DirectGrantFlow, s.RegistrationFlow, s.ResetCredentialsFlow,
		s.ClientAuthenticationFlow, s.FirstBrokerLoginFlow, s.DockerAuthenticationFlow} {
		if bound == f.Alias {
			return conflict("Cannot delete flow, it is used by the realm")
		}
	}
	if err := h.Svc.Store.DeleteFlow(r.Context(), f.ID); err != nil {
		return err
	}
	return noContent(w)
}

// copyFlow deep-copies a flow (POST /authentication/flows/{alias}/copy).
func (h *Handler) copyFlow(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	src, err := h.flowByAlias(r, realm)
	if err != nil {
		return err
	}
	var body struct {
		NewName string `json:"newName"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if body.NewName == "" {
		return badRequestPlain("New name for flow is required")
	}
	var dst *model.AuthFlow
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		var err error
		dst, err = copyFlow(r.Context(), tx, realm, src, body.NewName, true)
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("New flow alias name already exists")
	}
	if err != nil {
		return err
	}
	return createdAt(w, r, "/authentication/flows/"+dst.ID)
}

func copyFlow(ctx context.Context, tx *store.Store, realm *model.Realm, src *model.AuthFlow, alias string, topLevel bool) (*model.AuthFlow, error) {
	dst := &model.AuthFlow{ID: service.NewID(), RealmID: realm.ID, Alias: alias, Description: src.Description,
		ProviderID: src.ProviderID, TopLevel: topLevel}
	if err := tx.CreateFlow(ctx, dst); err != nil {
		return nil, err
	}
	execs, err := tx.ListExecutions(ctx, src.ID)
	if err != nil {
		return nil, err
	}
	for _, ex := range execs {
		nx := *ex
		nx.ID, nx.FlowID = service.NewID(), dst.ID
		if ex.SubFlowID != "" {
			sub, err := tx.GetFlow(ctx, realm.ID, ex.SubFlowID)
			if err != nil {
				return nil, err
			}
			copied, err := copyFlow(ctx, tx, realm, sub, alias+" "+sub.Alias, false)
			if err != nil {
				return nil, err
			}
			nx.SubFlowID = copied.ID
		}
		if ex.ConfigID != "" {
			if c, err := tx.GetAuthConfig(ctx, realm.ID, ex.ConfigID); err == nil {
				nc := &model.AuthenticatorConfig{ID: service.NewID(), RealmID: realm.ID, Alias: c.Alias, Config: c.Config}
				if err := tx.CreateAuthConfig(ctx, nc); err != nil {
					return nil, err
				}
				nx.ConfigID = nc.ID
			}
		}
		if err := tx.CreateExecution(ctx, &nx); err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// ---------------------------------------------------------------- executions

func (h *Handler) getExecutions(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	f, err := h.flowByAlias(r, realm)
	if err != nil {
		return err
	}
	out := []executionInfo{}
	if err := h.executionInfos(r.Context(), realm, f.ID, 0, &out); err != nil {
		return err
	}
	return ok(w, out)
}

func nextPriority(ctx context.Context, st *store.Store, flowID string) (int, error) {
	execs, err := st.ListExecutions(ctx, flowID)
	if err != nil {
		return 0, err
	}
	if len(execs) == 0 {
		return 0, nil
	}
	return execs[len(execs)-1].Priority + 1, nil
}

func (h *Handler) addExecution(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	f, err := h.flowByAlias(r, realm)
	if err != nil {
		return err
	}
	if f.BuiltIn {
		return badRequestPlain("It is illegal to add execution to a built in flow")
	}
	var body struct {
		Provider string `json:"provider"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	info, known := lookupProvider(body.Provider)
	if !known {
		return badRequestPlain("No authentication provider found for id: " + body.Provider)
	}
	req := model.Disabled
	if len(info.choices) == 1 {
		req = info.choices[0]
	}
	prio, err := nextPriority(r.Context(), h.Svc.Store, f.ID)
	if err != nil {
		return err
	}
	ex := &model.AuthExecution{ID: service.NewID(), RealmID: realm.ID, FlowID: f.ID, Authenticator: body.Provider,
		Requirement: req, Priority: prio}
	if err := h.Svc.Store.CreateExecution(r.Context(), ex); err != nil {
		return err
	}
	return createdAt(w, r, "/authentication/executions/"+ex.ID)
}

func (h *Handler) addSubflow(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	f, err := h.flowByAlias(r, realm)
	if err != nil {
		return err
	}
	if f.BuiltIn {
		return badRequestPlain("It is illegal to add sub-flow to a built in flow")
	}
	var body struct {
		Alias       string `json:"alias"`
		Type        string `json:"type"`
		Provider    string `json:"provider"`
		Description string `json:"description"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	if body.Type == "" {
		body.Type = "basic-flow"
	}
	if body.Type != "basic-flow" && body.Type != "form-flow" {
		return badRequestPlain("Unknown flow type " + body.Type)
	}
	sub := &model.AuthFlow{ID: service.NewID(), RealmID: realm.ID, Alias: body.Alias, Description: body.Description, ProviderID: body.Type}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := tx.CreateFlow(r.Context(), sub); err != nil {
			return err
		}
		prio, err := nextPriority(r.Context(), tx, f.ID)
		if err != nil {
			return err
		}
		authenticator := ""
		if body.Type == "form-flow" {
			authenticator = body.Provider
		}
		return tx.CreateExecution(r.Context(), &model.AuthExecution{ID: service.NewID(), RealmID: realm.ID, FlowID: f.ID,
			Authenticator: authenticator, SubFlowID: sub.ID, Requirement: model.Disabled, Priority: prio})
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("New flow alias name already exists")
	}
	if err != nil {
		return err
	}
	return createdAt(w, r, "/authentication/flows/"+sub.ID)
}

func (h *Handler) updateExecution(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	if _, err := h.flowByAlias(r, realm); err != nil {
		return err
	}
	var info executionInfo
	if err := decode(r, &info); err != nil {
		return err
	}
	ex, err := h.Svc.Store.GetExecution(r.Context(), realm.ID, info.ID)
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Illegal execution")
	}
	if err != nil {
		return err
	}
	switch info.Requirement {
	case model.Required, model.Alternative, model.Disabled, model.Conditional:
	default:
		return badRequestPlain("Invalid requirement " + info.Requirement)
	}
	if info.Requirement == model.Conditional && ex.SubFlowID == "" {
		return badRequestPlain("Only sub flows can be conditional")
	}
	ex.Requirement = info.Requirement
	if info.Priority != 0 {
		ex.Priority = info.Priority
	}
	if err := h.Svc.Store.UpdateExecution(r.Context(), ex); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) loadExecution(r *http.Request, p *principal, write bool) (*model.Realm, *model.AuthExecution, error) {
	perm := permViewRealm
	if write {
		perm = permManageRealm
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, nil, err
	}
	ex, err := h.Svc.Store.GetExecution(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, notFound("Illegal execution")
	}
	return realm, ex, err
}

func (h *Handler) getExecution(w http.ResponseWriter, r *http.Request, p *principal) error {
	_, ex, err := h.loadExecution(r, p, false)
	if err != nil {
		return err
	}
	return ok(w, map[string]any{"id": ex.ID, "authenticator": ex.Authenticator, "authenticatorFlow": ex.SubFlowID != "",
		"requirement": ex.Requirement, "priority": ex.Priority, "parentFlow": ex.FlowID, "flowId": ex.SubFlowID,
		"authenticatorConfig": ex.ConfigID})
}

func (h *Handler) deleteExecution(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, ex, err := h.loadExecution(r, p, true)
	if err != nil {
		return err
	}
	if f, err := h.Svc.Store.GetFlow(r.Context(), realm.ID, ex.FlowID); err == nil && f.BuiltIn {
		return badRequestPlain("It is illegal to remove execution from a built in flow")
	}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := tx.DeleteExecution(r.Context(), ex.ID); err != nil {
			return err
		}
		if ex.SubFlowID != "" {
			return tx.DeleteFlow(r.Context(), ex.SubFlowID)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

// movePriority swaps an execution with its neighbour.
func (h *Handler) movePriority(up bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		_, ex, err := h.loadExecution(r, p, true)
		if err != nil {
			return err
		}
		execs, err := h.Svc.Store.ListExecutions(r.Context(), ex.FlowID)
		if err != nil {
			return err
		}
		for i, e := range execs {
			if e.ID != ex.ID {
				continue
			}
			j := i + 1
			if up {
				j = i - 1
			}
			if j < 0 || j >= len(execs) {
				return noContent(w)
			}
			other := execs[j]
			// renumber so that equal priorities still swap
			for k, x := range execs {
				x.Priority = k * 10
			}
			ex, other = execs[i], execs[j]
			ex.Priority, other.Priority = other.Priority, ex.Priority
			err := h.withTx(r.Context(), func(tx *store.Store) error {
				for _, x := range execs {
					if err := tx.UpdateExecution(r.Context(), x); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			return noContent(w)
		}
		return noContent(w)
	}
}

// ---------------------------------------------------------------- configs

func (h *Handler) createExecutionConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, ex, err := h.loadExecution(r, p, true)
	if err != nil {
		return err
	}
	var rep authConfigRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Alias == "" {
		return badRequestPlain("Alias is required")
	}
	c := &model.AuthenticatorConfig{ID: service.NewID(), RealmID: realm.ID, Alias: rep.Alias, Config: rep.Config}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := tx.CreateAuthConfig(r.Context(), c); err != nil {
			return err
		}
		ex.ConfigID = c.ID
		return tx.UpdateExecution(r.Context(), ex)
	})
	if err != nil {
		return err
	}
	return createdAt(w, r, "/authentication/executions/"+ex.ID+"/config/"+c.ID)
}

func (h *Handler) loadAuthConfig(r *http.Request, p *principal, write bool) (*model.AuthenticatorConfig, error) {
	perm := permViewRealm
	if write {
		perm = permManageRealm
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	c, err := h.Svc.Store.GetAuthConfig(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find authenticator config")
	}
	return c, err
}

func (h *Handler) getAuthConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	c, err := h.loadAuthConfig(r, p, false)
	if err != nil {
		return err
	}
	return ok(w, authConfigRep{c.ID, c.Alias, c.Config})
}

func (h *Handler) updateAuthConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	c, err := h.loadAuthConfig(r, p, true)
	if err != nil {
		return err
	}
	var rep authConfigRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Alias != "" {
		c.Alias = rep.Alias
	}
	if rep.Config != nil {
		c.Config = rep.Config
	}
	if err := h.Svc.Store.UpdateAuthConfig(r.Context(), c); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteAuthConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	c, err := h.loadAuthConfig(r, p, true)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteAuthConfig(r.Context(), c.ID); err != nil {
		return err
	}
	return noContent(w)
}

// ---------------------------------------------------------------- providers

func providerList(m map[string]providerInfo) []map[string]string {
	out := []map[string]string{}
	for id, p := range m {
		out = append(out, map[string]string{"id": id, "displayName": p.displayName, "description": p.description})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"] < out[j]["id"] })
	return out
}

func (h *Handler) providerListHandler(m map[string]providerInfo) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		if _, err := h.realmFor(r, p, permViewRealm); err != nil {
			return err
		}
		return ok(w, providerList(m))
	}
}

// ---------------------------------------------------------------- required actions

func (h *Handler) listRequiredActions(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	actions, err := h.Svc.Store.ListRequiredActions(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	out := []requiredActionRep{}
	for _, a := range actions {
		out = append(out, requiredActionToRep(a))
	}
	return ok(w, out)
}

func (h *Handler) loadRequiredAction(r *http.Request, p *principal, write bool) (*model.RequiredActionProvider, error) {
	perm := permViewRealm
	if write {
		perm = permManageRealm
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	a, err := h.Svc.Store.GetRequiredAction(r.Context(), realm.ID, r.PathValue("alias"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Failed to find required action")
	}
	return a, err
}

func (h *Handler) getRequiredAction(w http.ResponseWriter, r *http.Request, p *principal) error {
	a, err := h.loadRequiredAction(r, p, false)
	if err != nil {
		return err
	}
	return ok(w, requiredActionToRep(a))
}

func (h *Handler) updateRequiredAction(w http.ResponseWriter, r *http.Request, p *principal) error {
	a, err := h.loadRequiredAction(r, p, true)
	if err != nil {
		return err
	}
	var rep requiredActionRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	a.Enabled, a.DefaultAction = rep.Enabled, rep.DefaultAction && rep.Enabled
	if rep.Name != "" {
		a.Name = rep.Name
	}
	if rep.Priority != 0 {
		a.Priority = rep.Priority
	}
	if rep.Config != nil {
		a.Config = rep.Config
	}
	if err := h.Svc.Store.UpdateRequiredAction(r.Context(), a); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteRequiredAction(w http.ResponseWriter, r *http.Request, p *principal) error {
	a, err := h.loadRequiredAction(r, p, true)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteRequiredAction(r.Context(), a.RealmID, a.Alias); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) moveRequiredAction(up bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		a, err := h.loadRequiredAction(r, p, true)
		if err != nil {
			return err
		}
		all, err := h.Svc.Store.ListRequiredActions(r.Context(), a.RealmID)
		if err != nil {
			return err
		}
		for i, x := range all {
			if x.Alias != a.Alias {
				continue
			}
			j := i + 1
			if up {
				j = i - 1
			}
			if j < 0 || j >= len(all) {
				return noContent(w)
			}
			for k, y := range all {
				y.Priority = (k + 1) * 10
			}
			all[i].Priority, all[j].Priority = all[j].Priority, all[i].Priority
			err := h.withTx(r.Context(), func(tx *store.Store) error {
				for _, y := range all {
					if err := tx.UpdateRequiredAction(r.Context(), y); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			return noContent(w)
		}
		return noContent(w)
	}
}

func (h *Handler) unregisteredRequiredActions(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	out := []map[string]string{}
	for _, a := range service.UnregisteredRequiredActions {
		if _, err := h.Svc.Store.GetRequiredAction(r.Context(), realm.ID, a.Alias); errors.Is(err, store.ErrNotFound) {
			out = append(out, map[string]string{"providerId": a.Alias, "name": a.Name})
		}
	}
	return ok(w, out)
}

func (h *Handler) registerRequiredAction(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	var body struct {
		ProviderID string `json:"providerId"`
		Name       string `json:"name"`
	}
	if err := decode(r, &body); err != nil {
		return err
	}
	known := false
	for _, a := range append(append([]model.RequiredActionProvider{}, service.DefaultRequiredActions...), service.UnregisteredRequiredActions...) {
		if a.Alias == body.ProviderID {
			known = true
			if body.Name == "" {
				body.Name = a.Name
			}
		}
	}
	if !known {
		return badRequestPlain("No provider found for providerId: " + body.ProviderID)
	}
	all, err := h.Svc.Store.ListRequiredActions(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	prio := 10
	for _, a := range all {
		if a.Priority >= prio {
			prio = a.Priority + 10
		}
	}
	err = h.Svc.Store.CreateRequiredAction(r.Context(), &model.RequiredActionProvider{RealmID: realm.ID, Alias: body.ProviderID,
		Name: body.Name, ProviderID: body.ProviderID, Enabled: true, Priority: prio})
	if errors.Is(err, store.ErrConflict) {
		return conflict("Required action already registered")
	}
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) registerAuthenticationRoutes(R string, add func(pattern string, fn handlerFunc)) {
	A := R + "/authentication"
	add("GET "+A+"/flows", h.listFlows)
	add("POST "+A+"/flows", h.createFlow)
	add("GET "+A+"/flows/{id}", h.getFlow)
	add("PUT "+A+"/flows/{id}", h.updateFlow)
	add("DELETE "+A+"/flows/{id}", h.deleteFlow)
	add("POST "+A+"/flows/{flowAlias}/copy", h.copyFlow)
	add("GET "+A+"/flows/{flowAlias}/executions", h.getExecutions)
	add("PUT "+A+"/flows/{flowAlias}/executions", h.updateExecution)
	add("POST "+A+"/flows/{flowAlias}/executions/execution", h.addExecution)
	add("POST "+A+"/flows/{flowAlias}/executions/flow", h.addSubflow)
	add("GET "+A+"/executions/{id}", h.getExecution)
	add("DELETE "+A+"/executions/{id}", h.deleteExecution)
	add("POST "+A+"/executions/{id}/raise-priority", h.movePriority(true))
	add("POST "+A+"/executions/{id}/lower-priority", h.movePriority(false))
	add("POST "+A+"/executions/{id}/config", h.createExecutionConfig)
	add("GET "+A+"/config/{id}", h.getAuthConfig)
	add("PUT "+A+"/config/{id}", h.updateAuthConfig)
	add("DELETE "+A+"/config/{id}", h.deleteAuthConfig)
	add("GET "+A+"/authenticator-providers", h.providerListHandler(providers))
	add("GET "+A+"/form-action-providers", h.providerListHandler(formActions))
	add("GET "+A+"/client-authenticator-providers", h.providerListHandler(clientAuthenticators))
	add("GET "+A+"/form-providers", h.providerListHandler(map[string]providerInfo{"registration-page-form": providers["registration-page-form"]}))
	add("GET "+A+"/required-actions", h.listRequiredActions)
	add("GET "+A+"/required-actions/{alias}", h.getRequiredAction)
	add("PUT "+A+"/required-actions/{alias}", h.updateRequiredAction)
	add("DELETE "+A+"/required-actions/{alias}", h.deleteRequiredAction)
	add("POST "+A+"/required-actions/{alias}/raise-priority", h.moveRequiredAction(true))
	add("POST "+A+"/required-actions/{alias}/lower-priority", h.moveRequiredAction(false))
	add("GET "+A+"/unregistered-required-actions", h.unregisteredRequiredActions)
	add("POST "+A+"/register-required-action", h.registerRequiredAction)
}
