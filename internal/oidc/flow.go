package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// This file implements Keycloak's authentication flow processing: a flow is
// a tree of executions (authenticators and sub flows) with requirements.
//
//   - REQUIRED and CONDITIONAL executions all have to succeed, in order; when
//     a level has any of them, its ALTERNATIVE executions are ignored.
//   - Otherwise one ALTERNATIVE has to succeed; alternatives that do not
//     apply ("attempted", e.g. no SSO cookie) pass to the next one.
//   - A CONDITIONAL sub flow runs only if all its conditional-* executions
//     match.
//   - A form flow (the registration form) renders one page whose submission
//     is validated by all its form actions.
//
// The flow is re-run from the top on every request of the login; executions
// that already succeeded are remembered in the auth session.

type result int

const (
	resSuccess   result = iota
	resAttempted        // not applicable, try an alternative
	resChallenge        // a page was rendered for the user
	resFailed           // the flow failed (error page rendered, or directErr set)
)

// Auth session keys holding flow state.
const (
	keyFlow       = "_flow"       // alias of the flow being run
	keyDone       = "_done"       // executions that succeeded
	keyActions    = "_actions"    // pending required actions
	keyRemember   = "_remember"   // remember me was checked
	keyMode       = "_mode"       // "execute-actions" for admin requested actions
	keyOTPSecret  = "_otp_secret" // secret shown by CONFIGURE_TOTP
	keyNoUser     = "_no_user"    // reset credentials for an unknown user
	keyEmailSent  = "_email_sent" // a reset or verification email was sent
	keyChallenge  = "_challenge"  // WebAuthn challenge
	modeExecution = "execute-actions"
)

// flowContext is the state of one request through a flow.
type flowContext struct {
	h      *Handler
	w      http.ResponseWriter
	r      *http.Request
	realm  *model.Realm
	client *model.Client
	as     *model.AuthSession
	user   *model.User
	sso    *model.UserSession // set by auth-cookie

	exec   *model.AuthExecution
	config map[string]string

	// postedExecution is the execution whose form was submitted; it is
	// processed with the authenticator's action once.
	postedExecution string

	direct    bool  // direct grant: no pages
	directErr error // error to return to the direct grant client
}

func (fc *flowContext) ctx() context.Context { return fc.r.Context() }

func (fc *flowContext) done(id string) bool {
	return slices.Contains(strings.Fields(fc.as.Params[keyDone]), id)
}

func (fc *flowContext) markDone(id string) {
	if !fc.done(id) {
		fc.as.Params[keyDone] = strings.TrimSpace(fc.as.Params[keyDone] + " " + id)
	}
}

// save persists the auth session (flow state and identified user).
func (fc *flowContext) save() error {
	if fc.direct {
		return nil
	}
	if fc.user != nil {
		fc.as.UserID = fc.user.ID
	}
	return fc.h.Svc.Store.UpdateAuthSession(fc.ctx(), fc.as)
}

// actionURL is where a page of the current execution posts to.
func (fc *flowContext) actionURL() string {
	return fc.h.loginActionURL(fc.r, fc.realm, "authenticate", fc.as.ID) + "&execution=" + fc.exec.ID
}

// fail ends the flow: in a direct grant with err, in a browser with an
// error page.
func (fc *flowContext) fail(err *oauthError, page string, args ...any) (result, error) {
	if fc.direct {
		fc.directErr = err
		return resFailed, nil
	}
	fc.h.render(fc.w, http.StatusBadRequest, "error", pageData{realm: fc.realm, r: fc.r, user: fc.user, Title: "errorTitle",
		Error: page, ErrorArgs: args})
	return resFailed, nil
}

// flowFor returns the top level flow bound for a binding ("browser",
// "direct_grant", ...), honouring the client's overrides.
func (h *Handler) flowFor(ctx context.Context, realm *model.Realm, client *model.Client, binding string) (*model.AuthFlow, error) {
	if client != nil {
		if id := client.FlowOverrides[binding]; id != "" {
			if f, err := h.Svc.Store.GetFlow(ctx, realm.ID, id); err == nil {
				return f, nil
			}
		}
	}
	alias := map[string]string{
		"browser":           realm.Settings.BrowserFlow,
		"direct_grant":      realm.Settings.DirectGrantFlow,
		"registration":      realm.Settings.RegistrationFlow,
		"reset_credentials": realm.Settings.ResetCredentialsFlow,
	}[binding]
	if alias == "" {
		alias = map[string]string{"browser": "browser", "direct_grant": "direct grant", "registration": "registration",
			"reset_credentials": "reset credentials"}[binding]
	}
	return h.Svc.Store.GetFlowByAlias(ctx, realm.ID, alias)
}

// runFlow processes the executions of a flow.
func (h *Handler) runFlow(fc *flowContext, flow *model.AuthFlow) (result, error) {
	execs, err := h.Svc.Store.ListExecutions(fc.ctx(), flow.ID)
	if err != nil {
		return 0, err
	}
	var required, alternatives []*model.AuthExecution
	for _, ex := range execs {
		if isCondition(ex.Authenticator) {
			continue // conditions are evaluated by conditionsMet
		}
		switch ex.Requirement {
		case model.Required, model.Conditional:
			required = append(required, ex)
		case model.Alternative:
			alternatives = append(alternatives, ex)
		}
	}
	if len(required) > 0 {
		ran := 0
		for _, ex := range required {
			if ex.Requirement == model.Conditional {
				met, err := h.conditionsMet(fc, ex)
				if err != nil {
					return 0, err
				}
				if !met {
					continue
				}
			}
			res, err := h.runExecution(fc, ex)
			if err != nil || res != resSuccess {
				return res, err
			}
			ran++
		}
		if ran == 0 {
			// Only conditional sub flows whose conditions did not match: the
			// flow authenticated nothing, so an alternative must be tried.
			return resAttempted, nil
		}
		return resSuccess, nil
	}
	if len(alternatives) == 0 {
		return resSuccess, nil
	}
	for _, ex := range alternatives {
		res, err := h.runExecution(fc, ex)
		if err != nil {
			return 0, err
		}
		switch res {
		case resSuccess:
			return resSuccess, nil
		case resAttempted:
			continue
		default:
			return res, nil
		}
	}
	return resAttempted, nil
}

func isCondition(authenticator string) bool { return strings.HasPrefix(authenticator, "conditional-") }

// runExecution runs one execution: an authenticator, a sub flow, or a form.
func (h *Handler) runExecution(fc *flowContext, ex *model.AuthExecution) (result, error) {
	if fc.done(ex.ID) {
		if ex.Authenticator == "auth-cookie" && fc.sso == nil {
			// the cookie authenticated an earlier request of this login
			fc.sso, _ = h.ssoSession(fc.r, fc.realm)
		}
		return resSuccess, nil
	}
	if ex.SubFlowID != "" {
		sub, err := h.Svc.Store.GetFlow(fc.ctx(), fc.realm.ID, ex.SubFlowID)
		if err != nil {
			return 0, err
		}
		var res result
		if sub.ProviderID == "form-flow" {
			res, err = h.runForm(fc, ex, sub)
		} else {
			res, err = h.runFlow(fc, sub)
		}
		if err == nil && res == resSuccess {
			fc.markDone(ex.ID)
		}
		return res, err
	}
	a := authenticators[ex.Authenticator]
	fc.exec, fc.config = ex, nil
	if ex.ConfigID != "" {
		if c, err := h.Svc.Store.GetAuthConfig(fc.ctx(), fc.realm.ID, ex.ConfigID); err == nil {
			fc.config = c.Config
		}
	}
	var fn func(*flowContext) (result, error)
	switch {
	case a == nil:
	case fc.direct:
		fn = a.direct
	case fc.postedExecution == ex.ID && fc.r.Method == http.MethodPost && a.action != nil:
		fc.postedExecution = "" // the form is consumed once
		fn = a.action
	default:
		fn = a.authenticate
	}
	if fn == nil {
		if ex.Requirement == model.Alternative {
			return resAttempted, nil
		}
		return fc.fail(&oauthError{http.StatusBadRequest, "invalid_request", "Authenticator " + ex.Authenticator + " is not supported"},
			"unsupportedAuthenticatorMessage", ex.Authenticator)
	}
	if a.requiresUser && fc.user == nil {
		return fc.fail(&oauthError{http.StatusBadRequest, "invalid_request", "Invalid flow"}, "invalidFlowMessage")
	}
	res, err := fn(fc)
	if err == nil && res == resSuccess {
		fc.markDone(ex.ID)
	}
	return res, err
}

// conditionsMet evaluates the conditions of a CONDITIONAL sub flow.
func (h *Handler) conditionsMet(fc *flowContext, ex *model.AuthExecution) (bool, error) {
	if ex.SubFlowID == "" {
		return false, nil
	}
	execs, err := h.Svc.Store.ListExecutions(fc.ctx(), ex.SubFlowID)
	if err != nil {
		return false, err
	}
	conditions := 0
	for _, c := range execs {
		if !isCondition(c.Authenticator) || c.Requirement == model.Disabled {
			continue
		}
		conditions++
		cfg := map[string]string{}
		if c.ConfigID != "" {
			if ac, err := h.Svc.Store.GetAuthConfig(fc.ctx(), fc.realm.ID, c.ConfigID); err == nil {
				cfg = ac.Config
			}
		}
		ok, err := h.evalCondition(fc, c.Authenticator, cfg, execs)
		if err != nil || !ok {
			return false, err
		}
	}
	return conditions > 0, nil
}

// configured reports whether every authenticator of a set of executions is
// set up for the user (conditional-user-configured).
func (h *Handler) configured(fc *flowContext, execs []*model.AuthExecution) (bool, error) {
	for _, ex := range execs {
		if isCondition(ex.Authenticator) || ex.Requirement == model.Disabled {
			continue
		}
		if ex.SubFlowID != "" {
			sub, err := h.Svc.Store.ListExecutions(fc.ctx(), ex.SubFlowID)
			if err != nil {
				return false, err
			}
			ok, err := h.configured(fc, sub)
			if err != nil || !ok {
				return false, err
			}
			continue
		}
		if a := authenticators[ex.Authenticator]; a != nil && a.configuredFor != nil {
			ok, err := a.configuredFor(fc, fc.user)
			if err != nil || !ok {
				return false, err
			}
		}
	}
	return true, nil
}

// runForm runs a form flow: its authenticator renders the page, its form
// actions validate the submission and then apply it.
func (h *Handler) runForm(fc *flowContext, ex *model.AuthExecution, form *model.AuthFlow) (result, error) {
	execs, err := h.Svc.Store.ListExecutions(fc.ctx(), form.ID)
	if err != nil {
		return 0, err
	}
	var actions []string
	for _, a := range execs {
		if a.Requirement != model.Disabled {
			actions = append(actions, a.Authenticator)
		}
	}
	fc.exec = ex
	posted := fc.postedExecution == ex.ID && fc.r.Method == http.MethodPost
	if fc.direct {
		return fc.fail(&oauthError{http.StatusBadRequest, "invalid_request", "Invalid flow"}, "invalidFlowMessage")
	}
	switch ex.Authenticator {
	case "registration-page-form":
		if !posted {
			return h.renderRegistration(fc, actions, nil, nil)
		}
		fc.postedExecution = ""
		return h.register(fc, actions)
	}
	return fc.fail(&oauthError{http.StatusBadRequest, "invalid_request", "Invalid flow"}, "unsupportedAuthenticatorMessage", ex.Authenticator)
}

// ---------------------------------------------------------------- entry points

// startFlow begins a flow for an auth session and processes it.
func (h *Handler) startFlow(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, as *model.AuthSession, binding string) {
	as.Params[keyFlow] = binding
	delete(as.Params, keyDone)
	delete(as.Params, keyActions)
	delete(as.Params, keyNoUser)
	delete(as.Params, keyEmailSent)
	if err := h.Svc.Store.UpdateAuthSession(r.Context(), as); err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	h.continueFlow(w, r, realm, client, as, "")
}

// continueFlow runs the auth session's flow; postedExecution is the
// execution whose form was submitted, if any.
func (h *Handler) continueFlow(w http.ResponseWriter, r *http.Request, realm *model.Realm, client *model.Client, as *model.AuthSession, postedExecution string) {
	fc := &flowContext{h: h, w: w, r: r, realm: realm, client: client, as: as, postedExecution: postedExecution}
	if as.UserID != "" {
		u, err := h.Svc.Store.GetUser(r.Context(), realm.ID, as.UserID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			h.serverErrorPage(w, r, err)
			return
		}
		fc.user = u
	}
	binding := as.Params[keyFlow]
	if binding == "" {
		binding = "browser"
	}
	flow, err := h.flowFor(r.Context(), realm, client, binding)
	if err != nil {
		h.serverErrorPage(w, r, fmt.Errorf("flow %s: %w", binding, err))
		return
	}
	res, err := h.runFlow(fc, flow)
	if err == nil {
		err = fc.save()
	}
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	switch res {
	case resSuccess:
		h.afterAuthentication(fc)
	case resAttempted:
		h.errorPage(w, r, http.StatusBadRequest, "noAuthenticationMethodMessage")
	}
}

// runDirectGrant runs the direct grant flow for the password grant and
// returns the authenticated user.
func (h *Handler) runDirectGrant(r *http.Request, realm *model.Realm, client *model.Client) (*model.User, error) {
	fc := &flowContext{h: h, r: r, realm: realm, client: client, direct: true,
		as: &model.AuthSession{Params: map[string]string{}}}
	flow, err := h.flowFor(r.Context(), realm, client, "direct_grant")
	if err != nil {
		return nil, err
	}
	res, err := h.runFlow(fc, flow)
	if err != nil {
		return nil, err
	}
	if fc.directErr != nil {
		return nil, fc.directErr
	}
	if res != resSuccess || fc.user == nil {
		return nil, errInvalidCredentials()
	}
	return fc.user, nil
}
