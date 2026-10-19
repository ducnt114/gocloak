// Package account implements the account console of a realm
// (/realms/{realm}/account): server-rendered pages for users to manage their
// profile, credentials, sessions and applications, and Keycloak's account
// REST API on the same paths for JSON requests.
package account

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
	"github.com/ducnt114/gocloak/internal/theme"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

// Handler serves the account console and API.
type Handler struct {
	Svc    *service.Service
	URLs   oidc.URLs
	Log    *slog.Logger
	Themes *theme.Manager
	OIDC   *oidc.Handler
}

// Register adds the account routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	const A = "/realms/{realm}/account"
	for _, p := range []string{A, A + "/"} {
		mux.HandleFunc("GET "+p, h.dispatch(h.personalInfo, h.apiGetAccount))
		mux.HandleFunc("POST "+p, h.dispatch(h.savePersonalInfo, h.apiUpdateAccount))
	}
	mux.HandleFunc("GET "+A+"/security", h.page(h.security))
	mux.HandleFunc("POST "+A+"/security/credentials/{id}/delete", h.page(h.deleteCredentialPage))
	mux.HandleFunc("GET "+A+"/device-activity", h.page(h.deviceActivity))
	mux.HandleFunc("POST "+A+"/device-activity/sign-out", h.page(h.signOutPage))
	mux.HandleFunc("GET "+A+"/applications", h.dispatch(h.applicationsPage, h.apiApplications))
	mux.HandleFunc("POST "+A+"/applications/{clientId}/revoke", h.page(h.revokeApplicationPage))
	mux.HandleFunc("GET "+A+"/groups", h.dispatch(h.groupsPage, h.apiGroups))

	// REST API only
	mux.HandleFunc("GET "+A+"/sessions", h.api(h.apiSessions))
	mux.HandleFunc("GET "+A+"/sessions/devices", h.api(h.apiDevices))
	mux.HandleFunc("DELETE "+A+"/sessions", h.api(h.apiDeleteSessions))
	mux.HandleFunc("DELETE "+A+"/sessions/{id}", h.api(h.apiDeleteSession))
	mux.HandleFunc("GET "+A+"/credentials", h.api(h.apiCredentials))
	mux.HandleFunc("DELETE "+A+"/credentials/{id}", h.api(h.apiDeleteCredential))
	mux.HandleFunc("PUT "+A+"/credentials/{id}/label", h.api(h.apiCredentialLabel))
	mux.HandleFunc("DELETE "+A+"/applications/{clientId}/consent", h.api(h.apiRevokeConsent))
	mux.HandleFunc("GET "+A+"/linked-accounts", h.api(func(w http.ResponseWriter, r *http.Request, c *caller) error {
		return writeJSON(w, http.StatusOK, []any{})
	}))
}

// caller is the authenticated user of a request.
type caller struct {
	realm   *model.Realm
	user    *model.User
	session *model.UserSession
	roles   map[string]bool // account client roles
}

// can checks an account role; manage-account includes view-profile.
func (c *caller) can(role string) bool {
	return c.roles[role] || (role == "view-profile" && c.roles["manage-account"])
}

func wantsJSON(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "application/json") || strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") ||
		strings.HasPrefix(r.Header.Get("Authorization"), "bearer ")
}

func (h *Handler) realm(r *http.Request) (*model.Realm, error) {
	realm, err := h.Svc.Store.GetRealmByName(r.Context(), r.PathValue("realm"))
	if err != nil {
		return nil, err
	}
	if !realm.Enabled {
		return nil, store.ErrNotFound
	}
	return realm, nil
}

// accountRoles returns the user's roles of the account client.
func (h *Handler) accountRoles(ctx context.Context, realm *model.Realm, u *model.User) (map[string]bool, error) {
	acc, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, service.AccountClient)
	if err != nil {
		return nil, err
	}
	roles, err := h.Svc.EffectiveRoles(ctx, realm.ID, u.ID)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, role := range roles {
		if role.ClientID == acc.ID {
			out[role.Name] = true
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- REST API

type apiFunc func(w http.ResponseWriter, r *http.Request, c *caller) error

type apiError struct {
	status int
	body   any
}

func (e *apiError) Error() string { return http.StatusText(e.status) }

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		return json.NewEncoder(w).Encode(v)
	}
	return nil
}

// api authenticates a bearer token issued by the realm, like Keycloak's
// account REST service, and requires an account role.
func (h *Handler) api(fn apiFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := func() error {
			realm, err := h.realm(r)
			if err != nil {
				return &apiError{http.StatusNotFound, map[string]string{"error": "Realm does not exist"}}
			}
			a := r.Header.Get("Authorization")
			if len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
				return &apiError{http.StatusUnauthorized, nil}
			}
			vt, err := h.Svc.VerifyToken(r.Context(), realm, strings.TrimSpace(a[7:]), h.URLs.Issuer(r, realm.Name), service.TokenBearer)
			if err != nil || vt.User == nil {
				if err != nil && !errors.Is(err, service.ErrInvalidToken) {
					return err
				}
				return &apiError{http.StatusUnauthorized, nil}
			}
			roles, err := h.accountRoles(r.Context(), realm, vt.User)
			if err != nil {
				return err
			}
			c := &caller{realm: realm, user: vt.User, session: vt.Session, roles: roles}
			need := "manage-account"
			if r.Method == http.MethodGet {
				need = "view-profile"
			}
			if !c.can(need) {
				return &apiError{http.StatusForbidden, nil}
			}
			return fn(w, r, c)
		}()
		if err == nil {
			return
		}
		var ae *apiError
		if errors.As(err, &ae) {
			if ae.status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			writeJSON(w, ae.status, ae.body)
			return
		}
		h.Log.Error("account api", "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unknown_error"})
	}
}

// dispatch serves the HTML page or, for JSON requests, the API.
func (h *Handler) dispatch(page pageFunc, api apiFunc) http.HandlerFunc {
	p, a := h.page(page), h.api(api)
	return func(w http.ResponseWriter, r *http.Request) {
		if wantsJSON(r) {
			a(w, r)
			return
		}
		p(w, r)
	}
}

// accountRep is the representation of GET /account.
type accountRep struct {
	ID                  string              `json:"id,omitempty"`
	Username            string              `json:"username,omitempty"`
	FirstName           string              `json:"firstName,omitempty"`
	LastName            string              `json:"lastName,omitempty"`
	Email               string              `json:"email,omitempty"`
	EmailVerified       bool                `json:"emailVerified"`
	Attributes          map[string][]string `json:"attributes,omitempty"`
	UserProfileMetadata any                 `json:"userProfileMetadata,omitempty"`
}

func (h *Handler) apiGetAccount(w http.ResponseWriter, r *http.Request, c *caller) error {
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, c.realm)
	if err != nil {
		return err
	}
	u := c.user
	rep := accountRep{ID: u.ID, Username: u.Username, FirstName: u.FirstName, LastName: u.LastName, Email: u.Email,
		EmailVerified: u.EmailVerified, Attributes: map[string][]string{}}
	for k, v := range u.Attributes {
		if cfg.CanView(k, userprofile.ContextUser) {
			rep.Attributes[k] = v
		}
	}
	if r.URL.Query().Get("userProfileMetadata") == "true" {
		rep.UserProfileMetadata = profileMetadata(cfg)
	}
	return writeJSON(w, http.StatusOK, rep)
}

func profileMetadata(cfg *userprofile.Config) map[string]any {
	var attrs []map[string]any
	for _, a := range cfg.Attributes {
		if !cfg.CanView(a.Name, userprofile.ContextUser) {
			continue
		}
		required := a.Name == "username" || (a.Required != nil && (len(a.Required.Roles) == 0 || slices.Contains(a.Required.Roles, userprofile.ContextUser)))
		attrs = append(attrs, map[string]any{"name": a.Name, "displayName": a.DisplayName, "required": required,
			"readOnly": !cfg.CanEdit(a.Name, userprofile.ContextUser), "validators": a.Validations, "multivalued": a.Multivalued})
	}
	return map[string]any{"attributes": attrs, "groups": cfg.Groups}
}

// updateProfile validates and saves profile values in the user context.
func (h *Handler) updateProfile(ctx context.Context, realm *model.Realm, u *model.User, values map[string][]string) (userprofile.Errors, error) {
	cfg, err := h.Svc.UserProfile(ctx, h.Svc.Store, realm)
	if err != nil {
		return nil, err
	}
	merged := service.ProfileValues(u)
	for k, v := range values {
		if cfg.CanEdit(k, userprofile.ContextUser) {
			merged[k] = v
		}
	}
	if !realm.Settings.EditUsernameAllowed {
		merged["username"] = []string{u.Username}
	}
	if errs := cfg.Validate(merged, userprofile.ContextUser, nil); len(errs) > 0 {
		return errs, nil
	}
	nu := *u
	first := func(k string) string {
		if v := merged[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	nu.Username, nu.FirstName, nu.LastName = first("username"), first("firstName"), first("lastName")
	if email := strings.ToLower(first("email")); email != u.Email {
		nu.Email, nu.EmailVerified = email, false
	}
	nu.Attributes = map[string][]string{}
	for k, v := range u.Attributes {
		nu.Attributes[k] = v
	}
	for k, v := range merged {
		if userprofile.IsCore(k) || !cfg.CanEdit(k, userprofile.ContextUser) {
			continue
		}
		if len(v) == 0 || (len(v) == 1 && v[0] == "") {
			delete(nu.Attributes, k)
		} else {
			nu.Attributes[k] = v
		}
	}
	if err := h.Svc.UpdateUser(ctx, h.Svc.Store, &nu); err != nil {
		if errors.Is(err, store.ErrConflict) {
			field, msg := "username", "usernameExistsMessage"
			if strings.Contains(err.Error(), "email") {
				field, msg = "email", "emailExistsMessage"
			}
			return userprofile.Errors{{Field: field, ErrorMessage: msg, Params: []any{field}}}, nil
		}
		return nil, err
	}
	*u = nu
	h.Svc.RecordEvent(ctx, realm, &model.Event{Type: "UPDATE_PROFILE", UserID: u.ID, ClientID: service.AccountClient})
	return nil, nil
}

func (h *Handler) apiUpdateAccount(w http.ResponseWriter, r *http.Request, c *caller) error {
	var rep accountRep
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&rep); err != nil {
		return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "Invalid JSON"}}
	}
	values := map[string][]string{"username": {rep.Username}, "email": {rep.Email}, "firstName": {rep.FirstName}, "lastName": {rep.LastName}}
	if rep.Username == "" {
		values["username"] = []string{c.user.Username}
	}
	for k, v := range rep.Attributes {
		values[k] = v
	}
	errs, err := h.updateProfile(r.Context(), c.realm, c.user, values)
	if err != nil {
		return err
	}
	if len(errs) == 1 {
		return &apiError{http.StatusBadRequest, errs[0]}
	}
	if len(errs) > 1 {
		return &apiError{http.StatusBadRequest, map[string]any{"errors": errs}}
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// sessionRep is Keycloak's account SessionRepresentation.
type sessionRep struct {
	ID         string      `json:"id"`
	IPAddress  string      `json:"ipAddress"`
	Started    int64       `json:"started"`
	LastAccess int64       `json:"lastAccess"`
	Expires    int64       `json:"expires"`
	Browser    string      `json:"browser,omitempty"`
	Current    bool        `json:"current,omitempty"`
	Clients    []clientRep `json:"clients"`
}

type clientRep struct {
	ClientID   string `json:"clientId"`
	ClientName string `json:"clientName"`
	URL        string `json:"url,omitempty"`
}

func (h *Handler) sessions(ctx context.Context, c *caller, base string) ([]sessionRep, error) {
	list, err := h.Svc.Store.ListUserSessions(ctx, c.user.ID)
	if err != nil {
		return nil, err
	}
	out := []sessionRep{}
	for _, s := range list {
		if !h.Svc.SessionValid(c.realm, s) {
			continue
		}
		rep := sessionRep{ID: s.ID, IPAddress: s.IPAddress, Started: s.Started.Unix(), LastAccess: s.LastRefresh.Unix(),
			Expires: s.Started.Add(time.Duration(h.Svc.SessionMaxLifespan(c.realm, s)) * time.Second).Unix(),
			Browser: browserName(s.Notes["userAgent"]), Current: c.session != nil && c.session.ID == s.ID, Clients: []clientRep{}}
		for cid := range s.Clients {
			cl, err := h.Svc.Store.GetClient(ctx, c.realm.ID, cid)
			if err != nil {
				continue
			}
			name := cl.Name
			if name == "" || strings.HasPrefix(name, "${") {
				name = cl.ClientID
			}
			rep.Clients = append(rep.Clients, clientRep{ClientID: cl.ClientID, ClientName: name, URL: clientURL(base, cl)})
		}
		sort.Slice(rep.Clients, func(i, j int) bool { return rep.Clients[i].ClientID < rep.Clients[j].ClientID })
		out = append(out, rep)
	}
	return out, nil
}

func clientURL(base string, c *model.Client) string {
	u := c.BaseURL
	if u == "" {
		return ""
	}
	if strings.HasPrefix(u, "/") {
		root := strings.ReplaceAll(c.RootURL, "${authBaseUrl}", base)
		if root == "" {
			root = base
		}
		u = strings.TrimSuffix(root, "/") + u
	}
	return u
}

// browserName summarises a User-Agent header.
func browserName(ua string) string {
	switch {
	case ua == "":
		return ""
	case strings.Contains(ua, "Edg/"):
		return "Edge"
	case strings.Contains(ua, "Firefox/"):
		return "Firefox"
	case strings.Contains(ua, "Chrome/"):
		return "Chrome"
	case strings.Contains(ua, "Safari/"):
		return "Safari"
	case strings.HasPrefix(ua, "Go-http-client"):
		return "Go HTTP client"
	}
	if i := strings.IndexAny(ua, "/ "); i > 0 {
		return ua[:i]
	}
	return ua
}

func (h *Handler) apiSessions(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.sessions(r.Context(), c, h.URLs.Base(r))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, list)
}

func (h *Handler) apiDevices(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.sessions(r.Context(), c, h.URLs.Base(r))
	if err != nil {
		return err
	}
	type device struct {
		ID         string       `json:"id"`
		IPAddress  string       `json:"ipAddress"`
		Browser    string       `json:"browser,omitempty"`
		LastAccess int64        `json:"lastAccess"`
		Current    bool         `json:"current,omitempty"`
		Sessions   []sessionRep `json:"sessions"`
	}
	out := []device{}
	for _, s := range list {
		out = append(out, device{ID: s.ID, IPAddress: s.IPAddress, Browser: s.Browser, LastAccess: s.LastAccess, Current: s.Current, Sessions: []sessionRep{s}})
	}
	return writeJSON(w, http.StatusOK, out)
}

// signOut ends the user's sessions: all, or all but the current one.
func (h *Handler) signOut(ctx context.Context, c *caller, includeCurrent bool) error {
	list, err := h.Svc.Store.ListUserSessions(ctx, c.user.ID)
	if err != nil {
		return err
	}
	for _, s := range list {
		if !includeCurrent && c.session != nil && s.ID == c.session.ID {
			continue
		}
		if err := h.Svc.Store.DeleteSession(ctx, s); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handler) apiDeleteSessions(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := h.signOut(r.Context(), c, r.URL.Query().Get("current") == "true"); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) apiDeleteSession(w http.ResponseWriter, r *http.Request, c *caller) error {
	s, err := h.Svc.Store.GetUserSession(r.Context(), r.PathValue("id"))
	if err != nil || s.UserID != c.user.ID {
		return &apiError{http.StatusNotFound, map[string]string{"errorMessage": "Session not found"}}
	}
	if err := h.Svc.Store.DeleteSession(r.Context(), s); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// credentialType describes a credential type in the account API.
type credentialType struct {
	Type, Category, DisplayName, HelpText, IconCSSClass, CreateAction, UpdateAction string
	Removeable                                                                      bool
}

var credentialTypes = []credentialType{
	{"password", "basic-authentication", "password-display-name", "password-help-text", "kcAuthenticatorPasswordClass", "", "UPDATE_PASSWORD", false},
	{"otp", "two-factor", "otp-display-name", "otp-help-text", "kcAuthenticatorOTPClass", "CONFIGURE_TOTP", "", true},
	{"webauthn", "two-factor", "webauthn-display-name", "webauthn-help-text", "kcAuthenticatorWebAuthnClass", "webauthn-register", "", true},
	{"webauthn-passwordless", "passwordless", "webauthn-passwordless-display-name", "webauthn-passwordless-help-text", "kcAuthenticatorWebAuthnPasswordlessClass", "webauthn-register-passwordless", "", true},
}

func (h *Handler) apiCredentials(w http.ResponseWriter, r *http.Request, c *caller) error {
	creds, err := h.Svc.Store.ListCredentials(r.Context(), c.user.ID)
	if err != nil {
		return err
	}
	type credRep struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		UserLabel   string `json:"userLabel,omitempty"`
		CreatedDate int64  `json:"createdDate"`
	}
	type metadata struct {
		Credential credRep `json:"credential"`
	}
	type typeRep struct {
		Type                    string     `json:"type"`
		Category                string     `json:"category"`
		DisplayName             string     `json:"displayName"`
		HelpText                string     `json:"helptext"`
		IconCSSClass            string     `json:"iconCssClass"`
		CreateAction            string     `json:"createAction,omitempty"`
		UpdateAction            string     `json:"updateAction,omitempty"`
		Removeable              bool       `json:"removeable"`
		UserCredentialMetadatas []metadata `json:"userCredentialMetadatas"`
	}
	filter := r.URL.Query().Get("type")
	out := []typeRep{}
	for _, t := range credentialTypes {
		if filter != "" && filter != t.Type {
			continue
		}
		tr := typeRep{Type: t.Type, Category: t.Category, DisplayName: t.DisplayName, HelpText: t.HelpText, IconCSSClass: t.IconCSSClass,
			CreateAction: t.CreateAction, UpdateAction: t.UpdateAction, Removeable: t.Removeable, UserCredentialMetadatas: []metadata{}}
		for _, cr := range creds {
			if cr.Type == t.Type {
				tr.UserCredentialMetadatas = append(tr.UserCredentialMetadatas, metadata{credRep{cr.ID, cr.Type, cr.UserLabel, cr.CreatedDate}})
			}
		}
		out = append(out, tr)
	}
	return writeJSON(w, http.StatusOK, out)
}

// removeCredential deletes a removable credential of the user.
func (h *Handler) removeCredential(ctx context.Context, c *caller, id string) error {
	creds, err := h.Svc.Store.ListCredentials(ctx, c.user.ID)
	if err != nil {
		return err
	}
	for _, cr := range creds {
		if cr.ID != id {
			continue
		}
		if cr.Type == model.CredentialPassword || cr.Type == service.CredentialPasswordHistory {
			return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "Password credentials cannot be removed"}}
		}
		if err := h.Svc.Store.DeleteCredential(ctx, c.user.ID, id); err != nil {
			return err
		}
		h.Svc.RecordEvent(ctx, c.realm, &model.Event{Type: "REMOVE_CREDENTIAL", UserID: c.user.ID, ClientID: service.AccountClient,
			Details: map[string]string{"credential_type": cr.Type, "credential_id": cr.ID}})
		return nil
	}
	return &apiError{http.StatusNotFound, map[string]string{"errorMessage": "Credential not found"}}
}

func (h *Handler) apiDeleteCredential(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := h.removeCredential(r.Context(), c, r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) apiCredentialLabel(w http.ResponseWriter, r *http.Request, c *caller) error {
	var label string
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4096)).Decode(&label); err != nil {
		return &apiError{http.StatusBadRequest, map[string]string{"errorMessage": "Invalid label"}}
	}
	if err := h.Svc.Store.UpdateCredentialLabel(r.Context(), c.user.ID, r.PathValue("id"), strings.TrimSpace(label)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &apiError{http.StatusNotFound, nil}
		}
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// applicationRep is Keycloak's account ClientRepresentation.
type applicationRep struct {
	ClientID            string `json:"clientId"`
	ClientName          string `json:"clientName"`
	Description         string `json:"description,omitempty"`
	UserConsentRequired bool   `json:"userConsentRequired"`
	InUse               bool   `json:"inUse"`
	OfflineAccess       bool   `json:"offlineAccess"`
	RootURL             string `json:"rootUrl,omitempty"`
	BaseURL             string `json:"baseUrl,omitempty"`
	EffectiveURL        string `json:"effectiveUrl,omitempty"`
}

// applications lists the clients the user is logged in to or has offline
// tokens for.
func (h *Handler) applications(ctx context.Context, c *caller, base string) ([]applicationRep, error) {
	inUse, offline := map[string]bool{}, map[string]bool{}
	sessions, err := h.Svc.Store.ListUserSessions(ctx, c.user.ID)
	if err != nil {
		return nil, err
	}
	for _, s := range sessions {
		for cid := range s.Clients {
			inUse[cid] = true
		}
	}
	offs, err := h.Svc.Store.ListOfflineSessions(ctx, c.user.ID)
	if err != nil {
		return nil, err
	}
	for _, s := range offs {
		for cid := range s.Clients {
			offline[cid] = true
		}
	}
	out := []applicationRep{}
	seen := map[string]bool{}
	for _, m := range []map[string]bool{inUse, offline} {
		for cid := range m {
			if seen[cid] {
				continue
			}
			seen[cid] = true
			cl, err := h.Svc.Store.GetClient(ctx, c.realm.ID, cid)
			if err != nil {
				continue
			}
			name := cl.Name
			if name == "" || strings.HasPrefix(name, "${") {
				name = cl.ClientID
			}
			out = append(out, applicationRep{ClientID: cl.ClientID, ClientName: name, Description: cl.Description,
				InUse: inUse[cid], OfflineAccess: offline[cid], RootURL: cl.RootURL, BaseURL: cl.BaseURL, EffectiveURL: clientURL(base, cl)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

func (h *Handler) apiApplications(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.applications(r.Context(), c, h.URLs.Base(r))
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, list)
}

// revokeOffline removes a client's offline tokens of the user.
func (h *Handler) revokeOffline(ctx context.Context, c *caller, clientID string) error {
	cl, err := h.Svc.Store.GetClientByClientID(ctx, c.realm.ID, clientID)
	if err != nil {
		return &apiError{http.StatusNotFound, map[string]string{"errorMessage": "Client not found"}}
	}
	offs, err := h.Svc.Store.ListOfflineSessions(ctx, c.user.ID)
	if err != nil {
		return err
	}
	for _, s := range offs {
		if !s.Clients[cl.ID] {
			continue
		}
		delete(s.Clients, cl.ID)
		if len(s.Clients) == 0 {
			err = h.Svc.Store.DeleteSession(ctx, s)
		} else {
			err = h.Svc.Store.UpdateUserSession(ctx, s)
		}
		if err != nil {
			return err
		}
	}
	h.Svc.RecordEvent(ctx, c.realm, &model.Event{Type: "REVOKE_GRANT", UserID: c.user.ID, ClientID: service.AccountClient,
		Details: map[string]string{"revoked_client": clientID}})
	return nil
}

func (h *Handler) apiRevokeConsent(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := h.revokeOffline(r.Context(), c, r.PathValue("clientId")); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) groups(ctx context.Context, c *caller) ([]map[string]string, error) {
	groups, err := h.Svc.Store.UserGroups(ctx, c.user.ID)
	if err != nil {
		return nil, err
	}
	all, err := h.Svc.Store.ListAllGroups(ctx, c.realm.ID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.Group{}
	for _, g := range all {
		byID[g.ID] = g
	}
	out := []map[string]string{}
	for _, g := range groups {
		path := ""
		for cur, d := g, 0; cur != nil && d < 100; cur, d = byID[cur.ParentID], d+1 {
			path = "/" + cur.Name + path
		}
		out = append(out, map[string]string{"id": g.ID, "name": g.Name, "path": path})
	}
	return out, nil
}

func (h *Handler) apiGroups(w http.ResponseWriter, r *http.Request, c *caller) error {
	if !c.can("view-groups") {
		return &apiError{http.StatusForbidden, nil}
	}
	list, err := h.groups(r.Context(), c)
	if err != nil {
		return err
	}
	return writeJSON(w, http.StatusOK, list)
}

// loginURL starts a login (optionally an application initiated action) of
// the account client that returns to the account console page.
func (h *Handler) loginURL(r *http.Request, realm *model.Realm, page, action string) string {
	iss := h.URLs.Issuer(r, realm.Name)
	q := url.Values{"client_id": {service.AccountClient}, "redirect_uri": {iss + "/account/" + strings.TrimPrefix(page, "/")},
		"response_type": {"code"}, "scope": {"openid"}}
	if action != "" {
		q.Set("kc_action", action)
	}
	return iss + "/protocol/openid-connect/auth?" + q.Encode()
}
