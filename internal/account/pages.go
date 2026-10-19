package account

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/theme"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

type pageFunc func(w http.ResponseWriter, r *http.Request, c *caller) error

// page serves an account console page to the browser's SSO session,
// sending users without one to the login of the account client.
func (h *Handler) page(fn pageFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm, err := h.realm(r)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Has("code") || q.Has("error") {
			// back from the login: the SSO cookie is set, drop the OAuth parameters
			if q.Has("error") && strings.HasSuffix(r.URL.Path, "/linked-accounts") {
				q.Set("linkError", q.Get("error")) // back from linking an account
			}
			for _, k := range []string{"code", "state", "session_state", "iss", "error", "error_description"} {
				q.Del(k)
			}
			u := *r.URL
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
		us, user := h.OIDC.SSOSession(r, realm)
		if us == nil {
			page := strings.TrimPrefix(r.URL.Path, "/realms/"+realm.Name+"/account")
			if r.Method != http.MethodGet {
				page = ""
			}
			http.Redirect(w, r, h.loginURL(r, realm, page, ""), http.StatusFound)
			return
		}
		roles, err := h.accountRoles(r.Context(), realm, user)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		c := &caller{realm: realm, user: user, session: us, roles: roles}
		if !c.can("view-profile") {
			h.render(w, r, c, http.StatusForbidden, "error", accountPage{Error: "forbiddenMessage"})
			return
		}
		if r.Method == http.MethodPost {
			if !c.can("manage-account") {
				h.render(w, r, c, http.StatusForbidden, "error", accountPage{Error: "forbiddenMessage"})
				return
			}
			if r.PostFormValue("stateChecker") == "" || r.PostFormValue("stateChecker") != oidc.StateChecker(r) {
				h.render(w, r, c, http.StatusBadRequest, "error", accountPage{Error: "invalidStateMessage"})
				return
			}
		}
		if err := fn(w, r, c); err != nil {
			var ae *apiError
			if errors.As(err, &ae) {
				h.render(w, r, c, ae.status, "error", accountPage{Error: "errorTitle"})
				return
			}
			h.fail(w, r, err)
		}
	}
}

func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("account console", "path", r.URL.Path, "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

// accountPage is the model of account console pages.
type accountPage struct {
	Realm, Section, Title string
	Error, Message        string
	ErrorArgs             []any
	User                  *model.User
	Profile               []field
	Sessions              []sessionRep
	Credentials           []credentialGroup
	Applications          []applicationRep
	Groups                []map[string]string
	LinkedAccounts        []linkedAccountRep
	ShowGroups            bool

	StateChecker, BaseURL, LogoutURL string
	Locale                           string
	Styles                           []string
	th                               *theme.Theme
}

type field struct {
	Name, Label, Type, Value, Error string
	ErrorArgs                       []any
	Required, ReadOnly              bool
}

type credentialGroup struct {
	Type, DisplayName, HelpText, SetupURL, UpdateURL string
	Removeable                                       bool
	Items                                            []*model.Credential
}

// T translates a message key.
func (p accountPage) T(key string, args ...any) string { return p.th.Message(p.Locale, key, args...) }

func (p accountPage) ErrorText() string        { return p.T(p.Error, p.ErrorArgs...) }
func (p accountPage) FieldText(f field) string { return p.T(f.Error, f.ErrorArgs...) }
func (p accountPage) Date(unix int64) string   { return time.Unix(unix, 0).Format("2006-01-02 15:04") }
func (p accountPage) DateMillis(ms int64) string {
	return time.UnixMilli(ms).Format("2006-01-02 15:04")
}
func (p accountPage) Active(section string) string {
	return map[bool]string{true: "active"}[p.Section == section]
}

// Removable reports whether a credential may be removed by the user.
func (p accountPage) Removable(c *model.Credential) bool {
	return c.Type != model.CredentialPassword && c.Type != service.CredentialPasswordHistory
}

func (h *Handler) render(w http.ResponseWriter, r *http.Request, c *caller, status int, page string, p accountPage) {
	th, err := h.Themes.Get(theme.Account, c.realm.Settings.AccountTheme)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	p.th = th
	p.Realm = c.realm.DisplayName
	if p.Realm == "" {
		p.Realm = c.realm.Name
	}
	p.User = c.user
	p.Locale = h.OIDC.Locale(w, r, c.realm, c.user)
	p.StateChecker = oidc.StateChecker(r)
	p.ShowGroups = c.can("view-groups")
	iss := h.URLs.Issuer(r, c.realm.Name)
	p.BaseURL = iss + "/account"
	p.LogoutURL = iss + "/protocol/openid-connect/logout?" + url.Values{"client_id": {service.AccountClient},
		"post_logout_redirect_uri": {iss + "/account/"}}.Encode()
	res := h.URLs.Base(r) + "/resources/" + url.PathEscape(th.Name) + "/account/"
	for _, s := range th.Styles {
		p.Styles = append(p.Styles, res+s)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'; object-src 'none';")
	w.WriteHeader(status)
	if err := th.Execute(w, page+".html", p); err != nil {
		h.Log.Error("render account page", "page", page, "err", err)
	}
}

// ---------------------------------------------------------------- personal info

func (h *Handler) profileFields(r *http.Request, c *caller, values map[string][]string, errs userprofile.Errors) ([]field, error) {
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, c.realm)
	if err != nil {
		return nil, err
	}
	errBy := map[string]userprofile.FieldError{}
	for _, e := range errs {
		if _, ok := errBy[e.Field]; !ok {
			errBy[e.Field] = e
		}
	}
	var out []field
	for _, a := range cfg.Attributes {
		if !cfg.CanView(a.Name, userprofile.ContextUser) {
			continue
		}
		label := a.DisplayName
		switch {
		case userprofile.IsCore(a.Name):
			label = a.Name
		case strings.HasPrefix(label, "${") && strings.HasSuffix(label, "}"):
			label = label[2 : len(label)-1]
		case label == "":
			label = a.Name
		}
		val := ""
		if v := values[a.Name]; len(v) > 0 {
			val = v[0]
		}
		typ := "text"
		if a.Name == "email" {
			typ = "email"
		}
		e := errBy[a.Name]
		out = append(out, field{Name: a.Name, Label: label, Type: typ, Value: val, Error: e.ErrorMessage, ErrorArgs: e.Params,
			Required: a.Required != nil, ReadOnly: !cfg.CanEdit(a.Name, userprofile.ContextUser) ||
				(a.Name == "username" && !c.realm.Settings.EditUsernameAllowed)})
	}
	return out, nil
}

func (h *Handler) personalInfo(w http.ResponseWriter, r *http.Request, c *caller) error {
	fields, err := h.profileFields(r, c, service.ProfileValues(c.user), nil)
	if err != nil {
		return err
	}
	msg := ""
	if r.URL.Query().Get("saved") == "true" {
		msg = "accountUpdatedMessage"
	}
	h.render(w, r, c, http.StatusOK, "personal-info", accountPage{Section: "personal-info", Title: "personalInfo", Profile: fields, Message: msg})
	return nil
}

func (h *Handler) savePersonalInfo(w http.ResponseWriter, r *http.Request, c *caller) error {
	r.ParseForm()
	values := map[string][]string{}
	for _, k := range []string{"username", "email", "firstName", "lastName"} {
		if v, ok := r.PostForm[k]; ok {
			values[k] = []string{strings.TrimSpace(v[0])}
		}
	}
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, c.realm)
	if err != nil {
		return err
	}
	for _, a := range cfg.Attributes {
		if v, ok := r.PostForm[a.Name]; ok && !userprofile.IsCore(a.Name) {
			values[a.Name] = []string{strings.TrimSpace(v[0])}
		}
	}
	errs, err := h.updateProfile(r.Context(), c.realm, c.user, values)
	if err != nil {
		return err
	}
	if len(errs) > 0 {
		shown := service.ProfileValues(c.user)
		for k, v := range values {
			shown[k] = v
		}
		fields, err := h.profileFields(r, c, shown, errs)
		if err != nil {
			return err
		}
		h.render(w, r, c, http.StatusBadRequest, "personal-info", accountPage{Section: "personal-info", Title: "personalInfo", Profile: fields})
		return nil
	}
	http.Redirect(w, r, h.URLs.Issuer(r, c.realm.Name)+"/account/?saved=true", http.StatusSeeOther)
	return nil
}

// ---------------------------------------------------------------- security

func (h *Handler) security(w http.ResponseWriter, r *http.Request, c *caller) error {
	creds, err := h.Svc.Store.ListCredentials(r.Context(), c.user.ID)
	if err != nil {
		return err
	}
	var groups []credentialGroup
	for _, t := range credentialTypes {
		g := credentialGroup{Type: t.Type, DisplayName: t.DisplayName, HelpText: t.HelpText, Removeable: t.Removeable}
		if t.CreateAction != "" {
			g.SetupURL = h.loginURL(r, c.realm, "security", t.CreateAction)
		}
		if t.UpdateAction != "" {
			g.UpdateURL = h.loginURL(r, c.realm, "security", t.UpdateAction)
		}
		for _, cr := range creds {
			if cr.Type == t.Type {
				g.Items = append(g.Items, cr)
			}
		}
		groups = append(groups, g)
	}
	h.render(w, r, c, http.StatusOK, "security", accountPage{Section: "security", Title: "accountSecurity", Credentials: groups,
		Message: map[bool]string{true: "credentialRemovedMessage"}[r.URL.Query().Get("removed") == "true"]})
	return nil
}

func (h *Handler) deleteCredentialPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := h.removeCredential(r.Context(), c, r.PathValue("id")); err != nil {
		return err
	}
	http.Redirect(w, r, h.URLs.Issuer(r, c.realm.Name)+"/account/security?removed=true", http.StatusSeeOther)
	return nil
}

// ---------------------------------------------------------------- sessions

func (h *Handler) deviceActivity(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.sessions(r.Context(), c, h.URLs.Base(r))
	if err != nil {
		return err
	}
	h.render(w, r, c, http.StatusOK, "device-activity", accountPage{Section: "device-activity", Title: "deviceActivity", Sessions: list})
	return nil
}

func (h *Handler) signOutPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	ctx := r.Context()
	switch id := r.PostFormValue("session"); id {
	case "":
		if err := h.signOut(r, c, false); err != nil {
			return err
		}
	default:
		s, err := h.Svc.Store.GetUserSession(ctx, id)
		if err != nil || s.UserID != c.user.ID {
			return &apiError{http.StatusNotFound, nil}
		}
		h.Svc.BackchannelLogout(ctx, h.URLs.Base(r), c.realm, s)
		if err := h.Svc.Store.DeleteSession(ctx, s); err != nil {
			return err
		}
		if s.ID == c.session.ID {
			http.Redirect(w, r, h.URLs.Issuer(r, c.realm.Name)+"/account/", http.StatusSeeOther)
			return nil
		}
	}
	http.Redirect(w, r, h.URLs.Issuer(r, c.realm.Name)+"/account/device-activity", http.StatusSeeOther)
	return nil
}

// ---------------------------------------------------------------- applications and groups

func (h *Handler) applicationsPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	list, err := h.applications(r.Context(), c, h.URLs.Base(r))
	if err != nil {
		return err
	}
	h.render(w, r, c, http.StatusOK, "applications", accountPage{Section: "applications", Title: "applications", Applications: list})
	return nil
}

func (h *Handler) revokeApplicationPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	if err := h.revokeOffline(r.Context(), c, r.PathValue("clientId")); err != nil {
		return err
	}
	http.Redirect(w, r, h.URLs.Issuer(r, c.realm.Name)+"/account/applications", http.StatusSeeOther)
	return nil
}

func (h *Handler) groupsPage(w http.ResponseWriter, r *http.Request, c *caller) error {
	if !c.can("view-groups") {
		return &apiError{http.StatusForbidden, nil}
	}
	list, err := h.groups(r.Context(), c)
	if err != nil {
		return err
	}
	h.render(w, r, c, http.StatusOK, "groups", accountPage{Section: "groups", Title: "groups", Groups: list})
	return nil
}
