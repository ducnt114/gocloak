package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
	"github.com/ducnt114/gocloak/internal/userprofile"
)

func (h *Handler) getUserProfile(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, realm)
	if err != nil {
		return err
	}
	return ok(w, cfg)
}

func (h *Handler) putUserProfile(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 1<<20))
	if err != nil {
		return badRequest("Invalid body")
	}
	cfg, err := userprofile.Parse(body)
	if err != nil {
		return badRequest(err.Error())
	}
	if err := h.Svc.SetUserProfile(r.Context(), h.Svc.Store, realm, cfg); err != nil {
		return err
	}
	return ok(w, cfg)
}

// attributeMetadata is an entry of the user profile metadata.
type attributeMetadata struct {
	Name        string                    `json:"name"`
	DisplayName string                    `json:"displayName,omitempty"`
	Required    bool                      `json:"required"`
	ReadOnly    bool                      `json:"readOnly"`
	Annotations map[string]any            `json:"annotations,omitempty"`
	Validators  map[string]map[string]any `json:"validators,omitempty"`
	Group       string                    `json:"group,omitempty"`
	Multivalued bool                      `json:"multivalued"`
}

type profileMetadata struct {
	Attributes []attributeMetadata `json:"attributes"`
	Groups     []userprofile.Group `json:"groups"`
}

func metadataFor(cfg *userprofile.Config, context string) profileMetadata {
	md := profileMetadata{Attributes: []attributeMetadata{}, Groups: cfg.Groups}
	if md.Groups == nil {
		md.Groups = []userprofile.Group{}
	}
	for _, a := range cfg.Attributes {
		if !cfg.CanView(a.Name, context) {
			continue
		}
		required := a.Name == "username" || (a.Required != nil && (len(a.Required.Roles) == 0 || slices.Contains(a.Required.Roles, context)))
		md.Attributes = append(md.Attributes, attributeMetadata{Name: a.Name, DisplayName: a.DisplayName, Required: required,
			ReadOnly: !cfg.CanEdit(a.Name, context), Annotations: a.Annotations, Validators: a.Validations, Group: a.Group,
			Multivalued: a.Multivalued})
	}
	return md
}

func (h *Handler) getUserProfileMetadata(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, realm)
	if err != nil {
		return err
	}
	return ok(w, metadataFor(cfg, userprofile.ContextAdmin))
}

// profileErrors renders validation errors as Keycloak does: one error as
// an object, several as {"errors": [...]}.
type profileErrors struct{ errs userprofile.Errors }

func (e *profileErrors) Error() string { return e.errs.Error() }

func writeProfileErrors(w http.ResponseWriter, errs userprofile.Errors) {
	if len(errs) == 1 {
		writeJSON(w, http.StatusBadRequest, errs[0])
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]any{"errors": errs})
}

// applyProfilePolicy validates a user written through the admin API and
// drops the attributes the admin context may not write. prev is the stored
// user for updates (nil on create).
func (h *Handler) applyProfilePolicy(r *http.Request, realm *model.Realm, u *model.User, prev *model.User) error {
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, realm)
	if err != nil {
		return err
	}
	attrs := map[string][]string{}
	for k, v := range u.Attributes {
		if cfg.CanEdit(k, userprofile.ContextAdmin) {
			attrs[k] = v
		} else if prev != nil && prev.Attributes[k] != nil {
			attrs[k] = prev.Attributes[k] // keep what the admin may not change
		}
	}
	if prev != nil {
		for k, v := range prev.Attributes {
			if _, ok := attrs[k]; !ok && !cfg.CanEdit(k, userprofile.ContextAdmin) {
				attrs[k] = v
			}
		}
	}
	u.Attributes = attrs
	values := service.ProfileValues(u)
	values["username"] = []string{strings.ToLower(u.Username)}
	if errs := cfg.Validate(values, userprofile.ContextAdmin, nil); len(errs) > 0 {
		return &profileErrors{errs}
	}
	return nil
}

// visibleAttributes hides the attributes the admin context may not view.
func (h *Handler) visibleAttributes(r *http.Request, realm *model.Realm, reps []UserRep) error {
	cfg, err := h.Svc.UserProfile(r.Context(), h.Svc.Store, realm)
	if err != nil {
		return err
	}
	for i := range reps {
		for k := range reps[i].Attributes {
			if !cfg.CanView(k, userprofile.ContextAdmin) {
				delete(reps[i].Attributes, k)
			}
		}
		if len(reps[i].Attributes) == 0 {
			reps[i].Attributes = nil
		}
	}
	return nil
}

// ---------------------------------------------------------------- emails

// actionEmailTarget resolves the client and redirect of an emailed action.
func (h *Handler) actionEmailTarget(r *http.Request, realm *model.Realm) (*model.Client, string, error) {
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		clientID = service.AccountClient
	}
	c, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, clientID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", badRequest("Client doesn't exist")
	}
	if err != nil {
		return nil, "", err
	}
	if !c.Enabled {
		return nil, "", badRequest("Client is not enabled")
	}
	redirect := r.URL.Query().Get("redirect_uri")
	if redirect != "" && !oidc.RedirectAllowed(h.URLs.Base(r), c, redirect) {
		return nil, "", badRequest("Invalid redirect uri.")
	}
	return c, redirect, nil
}

func (h *Handler) executeActionsEmail(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	var actions []string
	if err := decode(r, &actions); err != nil {
		return err
	}
	return h.sendActionEmail(w, r, realm, u, "execute-actions", actions)
}

func (h *Handler) sendVerifyEmail(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	return h.sendActionEmail(w, r, realm, u, "verify-email", nil)
}

func (h *Handler) sendActionEmail(w http.ResponseWriter, r *http.Request, realm *model.Realm, u *model.User, typ string, actions []string) error {
	if u.Email == "" {
		return badRequest("User email missing")
	}
	if !u.Enabled {
		return badRequest("User is disabled")
	}
	c, redirect, err := h.actionEmailTarget(r, realm)
	if err != nil {
		return err
	}
	lifespan := realm.Settings.ActionTokenGeneratedByAdmin
	if l := intParam(r, "lifespan", 0); l > 0 {
		lifespan = l
	}
	link, err := oidc.ActionTokenLink(r.Context(), h.Svc, h.URLs.Issuer(r, realm.Name), realm, c.ClientID, u, typ, actions, redirect, lifespan)
	if err != nil {
		return err
	}
	kind := service.EmailVerification
	if typ == "execute-actions" {
		kind = service.ExecuteActions
	}
	msg, err := h.Svc.EmailMessage(realm, u, kind, link, lifespan, actions)
	if err != nil {
		return err
	}
	if err := h.Svc.SendEmail(r.Context(), realm, msg); err != nil {
		h.Log.Warn("send email", "realm", realm.Name, "type", typ, "err", err)
		return errStatus(http.StatusInternalServerError, "Failed to send %s email", typ)
	}
	return noContent(w)
}

func (h *Handler) testSMTPConnection(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	var cfg map[string]string
	if err := decode(r, &cfg); err != nil {
		return err
	}
	if p.user.Email == "" {
		return errStatus(http.StatusInternalServerError, "Logged in user does not have an e-mail.")
	}
	// A masked password means "the one already configured".
	if cfg["password"] == "**********" {
		cfg["password"] = realm.Settings.SMTPServer["password"]
	}
	msg, err := h.Svc.EmailMessage(realm, p.user, service.EmailTest, "", 0, nil)
	if err != nil {
		return err
	}
	if err := service.SendWith(r.Context(), cfg, msg); err != nil {
		h.Log.Warn("SMTP test", "realm", realm.Name, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"errorMessage": "Failed to send email"})
		return nil
	}
	return noContent(w)
}

// ---------------------------------------------------------------- credentials

func (h *Handler) setCredentialLabel(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 4096))
	if err != nil {
		return badRequest("Invalid body")
	}
	label := strings.TrimSpace(string(b))
	var quoted string
	if json.Unmarshal(b, &quoted) == nil {
		label = quoted
	}
	if err := h.Svc.Store.UpdateCredentialLabel(r.Context(), u.ID, r.PathValue("credId"), label); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("Credential")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) storageCredentialTypes(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permViewUsers); err != nil {
		return err
	}
	return ok(w, []string{})
}
