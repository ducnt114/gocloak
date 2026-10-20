package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ducnt114/gocloak/internal/federation"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// User federation (LDAP): provider and mapper components, synchronization
// and the connection test.

// maskedComponentConfig are config keys shown as "**********".
var maskedComponentConfig = map[string]bool{"bindCredential": true}

// prepareFederationComponent validates an LDAP provider or mapper before it
// is saved; previous is the stored component on updates.
func (h *Handler) prepareFederationComponent(ctx context.Context, realm *model.Realm, c *model.Component, previous *model.Component) error {
	switch c.ProviderType {
	case federation.ProviderType:
		if c.ProviderID != federation.ProviderLDAP {
			return badRequestPlain("Invalid provider type or no such provider")
		}
		if previous != nil {
			for k := range maskedComponentConfig {
				if c.Get(k) == maskedSecret {
					c.Config[k] = previous.Config[k]
				}
			}
		}
		if msg := federation.ValidateConfig(c); msg != "" {
			return badRequest(msg)
		}
		if previous == nil {
			federation.PrepareProvider(c)
		}
	case federation.MapperType:
		if !federation.MapperProviders[c.ProviderID] {
			return badRequestPlain("Invalid provider type or no such provider")
		}
		parent, err := h.Svc.Store.GetComponent(ctx, realm.ID, c.ParentID)
		if err != nil || parent.ProviderType != federation.ProviderType {
			return badRequest("LDAP mapper must belong to an LDAP provider")
		}
		if msg, plain := federation.ValidateMapper(ctx, h.Svc.Store, realm, c); msg != "" {
			if plain {
				return badRequestPlain(msg)
			}
			return badRequest(msg)
		}
	}
	return nil
}

// createFederationComponent saves a new LDAP provider with Keycloak's
// default mappers.
func (h *Handler) createFederationComponent(ctx context.Context, c *model.Component) error {
	return h.withTx(ctx, func(tx *store.Store) error {
		if err := tx.CreateComponent(ctx, c); err != nil {
			return err
		}
		if c.ProviderType != federation.ProviderType {
			return nil
		}
		for _, m := range federation.DefaultMappers(c) {
			m.ID, m.RealmID = service.NewID(), c.RealmID
			if err := tx.CreateComponent(ctx, m); err != nil {
				return err
			}
		}
		return nil
	})
}

// deleteFederationComponent removes an LDAP provider with its mappers and
// the users imported from it, as Keycloak does.
func (h *Handler) deleteFederationComponent(ctx context.Context, realm *model.Realm, c *model.Component) error {
	if err := h.Fed.RemoveImportedUsers(ctx, realm, c); err != nil {
		return err
	}
	return h.Svc.Store.DeleteComponentTree(ctx, realm.ID, c.ID)
}

func (h *Handler) loadStorageProvider(r *http.Request, realm *model.Realm, id string) (*model.Component, error) {
	c, err := h.Svc.Store.GetComponent(r.Context(), realm.ID, id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.ProviderType != federation.ProviderType) {
		return nil, notFound("Could not find component")
	}
	return c, err
}

// syncUsers implements POST /user-storage/{id}/sync?action=triggerFullSync|triggerChangedUsersSync.
func (h *Handler) syncUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	c, err := h.loadStorageProvider(r, realm, r.PathValue("id"))
	if err != nil {
		return err
	}
	var changed bool
	switch r.URL.Query().Get("action") {
	case "triggerFullSync":
	case "triggerChangedUsersSync":
		changed = true
	default:
		return notFound("Unknown action: " + r.URL.Query().Get("action"))
	}
	res, err := h.Fed.SyncUsers(r.Context(), realm, c, changed)
	if err != nil {
		h.Log.Warn("ldap sync", "realm", realm.Name, "provider", c.Name, "err", err)
		return badRequest(ldapErrorKey(err))
	}
	return ok(w, res)
}

// ldapErrorKey maps a directory error to Keycloak's error keys.
func ldapErrorKey(err error) string {
	msg := err.Error()
	for _, k := range []string{"connection refused", "no such host", "i/o timeout", "network is unreachable", "connection reset"} {
		if strings.Contains(msg, k) {
			return "SocketReset"
		}
	}
	if strings.Contains(msg, "Invalid Credentials") {
		return "AuthenticationFailure"
	}
	return msg
}

func (h *Handler) removeImportedUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	c, err := h.loadStorageProvider(r, realm, r.PathValue("id"))
	if err != nil {
		return err
	}
	if err := h.Fed.RemoveImportedUsers(r.Context(), realm, c); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) unlinkUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	c, err := h.loadStorageProvider(r, realm, r.PathValue("id"))
	if err != nil {
		return err
	}
	if err := h.Fed.UnlinkUsers(r.Context(), realm, c); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) storageProviderName(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	c, err := h.loadStorageProvider(r, realm, r.PathValue("id"))
	if err != nil {
		return err
	}
	return ok(w, map[string]string{"id": c.ID, "name": c.Name})
}

// syncMapper implements POST /user-storage/{parentId}/mappers/{id}/sync?direction=.
func (h *Handler) syncMapper(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	parent, err := h.loadStorageProvider(r, realm, r.PathValue("parentId"))
	if err != nil {
		return err
	}
	m, err := h.Svc.Store.GetComponent(r.Context(), realm.ID, r.PathValue("id"))
	if err != nil || m.ParentID != parent.ID {
		return notFound("Could not find mapper")
	}
	direction := r.URL.Query().Get("direction")
	if direction != "fedToGocloak" && direction != "gocloakToFed" {
		return badRequest("Unknown direction: " + direction)
	}
	res, err := h.Fed.SyncMapper(r.Context(), realm, parent, m, direction)
	if err != nil {
		return badRequest(ldapErrorKey(err))
	}
	return ok(w, res)
}

// testLDAPConnection implements POST /testLDAPConnection.
func (h *Handler) testLDAPConnection(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	var req map[string]string
	if r.Header.Get("Content-Type") == "application/json" || r.Header.Get("Content-Type") == "" {
		if err := decode(r, &req); err != nil {
			return err
		}
	} else {
		r.ParseForm()
		req = map[string]string{}
		for k := range r.Form {
			req[k] = r.Form.Get(k)
		}
	}
	c := &model.Component{Config: map[string][]string{}}
	for _, k := range []string{"connectionUrl", "bindDn", "bindCredential", "authType", "startTls", "connectionTimeout"} {
		if v := req[k]; v != "" {
			c.Set(k, v)
		}
	}
	if req["bindCredential"] == maskedSecret && req["componentId"] != "" {
		stored, err := h.Svc.Store.GetComponent(r.Context(), realm.ID, req["componentId"])
		if err != nil {
			return badRequest("Could not find component")
		}
		c.Set("bindCredential", stored.Get("bindCredential"))
	}
	var authenticate bool
	switch req["action"] {
	case "testConnection":
	case "testAuthentication":
		authenticate = true
	default:
		return badRequest("unknown action")
	}
	if err := federation.TestConnection(federation.ParseConfig(c), authenticate); err != nil {
		return badRequest(err.Error())
	}
	return noContent(w)
}

func (h *Handler) registerFederationRoutes(R string, add func(string, handlerFunc)) {
	add("POST "+R+"/user-storage/{id}/sync", h.syncUsers)
	add("POST "+R+"/user-storage/{id}/remove-imported-users", h.removeImportedUsers)
	add("POST "+R+"/user-storage/{id}/unlink-users", h.unlinkUsers)
	add("GET "+R+"/user-storage/{id}/name", h.storageProviderName)
	add("POST "+R+"/user-storage/{parentId}/mappers/{id}/sync", h.syncMapper)
	add("POST "+R+"/testLDAPConnection", h.testLDAPConnection)
}
