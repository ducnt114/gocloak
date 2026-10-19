package admin

import (
	"errors"
	"net/http"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

func (h *Handler) loadClient(r *http.Request, realm *model.Realm) (*model.Client, error) {
	c, err := h.Svc.Store.GetClient(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find client")
	}
	return c, err
}

func (h *Handler) clientRep(p *principal, realm *model.Realm, c *model.Client) ClientRep {
	rep := clientToRep(c)
	if !c.PublicClient && !c.BearerOnly && p.can(realm, permManageClients) {
		rep.Secret = ptr(c.Secret)
	}
	return rep
}

func (h *Handler) listClients(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryClients)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	var clients []*model.Client
	if cid := q.Get("clientId"); cid != "" && q.Get("search") != "true" {
		c, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, cid)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if c != nil {
			clients = append(clients, c)
		}
	} else {
		clients, err = h.Svc.Store.ListClients(r.Context(), realm.ID, cid, intParam(r, "first", 0), intParam(r, "max", 100))
		if err != nil {
			return err
		}
	}
	out := []ClientRep{}
	for _, c := range clients {
		out = append(out, h.clientRep(p, realm, c))
	}
	return ok(w, out)
}

func (h *Handler) createClient(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permCreateClient)
	if err != nil {
		return err
	}
	var rep ClientRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.ClientID == nil || *rep.ClientID == "" {
		return badRequest("clientId is required")
	}
	c := newClient(realm.ID)
	if rep.ID != nil {
		c.ID = *rep.ID
	}
	applyClientRep(c, &rep)
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		return h.Svc.CreateClient(r.Context(), tx, c)
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("Client " + c.ClientID + " already exists")
	}
	if err != nil {
		return err
	}
	return created(w, r, c.ID)
}

func (h *Handler) getClient(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	return ok(w, h.clientRep(p, realm, c))
}

func (h *Handler) updateClient(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	var rep ClientRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if c.ClientID == service.RealmManagementClient && rep.ClientID != nil && *rep.ClientID != c.ClientID {
		return badRequest("The realm-management client cannot be renamed")
	}
	applyClientRep(c, &rep)
	if !c.PublicClient && !c.BearerOnly && c.Secret == "" {
		c.Secret = service.RandomToken(24)
	}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := tx.UpdateClient(r.Context(), c); err != nil {
			return err
		}
		return h.Svc.SyncServiceAccount(r.Context(), tx, c)
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("Client " + c.ClientID + " already exists")
	}
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteClient(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	if c.ClientID == service.RealmManagementClient {
		return badRequest("The realm-management client cannot be deleted")
	}
	if err := h.Svc.Store.DeleteClient(r.Context(), c.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) getClientSecret(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	if !p.can(realm, permManageClients) {
		return forbidden()
	}
	return ok(w, map[string]string{"type": "secret", "value": c.Secret})
}

func (h *Handler) regenerateClientSecret(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	if c.PublicClient || c.BearerOnly {
		return badRequest("Client is not confidential")
	}
	c.Secret = service.RandomToken(24)
	if err := h.Svc.Store.UpdateClient(r.Context(), c); err != nil {
		return err
	}
	return ok(w, map[string]string{"type": "secret", "value": c.Secret})
}

func (h *Handler) serviceAccountUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	if !c.ServiceAccountsEnabled {
		return badRequest("Service account not enabled for the client '" + c.ClientID + "'")
	}
	u, err := h.Svc.Store.GetServiceAccountUser(r.Context(), c.ID)
	if err != nil {
		return err
	}
	return ok(w, userToRep(u))
}

func (h *Handler) clientSessions(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	all, err := h.Svc.Store.ListRealmSessions(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	var sessions []*model.UserSession
	for _, s := range all {
		if s.Clients[c.ID] {
			sessions = append(sessions, s)
		}
	}
	out, err := h.sessionsToRep(r, realm, sessions, map[string]*model.User{})
	if err != nil {
		return err
	}
	return ok(w, out)
}
