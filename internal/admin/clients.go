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

func (h *Handler) loadClient(r *http.Request, realm *model.Realm) (*model.Client, error) {
	c, err := h.Svc.Store.GetClient(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find client")
	}
	return c, err
}

func (h *Handler) clientRep(ctx context.Context, p *principal, realm *model.Realm, c *model.Client) (ClientRep, error) {
	rep, err := clientRepWithScopes(ctx, h.Svc.Store, c)
	if err != nil {
		return rep, err
	}
	if !c.PublicClient && !c.BearerOnly && p.can(realm, permManageClients) {
		rep.Secret = ptr(c.Secret)
	}
	return rep, nil
}

// clientRepWithScopes adds the client's scopes (by name) and its own
// protocol mappers to the representation.
func clientRepWithScopes(ctx context.Context, st *store.Store, c *model.Client) (ClientRep, error) {
	rep := clientToRep(c)
	links, err := st.ListClientScopeLinks(ctx, c.ID)
	if err != nil {
		return rep, err
	}
	for _, l := range links {
		cs, err := st.GetClientScope(ctx, c.RealmID, l.ScopeID)
		if err != nil {
			return rep, err
		}
		if l.Default {
			rep.DefaultClientScopes = append(rep.DefaultClientScopes, cs.Name)
		} else {
			rep.OptionalClientScopes = append(rep.OptionalClientScopes, cs.Name)
		}
	}
	sort.Strings(rep.DefaultClientScopes)
	sort.Strings(rep.OptionalClientScopes)
	ms, err := st.ListMappers(ctx, c.ID)
	if err != nil {
		return rep, err
	}
	if len(ms) > 0 {
		rep.ProtocolMappers = mappersToRep(ms)
	}
	return rep, nil
}

// applyClientScopes replaces the client's default and/or optional scopes
// when the representation lists them; unknown scope names are ignored, as
// in Keycloak. With mappers, the representation's protocol mappers replace
// the client's own.
func applyClientScopes(ctx context.Context, tx *store.Store, c *model.Client, rep *ClientRep, mappers bool) error {
	for _, kind := range []struct {
		names     []string
		isDefault bool
	}{{rep.DefaultClientScopes, true}, {rep.OptionalClientScopes, false}} {
		if kind.names == nil {
			continue
		}
		links, err := tx.ListClientScopeLinks(ctx, c.ID)
		if err != nil {
			return err
		}
		for _, l := range links {
			if l.Default == kind.isDefault {
				if err := tx.RemoveClientScopeLink(ctx, c.ID, l.ScopeID); err != nil {
					return err
				}
			}
		}
		for _, name := range kind.names {
			cs, err := tx.GetClientScopeByName(ctx, c.RealmID, name)
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if err := tx.SetClientScopeLink(ctx, c.ID, cs.ID, kind.isDefault); err != nil {
				return err
			}
		}
	}
	if !mappers || rep.ProtocolMappers == nil {
		return nil
	}
	existing, err := tx.ListMappers(ctx, c.ID)
	if err != nil {
		return err
	}
	byName := map[string]*model.ProtocolMapper{}
	for _, m := range existing {
		byName[m.Name] = m
	}
	for i := range rep.ProtocolMappers {
		mr := rep.ProtocolMappers[i]
		mr.ID = ""
		m, err := validateMapper(c.RealmID, c.ID, &mr)
		if err != nil {
			return err
		}
		if old := byName[m.Name]; old != nil {
			m.ID = old.ID
			if err := tx.UpdateMapper(ctx, m); err != nil {
				return err
			}
			continue
		}
		if err := tx.CreateMapper(ctx, m); err != nil {
			return err
		}
	}
	return nil
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
		rep, err := h.clientRep(r.Context(), p, realm, c)
		if err != nil {
			return err
		}
		out = append(out, rep)
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
	c := newClientFromRep(realm.ID, &rep)
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := h.Svc.CreateClient(r.Context(), tx, c); err != nil {
			return err
		}
		return applyClientScopes(r.Context(), tx, c, &rep, true)
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
	rep, err := h.clientRep(r.Context(), p, realm, c)
	if err != nil {
		return err
	}
	return ok(w, rep)
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
		if err := applyClientScopes(r.Context(), tx, c, &rep, false); err != nil {
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
	list := h.Svc.Store.ListRealmSessions
	if strings.Contains(r.URL.Path, "offline-session") {
		list = h.Svc.Store.ListRealmOfflineSessions
	}
	all, err := list(r.Context(), realm.ID)
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
	if strings.HasSuffix(r.URL.Path, "-count") {
		return ok(w, map[string]int{"count": len(out)})
	}
	return ok(w, page(r, out))
}
