package admin

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// ClientScopeRep mirrors Keycloak's ClientScopeRepresentation.
type ClientScopeRep struct {
	ID              *string             `json:"id,omitempty"`
	Name            *string             `json:"name,omitempty"`
	Description     *string             `json:"description,omitempty"`
	Protocol        *string             `json:"protocol,omitempty"`
	Attributes      strMap              `json:"attributes,omitempty"`
	ProtocolMappers []ProtocolMapperRep `json:"protocolMappers,omitempty"`
}

// ProtocolMapperRep mirrors Keycloak's ProtocolMapperRepresentation.
type ProtocolMapperRep struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`
	ProtocolMapper string `json:"protocolMapper"`
	Config         strMap `json:"config"`
}

// ScopeMappingRep is an entry of a realm export's scopeMappings /
// clientScopeMappings: the roles (by name) a client or client scope may use.
type ScopeMappingRep struct {
	Client      string   `json:"client,omitempty"`
	ClientScope string   `json:"clientScope,omitempty"`
	Roles       []string `json:"roles"`
}

func mapperToRep(m *model.ProtocolMapper) ProtocolMapperRep {
	return ProtocolMapperRep{ID: m.ID, Name: m.Name, Protocol: m.Protocol, ProtocolMapper: m.Type, Config: m.Config}
}

func mappersToRep(ms []*model.ProtocolMapper) []ProtocolMapperRep {
	out := make([]ProtocolMapperRep, 0, len(ms))
	for _, m := range ms {
		out = append(out, mapperToRep(m))
	}
	return out
}

func (h *Handler) scopeRep(ctx context.Context, cs *model.ClientScope) (ClientScopeRep, error) {
	ms, err := h.Svc.Store.ListMappers(ctx, cs.ID)
	if err != nil {
		return ClientScopeRep{}, err
	}
	rep := ClientScopeRep{ID: ptr(cs.ID), Name: ptr(cs.Name), Protocol: ptr(cs.Protocol), Attributes: cs.Attributes}
	if cs.Description != "" {
		rep.Description = ptr(cs.Description)
	}
	if len(ms) > 0 {
		rep.ProtocolMappers = mappersToRep(ms)
	}
	return rep, nil
}

// validateMapper checks a mapper representation and turns it into a model.
func validateMapper(realmID, ownerID string, rep *ProtocolMapperRep) (*model.ProtocolMapper, error) {
	if rep.Name == "" {
		return nil, badRequest("Protocol mapper name is required")
	}
	if rep.Protocol == "" {
		rep.Protocol = "openid-connect"
	}
	if rep.Protocol != "openid-connect" {
		return nil, badRequest("Unsupported protocol " + rep.Protocol)
	}
	if !service.MapperTypes[rep.ProtocolMapper] {
		return nil, badRequest("ProtocolMapper provider not found: " + rep.ProtocolMapper)
	}
	m := &model.ProtocolMapper{ID: rep.ID, RealmID: realmID, OwnerID: ownerID, Name: rep.Name,
		Protocol: rep.Protocol, Type: rep.ProtocolMapper, Config: rep.Config}
	if m.ID == "" {
		m.ID = service.NewID()
	}
	if m.Config == nil {
		m.Config = map[string]string{}
	}
	return m, nil
}

// ---------------------------------------------------------------- client scopes

func (h *Handler) loadScope(r *http.Request, realm *model.Realm) (*model.ClientScope, error) {
	cs, err := h.Svc.Store.GetClientScope(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find client scope")
	}
	return cs, err
}

func (h *Handler) listClientScopes(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	scopes, err := h.Svc.Store.ListClientScopes(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	out := []ClientScopeRep{}
	for _, cs := range scopes {
		rep, err := h.scopeRep(r.Context(), cs)
		if err != nil {
			return err
		}
		out = append(out, rep)
	}
	return ok(w, out)
}

func (h *Handler) createClientScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	var rep ClientScopeRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	var cs *model.ClientScope
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		var err error
		cs, err = upsertScope(r.Context(), tx, realm, &rep, false)
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("Client Scope " + *rep.Name + " already exists")
	}
	if err != nil {
		return err
	}
	return created(w, r, cs.ID)
}

// upsertScope creates a client scope, or with update updates the existing
// scope of the same name, replacing its mappers when the representation lists them.
func upsertScope(ctx context.Context, tx *store.Store, realm *model.Realm, rep *ClientScopeRep, update bool) (*model.ClientScope, error) {
	if rep.Name == nil || *rep.Name == "" {
		return nil, badRequest("Client scope name is required")
	}
	cs, err := tx.GetClientScopeByName(ctx, realm.ID, *rep.Name)
	switch {
	case err == nil && !update:
		return nil, store.ErrConflict
	case errors.Is(err, store.ErrNotFound):
		cs = &model.ClientScope{ID: service.NewID(), RealmID: realm.ID, Protocol: "openid-connect", Attributes: map[string]string{}}
		applyScopeRep(cs, rep)
		if err := tx.CreateClientScope(ctx, cs); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		applyScopeRep(cs, rep)
		if err := tx.UpdateClientScope(ctx, cs); err != nil {
			return nil, err
		}
		if rep.ProtocolMappers != nil {
			old, err := tx.ListMappers(ctx, cs.ID)
			if err != nil {
				return nil, err
			}
			for _, m := range old {
				if err := tx.DeleteMapper(ctx, cs.ID, m.ID); err != nil {
					return nil, err
				}
			}
		}
	}
	for i := range rep.ProtocolMappers {
		mr := rep.ProtocolMappers[i]
		mr.ID = "" // ids from another realm would collide
		m, err := validateMapper(realm.ID, cs.ID, &mr)
		if err != nil {
			return nil, err
		}
		if err := tx.CreateMapper(ctx, m); err != nil {
			return nil, err
		}
	}
	return cs, nil
}

func applyScopeRep(cs *model.ClientScope, rep *ClientScopeRep) {
	set(&cs.Name, rep.Name)
	set(&cs.Description, rep.Description)
	set(&cs.Protocol, rep.Protocol)
	if rep.Attributes != nil {
		cs.Attributes = rep.Attributes
	}
}

func (h *Handler) getClientScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	cs, err := h.loadScope(r, realm)
	if err != nil {
		return err
	}
	rep, err := h.scopeRep(r.Context(), cs)
	if err != nil {
		return err
	}
	return ok(w, rep)
}

func (h *Handler) updateClientScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	cs, err := h.loadScope(r, realm)
	if err != nil {
		return err
	}
	var rep ClientScopeRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	applyScopeRep(cs, &rep)
	if err := h.Svc.Store.UpdateClientScope(r.Context(), cs); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Client Scope " + cs.Name + " already exists")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteClientScope(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	cs, err := h.loadScope(r, realm)
	if err != nil {
		return err
	}
	links, err := h.Svc.Store.ListRealmDefaultScopes(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	for _, l := range links {
		if l.ScopeID == cs.ID {
			return badRequest("Cannot remove client scope, it is currently in use")
		}
	}
	if err := h.Svc.Store.DeleteClientScope(r.Context(), cs.ID); err != nil {
		return err
	}
	return noContent(w)
}

// ---------------------------------------------------------------- protocol mappers

// mapperOwner resolves the client or client scope a mapper route refers to.
func (h *Handler) mapperOwner(r *http.Request, p *principal, ofScope, write bool) (*model.Realm, string, error) {
	perm := permViewClients
	if write {
		perm = permManageClients
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, "", err
	}
	if ofScope {
		cs, err := h.loadScope(r, realm)
		if err != nil {
			return nil, "", err
		}
		return realm, cs.ID, nil
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return nil, "", err
	}
	return realm, c.ID, nil
}

func (h *Handler) mapperHandlers(ofScope bool) (list, create, addModels, get, update, del handlerFunc) {
	list = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		_, owner, err := h.mapperOwner(r, p, ofScope, false)
		if err != nil {
			return err
		}
		ms, err := h.Svc.Store.ListMappers(r.Context(), owner)
		if err != nil {
			return err
		}
		return ok(w, mappersToRep(ms))
	}
	createAll := func(w http.ResponseWriter, r *http.Request, p *principal, reps []ProtocolMapperRep) (*model.ProtocolMapper, error) {
		realm, owner, err := h.mapperOwner(r, p, ofScope, true)
		if err != nil {
			return nil, err
		}
		var last *model.ProtocolMapper
		err = h.withTx(r.Context(), func(tx *store.Store) error {
			for i := range reps {
				m, err := validateMapper(realm.ID, owner, &reps[i])
				if err != nil {
					return err
				}
				if err := tx.CreateMapper(r.Context(), m); err != nil {
					if errors.Is(err, store.ErrConflict) {
						return conflict("Protocol mapper exists with same name")
					}
					return err
				}
				last = m
			}
			return nil
		})
		return last, err
	}
	create = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		var rep ProtocolMapperRep
		if err := decode(r, &rep); err != nil {
			return err
		}
		m, err := createAll(w, r, p, []ProtocolMapperRep{rep})
		if err != nil {
			return err
		}
		return created(w, r, m.ID)
	}
	addModels = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		var reps []ProtocolMapperRep
		if err := decode(r, &reps); err != nil {
			return err
		}
		if _, err := createAll(w, r, p, reps); err != nil {
			return err
		}
		return noContent(w)
	}
	load := func(r *http.Request, p *principal, write bool) (*model.Realm, *model.ProtocolMapper, error) {
		realm, owner, err := h.mapperOwner(r, p, ofScope, write)
		if err != nil {
			return nil, nil, err
		}
		m, err := h.Svc.Store.GetMapper(r.Context(), owner, r.PathValue("mapperId"))
		if errors.Is(err, store.ErrNotFound) {
			return nil, nil, notFound("Model not found")
		}
		return realm, m, err
	}
	get = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		_, m, err := load(r, p, false)
		if err != nil {
			return err
		}
		return ok(w, mapperToRep(m))
	}
	update = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		realm, m, err := load(r, p, true)
		if err != nil {
			return err
		}
		var rep ProtocolMapperRep
		if err := decode(r, &rep); err != nil {
			return err
		}
		if rep.Name == "" {
			rep.Name = m.Name
		}
		if rep.ProtocolMapper == "" {
			rep.ProtocolMapper = m.Type
		}
		rep.ID = m.ID
		nm, err := validateMapper(realm.ID, m.OwnerID, &rep)
		if err != nil {
			return err
		}
		if err := h.Svc.Store.UpdateMapper(r.Context(), nm); err != nil {
			if errors.Is(err, store.ErrConflict) {
				return conflict("Protocol mapper exists with same name")
			}
			return err
		}
		return noContent(w)
	}
	del = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		_, m, err := load(r, p, true)
		if err != nil {
			return err
		}
		if err := h.Svc.Store.DeleteMapper(r.Context(), m.OwnerID, m.ID); err != nil {
			return err
		}
		return noContent(w)
	}
	return
}

// ---------------------------------------------------------------- default scopes

type scopeLinkTarget struct {
	realm  *model.Realm
	list   func(ctx context.Context) ([]model.ClientScopeLink, error)
	set    func(ctx context.Context, scopeID string, isDefault bool) error
	remove func(ctx context.Context, scopeID string) error
}

func (h *Handler) realmScopeTarget(r *http.Request, p *principal, write bool) (*scopeLinkTarget, error) {
	perm := permViewRealm
	if write {
		perm = permManageRealm
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	st := h.Svc.Store
	return &scopeLinkTarget{
		realm: realm,
		list: func(ctx context.Context) ([]model.ClientScopeLink, error) {
			return st.ListRealmDefaultScopes(ctx, realm.ID)
		},
		set: func(ctx context.Context, id string, d bool) error {
			return st.SetRealmDefaultScope(ctx, realm.ID, id, d)
		},
		remove: func(ctx context.Context, id string) error { return st.RemoveRealmDefaultScope(ctx, realm.ID, id) },
	}, nil
}

func (h *Handler) clientScopeTarget(r *http.Request, p *principal, write bool) (*scopeLinkTarget, error) {
	perm := permViewClients
	if write {
		perm = permManageClients
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return nil, err
	}
	st := h.Svc.Store
	return &scopeLinkTarget{
		realm:  realm,
		list:   func(ctx context.Context) ([]model.ClientScopeLink, error) { return st.ListClientScopeLinks(ctx, c.ID) },
		set:    func(ctx context.Context, id string, d bool) error { return st.SetClientScopeLink(ctx, c.ID, id, d) },
		remove: func(ctx context.Context, id string) error { return st.RemoveClientScopeLink(ctx, c.ID, id) },
	}, nil
}

func (h *Handler) scopeLinkHandlers(target func(r *http.Request, p *principal, write bool) (*scopeLinkTarget, error), isDefault bool) (list, add, remove handlerFunc) {
	list = func(w http.ResponseWriter, r *http.Request, p *principal) error {
		t, err := target(r, p, false)
		if err != nil {
			return err
		}
		links, err := t.list(r.Context())
		if err != nil {
			return err
		}
		type brief struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		out := []brief{}
		for _, l := range links {
			if l.Default != isDefault {
				continue
			}
			cs, err := h.Svc.Store.GetClientScope(r.Context(), t.realm.ID, l.ScopeID)
			if err != nil {
				return err
			}
			out = append(out, brief{cs.ID, cs.Name})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return ok(w, out)
	}
	change := func(w http.ResponseWriter, r *http.Request, p *principal, add bool) error {
		t, err := target(r, p, true)
		if err != nil {
			return err
		}
		cs, err := h.Svc.Store.GetClientScope(r.Context(), t.realm.ID, r.PathValue("scopeId"))
		if errors.Is(err, store.ErrNotFound) {
			return notFound("Client scope")
		}
		if err != nil {
			return err
		}
		if add {
			err = t.set(r.Context(), cs.ID, isDefault)
		} else {
			err = t.remove(r.Context(), cs.ID)
		}
		if err != nil {
			return err
		}
		return noContent(w)
	}
	add = func(w http.ResponseWriter, r *http.Request, p *principal) error { return change(w, r, p, true) }
	remove = func(w http.ResponseWriter, r *http.Request, p *principal) error { return change(w, r, p, false) }
	return
}

// ---------------------------------------------------------------- scope mappings

// scopeMappingSubject adapts a client or client scope to the role mapping
// handlers in roles.go.
func (h *Handler) scopeMappingSubject(ofScope bool) func(r *http.Request, p *principal, write bool) (*mappingSubject, error) {
	return func(r *http.Request, p *principal, write bool) (*mappingSubject, error) {
		realm, owner, err := h.mapperOwner(r, p, ofScope, write)
		if err != nil {
			return nil, err
		}
		st := h.Svc.Store
		direct := func(ctx context.Context) ([]*model.Role, error) { return st.ListScopeMappings(ctx, owner) }
		return &mappingSubject{
			p: p, realm: realm, noGrantCheck: true, direct: direct,
			effective: func(ctx context.Context) ([]*model.Role, error) {
				roles, err := direct(ctx)
				if err != nil {
					return nil, err
				}
				return h.Svc.ExpandComposites(ctx, realm.ID, roles)
			},
			grant:  func(ctx context.Context, id string) error { return st.AddScopeMapping(ctx, owner, id) },
			revoke: func(ctx context.Context, id string) error { return st.RemoveScopeMapping(ctx, owner, id) },
		}, nil
	}
}

func (h *Handler) subjectHandler(subject func(r *http.Request, p *principal, write bool) (*mappingSubject, error), write bool,
	fn func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		s, err := subject(r, p, write)
		if err != nil {
			return err
		}
		return fn(w, r, s)
	}
}

// ---------------------------------------------------------------- evaluate scopes

func (h *Handler) evaluate(kind string) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		realm, err := h.realmFor(r, p, permViewClients)
		if err != nil {
			return err
		}
		if !p.can(realm, permViewUsers) {
			return forbidden()
		}
		c, err := h.loadClient(r, realm)
		if err != nil {
			return err
		}
		u, err := h.Svc.Store.GetUser(r.Context(), realm.ID, r.URL.Query().Get("userId"))
		if errors.Is(err, store.ErrNotFound) {
			return badRequest("No user found")
		}
		if err != nil {
			return err
		}
		claims, err := oidc.ExampleClaims(r.Context(), h.Svc, h.URLs.Issuer(r, realm.Name), h.URLs.Base(r), realm, c, u,
			r.URL.Query().Get("scope"), kind)
		if err != nil {
			return err
		}
		return ok(w, claims)
	}
}

// evaluateMappers lists the mappers applied for a scope parameter.
func (h *Handler) evaluateMappers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	scopes, err := oidc.AppliedScopes(r.Context(), h.Svc.Store, realm, c, r.URL.Query().Get("scope"))
	if err != nil {
		return err
	}
	type evaluated struct {
		MapperID       string `json:"mapperId"`
		MapperName     string `json:"mapperName"`
		ContainerID    string `json:"containerId"`
		ContainerName  string `json:"containerName"`
		ContainerType  string `json:"containerType"`
		Protocol       string `json:"protocol"`
		ProtocolMapper string `json:"protocolMapper"`
	}
	out := []evaluated{}
	add := func(owner, name, typ string) error {
		ms, err := h.Svc.Store.ListMappers(r.Context(), owner)
		if err != nil {
			return err
		}
		for _, m := range ms {
			out = append(out, evaluated{m.ID, m.Name, owner, name, typ, m.Protocol, m.Type})
		}
		return nil
	}
	if err := add(c.ID, c.ClientID, "client"); err != nil {
		return err
	}
	for _, s := range scopes {
		if err := add(s.ID, s.Name, "client-scope"); err != nil {
			return err
		}
	}
	return ok(w, out)
}

func (h *Handler) registerScopeRoutes(R string, add func(pattern string, fn handlerFunc)) {
	add("GET "+R+"/client-scopes", h.listClientScopes)
	add("POST "+R+"/client-scopes", h.createClientScope)
	add("GET "+R+"/client-scopes/{id}", h.getClientScope)
	add("PUT "+R+"/client-scopes/{id}", h.updateClientScope)
	add("DELETE "+R+"/client-scopes/{id}", h.deleteClientScope)

	for _, owner := range []struct {
		prefix  string
		ofScope bool
	}{{R + "/client-scopes/{id}", true}, {R + "/clients/{id}", false}} {
		list, create, addModels, getOne, update, del := h.mapperHandlers(owner.ofScope)
		pm := owner.prefix + "/protocol-mappers"
		add("GET "+pm+"/models", list)
		add("POST "+pm+"/models", create)
		add("POST "+pm+"/add-models", addModels)
		add("GET "+pm+"/models/{mapperId}", getOne)
		add("PUT "+pm+"/models/{mapperId}", update)
		add("DELETE "+pm+"/models/{mapperId}", del)
		add("GET "+pm+"/protocol/{protocol}", list)

		subject := h.scopeMappingSubject(owner.ofScope)
		sm := owner.prefix + "/scope-mappings"
		add("GET "+sm, h.subjectHandler(subject, false, h.allMappings))
		add("GET "+sm+"/realm", h.subjectHandler(subject, false, get(mappingDirect, h)))
		add("POST "+sm+"/realm", h.subjectHandler(subject, true, change(true, h)))
		add("DELETE "+sm+"/realm", h.subjectHandler(subject, true, change(false, h)))
		add("GET "+sm+"/realm/composite", h.subjectHandler(subject, false, get(mappingComposite, h)))
		add("GET "+sm+"/realm/available", h.subjectHandler(subject, false, get(mappingAvailable, h)))
		add("GET "+sm+"/clients/{client}", h.subjectHandler(subject, false, get(mappingDirect, h)))
		add("POST "+sm+"/clients/{client}", h.subjectHandler(subject, true, change(true, h)))
		add("DELETE "+sm+"/clients/{client}", h.subjectHandler(subject, true, change(false, h)))
		add("GET "+sm+"/clients/{client}/composite", h.subjectHandler(subject, false, get(mappingComposite, h)))
		add("GET "+sm+"/clients/{client}/available", h.subjectHandler(subject, false, get(mappingAvailable, h)))
	}

	for _, link := range []struct {
		path      string
		target    func(r *http.Request, p *principal, write bool) (*scopeLinkTarget, error)
		isDefault bool
	}{
		{R + "/default-default-client-scopes", h.realmScopeTarget, true},
		{R + "/default-optional-client-scopes", h.realmScopeTarget, false},
		{R + "/clients/{id}/default-client-scopes", h.clientScopeTarget, true},
		{R + "/clients/{id}/optional-client-scopes", h.clientScopeTarget, false},
	} {
		list, addLink, removeLink := h.scopeLinkHandlers(link.target, link.isDefault)
		add("GET "+link.path, list)
		add("PUT "+link.path+"/{scopeId}", addLink)
		add("DELETE "+link.path+"/{scopeId}", removeLink)
	}

	ev := R + "/clients/{id}/evaluate-scopes"
	add("GET "+ev+"/generate-example-access-token", h.evaluate("access"))
	add("GET "+ev+"/generate-example-id-token", h.evaluate("id"))
	add("GET "+ev+"/generate-example-userinfo", h.evaluate("userinfo"))
	add("GET "+ev+"/protocol-mappers", h.evaluateMappers)
	add("GET "+ev+"/scope-mappings/{container}/granted", h.evaluateScopeMappings(true))
	add("GET "+ev+"/scope-mappings/{container}/not-granted", h.evaluateScopeMappings(false))
}

// evaluateScopeMappings lists the roles of a container (the realm name or
// a client id) that the client's scope grants, or does not grant.
func (h *Handler) evaluateScopeMappings(granted bool) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		realm, err := h.realmFor(r, p, permViewClients)
		if err != nil {
			return err
		}
		c, err := h.loadClient(r, realm)
		if err != nil {
			return err
		}
		ctx := r.Context()
		containerUUID := ""
		if container := r.PathValue("container"); container != realm.Name && container != realm.ID {
			cc, err := h.Svc.Store.GetClient(ctx, realm.ID, container)
			if err != nil {
				return notFound("No client with id " + container)
			}
			containerUUID = cc.ID
		}
		roles, err := h.Svc.Store.ListRoles(ctx, realm.ID, containerUUID, "", 0, 1<<30)
		if err != nil {
			return err
		}
		allowed := map[string]bool{}
		if !c.FullScopeAllowed {
			mapped, err := h.Svc.Store.ListScopeMappings(ctx, c.ID)
			if err != nil {
				return err
			}
			scopes, err := oidc.AppliedScopes(ctx, h.Svc.Store, realm, c, r.URL.Query().Get("scope"))
			if err != nil {
				return err
			}
			for _, cs := range scopes {
				sm, err := h.Svc.Store.ListScopeMappings(ctx, cs.ID)
				if err != nil {
					return err
				}
				mapped = append(mapped, sm...)
			}
			expanded, err := h.Svc.ExpandComposites(ctx, realm.ID, mapped)
			if err != nil {
				return err
			}
			for _, role := range expanded {
				allowed[role.ID] = true
			}
		}
		var out []*model.Role
		for _, role := range roles {
			if (c.FullScopeAllowed || allowed[role.ID]) == granted {
				out = append(out, role)
			}
		}
		return ok(w, rolesToRep(out, realm.ID))
	}
}
