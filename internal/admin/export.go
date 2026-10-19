package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/ducnt114/gocloak/internal/federation"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// ExportOptions selects what Export includes.
type ExportOptions struct {
	Clients bool // clients and client roles
	Groups  bool // groups and realm roles
	Users   bool // users with credentials, role mappings and groups
	Secrets bool // client secrets in clear text instead of "**********"
}

// FullExport is what `gocloak export` writes.
var FullExport = ExportOptions{Clients: true, Groups: true, Users: true, Secrets: true}

const maskedSecret = "**********"

// Export builds a Keycloak RealmRepresentation of a realm, the inverse of
// Import: roles and composites are referenced by name, groups by path.
func Export(ctx context.Context, svc *service.Service, realm *model.Realm, opts ExportOptions) (*RealmRep, error) {
	st := svc.Store
	var defaultRole *model.Role
	roles, err := st.ListAllRoles(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	roleByID := map[string]*model.Role{}
	for _, r := range roles {
		roleByID[r.ID] = r
		if r.ID == realm.DefaultRoleID {
			defaultRole = r
		}
	}
	rep := realmToRep(realm, defaultRole)

	clients, err := st.ListClients(ctx, realm.ID, "", 0, 0)
	if err != nil {
		return nil, err
	}
	clientByID := map[string]*model.Client{}
	for _, c := range clients {
		clientByID[c.ID] = c
	}
	if opts.Clients {
		if err := exportScopes(ctx, st, realm, &rep, clients, clientByID); err != nil {
			return nil, err
		}
		for _, c := range clients {
			cr, err := clientRepWithScopes(ctx, st, c)
			if err != nil {
				return nil, err
			}
			if !c.PublicClient && !c.BearerOnly {
				if opts.Secrets {
					cr.Secret = ptr(c.Secret)
				} else {
					cr.Secret = ptr(maskedSecret)
				}
			}
			if cr.AuthorizationServicesEnabled != nil {
				if d, err := svc.LoadAuthz(ctx, st, c.ID); err == nil {
					settings := (&Handler{Svc: svc}).exportSettings(ctx, &authzCtx{realm: realm, client: c, data: d})
					cr.AuthorizationSettings, _ = json.Marshal(settings)
				}
			}
			rep.Clients = append(rep.Clients, cr)
		}
	}

	// splitRoles groups roles into realm role names and clientId -> names.
	splitRoles := func(list []*model.Role) ([]string, map[string][]string) {
		var realmNames []string
		var clientNames map[string][]string
		for _, r := range list {
			if r.ClientID == "" {
				realmNames = append(realmNames, r.Name)
				continue
			}
			c := clientByID[r.ClientID]
			if c == nil {
				continue
			}
			if clientNames == nil {
				clientNames = map[string][]string{}
			}
			clientNames[c.ClientID] = append(clientNames[c.ClientID], r.Name)
		}
		sort.Strings(realmNames)
		for _, v := range clientNames {
			sort.Strings(v)
		}
		return realmNames, clientNames
	}

	if opts.Groups || opts.Clients {
		edges, err := st.CompositeEdges(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		roleRep := func(r *model.Role) RoleRep {
			rr := roleToRep(r, realm.ID)
			if children := edges[r.ID]; len(children) > 0 {
				var list []*model.Role
				for _, id := range children {
					if c := roleByID[id]; c != nil {
						list = append(list, c)
					}
				}
				rn, cn := splitRoles(list)
				rr.Composites = &CompositesRep{Realm: rn, Client: cn}
			}
			return rr
		}
		rep.Roles = &RolesRep{}
		for _, r := range roles {
			switch {
			case r.ClientID == "" && opts.Groups:
				rep.Roles.Realm = append(rep.Roles.Realm, roleRep(r))
			case r.ClientID != "" && opts.Clients:
				c := clientByID[r.ClientID]
				if c == nil {
					continue
				}
				if rep.Roles.Client == nil {
					rep.Roles.Client = map[string][]RoleRep{}
				}
				rep.Roles.Client[c.ClientID] = append(rep.Roles.Client[c.ClientID], roleRep(r))
			}
		}
		sort.Slice(rep.Roles.Realm, func(i, j int) bool { return *rep.Roles.Realm[i].Name < *rep.Roles.Realm[j].Name })
		for _, list := range rep.Roles.Client {
			sort.Slice(list, func(i, j int) bool { return *list[i].Name < *list[j].Name })
		}
	}

	if opts.Groups {
		groups, err := st.ListAllGroups(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		children := map[string][]*model.Group{}
		for _, g := range groups {
			children[g.ParentID] = append(children[g.ParentID], g)
		}
		paths := groupPaths(groups)
		var build func(g *model.Group) (GroupRep, error)
		build = func(g *model.Group) (GroupRep, error) {
			gr := groupToRep(g, paths[g.ID], len(children[g.ID]))
			gr.Access, gr.SubGroupCount = nil, nil
			mapped, err := st.GroupRoles(ctx, g.ID)
			if err != nil {
				return gr, err
			}
			gr.RealmRoles, gr.ClientRoles = splitRoles(mapped)
			for _, c := range children[g.ID] {
				sub, err := build(c)
				if err != nil {
					return gr, err
				}
				gr.SubGroups = append(gr.SubGroups, sub)
			}
			return gr, nil
		}
		for _, g := range children[""] {
			gr, err := build(g)
			if err != nil {
				return nil, err
			}
			rep.Groups = append(rep.Groups, gr)
		}
		defaults, err := st.ListDefaultGroups(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range defaults {
			rep.DefaultGroups = append(rep.DefaultGroups, paths[g.ID])
		}
	}

	if opts.Groups || opts.Clients {
		if err := exportAuthentication(ctx, st, realm, &rep); err != nil {
			return nil, err
		}
	}
	if opts.Secrets {
		if err := exportComponents(ctx, st, realm, &rep); err != nil {
			return nil, err
		}
	} else {
		if err := exportUserProfile(ctx, st, realm, &rep); err != nil {
			return nil, err
		}
		// user storage providers, with masked credentials
		storage, err := st.ListComponents(ctx, realm.ID, federation.ProviderType)
		if err != nil {
			return nil, err
		}
		mappers, err := st.ListComponents(ctx, realm.ID, federation.MapperType)
		if err != nil {
			return nil, err
		}
		addComponentTree(&rep, append(storage, mappers...), true)
	}

	idps, err := st.ListIdentityProviders(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	for _, idp := range idps {
		rep.IdentityProviders = append(rep.IdentityProviders, idpToRep(idp, opts.Secrets))
		ms, err := st.ListIdPMappers(ctx, realm.ID, idp.Alias)
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			rep.IdentityProviderMappers = append(rep.IdentityProviderMappers, idpMapperToRep(m))
		}
	}

	if opts.Users {
		users, err := exportUsers(ctx, svc, realm, clientByID, splitRoles)
		if err != nil {
			return nil, err
		}
		rep.Users = users
	}
	return &rep, nil
}

func exportUsers(ctx context.Context, svc *service.Service, realm *model.Realm, clientByID map[string]*model.Client,
	splitRoles func([]*model.Role) ([]string, map[string][]string)) ([]UserRep, error) {
	st := svc.Store
	groups, err := st.ListAllGroups(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	paths := groupPaths(groups)
	users, err := st.ListAllUsers(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	out := []UserRep{}
	for _, u := range users {
		ur := userToRep(u)
		ur.Access = nil
		if u.ServiceAccountClientID != "" {
			if c := clientByID[u.ServiceAccountClientID]; c != nil {
				ur.ServiceAccountClientID = ptr(c.ClientID)
			}
		}
		creds, err := st.ListCredentials(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, c := range creds {
			ur.Credentials = append(ur.Credentials, CredentialRep{ID: c.ID, Type: c.Type, UserLabel: c.UserLabel,
				CreatedDate: c.CreatedDate, SecretData: c.SecretData, CredentialData: c.CredentialData, Priority: c.Priority})
		}
		mapped, err := st.UserRoles(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		ur.RealmRoles, ur.ClientRoles = splitRoles(mapped)
		ug, err := st.UserGroups(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, g := range ug {
			ur.Groups = append(ur.Groups, paths[g.ID])
		}
		sort.Strings(ur.Groups)
		links, err := st.ListFederatedIdentities(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range links {
			ur.FederatedIdentities = append(ur.FederatedIdentities, FederatedIdentityRep{IdentityProvider: l.IdentityProvider,
				UserID: l.FederatedUserID, UserName: l.FederatedUsername})
		}
		consents, err := st.ListConsents(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, cn := range consents {
			c, err := st.GetClient(ctx, realm.ID, cn.ClientID)
			if err != nil {
				continue
			}
			cr := ClientConsentRep{ClientID: c.ClientID, GrantedClientScopes: []string{}, CreatedDate: cn.Created, LastUpdatedDate: cn.Updated}
			for _, id := range cn.Scopes {
				if id == c.ID {
					cr.GrantedClientScopes = append(cr.GrantedClientScopes, c.ClientID)
				} else if sc, err := st.GetClientScope(ctx, realm.ID, id); err == nil {
					cr.GrantedClientScopes = append(cr.GrantedClientScopes, sc.Name)
				}
			}
			ur.ClientConsents = append(ur.ClientConsents, cr)
		}
		out = append(out, ur)
	}
	return out, nil
}

// partialExport implements POST /admin/realms/{realm}/partial-export. Like
// Keycloak it never includes users, and client secrets are masked.
func (h *Handler) partialExport(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	opts := ExportOptions{Clients: q.Get("exportClients") == "true", Groups: q.Get("exportGroupsAndRoles") == "true"}
	if opts.Clients && !p.can(realm, permViewClients) {
		return forbidden()
	}
	rep, err := Export(r.Context(), h.Svc, realm, opts)
	if err != nil {
		return err
	}
	return ok(w, rep)
}

// exportScopes adds client scopes, the realm's default scopes and the role
// scope mappings of clients and client scopes.
func exportScopes(ctx context.Context, st *store.Store, realm *model.Realm, rep *RealmRep, clients []*model.Client, clientByID map[string]*model.Client) error {
	scopes, err := st.ListClientScopes(ctx, realm.ID)
	if err != nil {
		return err
	}
	scopeByID := map[string]*model.ClientScope{}
	for _, cs := range scopes {
		scopeByID[cs.ID] = cs
		ms, err := st.ListMappers(ctx, cs.ID)
		if err != nil {
			return err
		}
		sr := ClientScopeRep{ID: ptr(cs.ID), Name: ptr(cs.Name), Protocol: ptr(cs.Protocol), Attributes: cs.Attributes,
			ProtocolMappers: mappersToRep(ms)}
		if cs.Description != "" {
			sr.Description = ptr(cs.Description)
		}
		rep.ClientScopes = append(rep.ClientScopes, sr)
	}
	links, err := st.ListRealmDefaultScopes(ctx, realm.ID)
	if err != nil {
		return err
	}
	rep.DefaultDefaultClientScopes, rep.DefaultOptionalClientScopes = []string{}, []string{}
	for _, l := range links {
		if cs := scopeByID[l.ScopeID]; cs != nil {
			if l.Default {
				rep.DefaultDefaultClientScopes = append(rep.DefaultDefaultClientScopes, cs.Name)
			} else {
				rep.DefaultOptionalClientScopes = append(rep.DefaultOptionalClientScopes, cs.Name)
			}
		}
	}
	sort.Strings(rep.DefaultDefaultClientScopes)
	sort.Strings(rep.DefaultOptionalClientScopes)

	addMappings := func(ownerID string, sm ScopeMappingRep) error {
		roles, err := st.ListScopeMappings(ctx, ownerID)
		if err != nil {
			return err
		}
		byClient := map[string][]string{}
		for _, r := range roles {
			if r.ClientID == "" {
				byClient[""] = append(byClient[""], r.Name)
			} else if c := clientByID[r.ClientID]; c != nil {
				byClient[c.ClientID] = append(byClient[c.ClientID], r.Name)
			}
		}
		for clientID, names := range byClient {
			sort.Strings(names)
			entry := sm
			entry.Roles = names
			if clientID == "" {
				rep.ScopeMappings = append(rep.ScopeMappings, entry)
				continue
			}
			if rep.ClientScopeMappings == nil {
				rep.ClientScopeMappings = map[string][]ScopeMappingRep{}
			}
			rep.ClientScopeMappings[clientID] = append(rep.ClientScopeMappings[clientID], entry)
		}
		return nil
	}
	for _, c := range clients {
		if err := addMappings(c.ID, ScopeMappingRep{Client: c.ClientID}); err != nil {
			return err
		}
	}
	for _, cs := range scopes {
		if err := addMappings(cs.ID, ScopeMappingRep{ClientScope: cs.Name}); err != nil {
			return err
		}
	}
	return nil
}

func exportAuthentication(ctx context.Context, st *store.Store, realm *model.Realm, rep *RealmRep) error {
	flows, err := st.ListFlows(ctx, realm.ID)
	if err != nil {
		return err
	}
	for _, f := range flows {
		fr, err := flowToRep(ctx, st, f)
		if err != nil {
			return err
		}
		rep.AuthenticationFlows = append(rep.AuthenticationFlows, fr)
	}
	configs, err := st.ListAuthConfigs(ctx, realm.ID)
	if err != nil {
		return err
	}
	for _, c := range configs {
		rep.AuthenticatorConfig = append(rep.AuthenticatorConfig, authConfigRep{ID: c.ID, Alias: c.Alias, Config: c.Config})
	}
	actions, err := st.ListRequiredActions(ctx, realm.ID)
	if err != nil {
		return err
	}
	for _, a := range actions {
		rep.RequiredActions = append(rep.RequiredActions, requiredActionToRep(a))
	}
	return nil
}

func componentToExport(c *model.Component) componentExport {
	return componentExport{ID: c.ID, Name: c.Name, ProviderID: c.ProviderID, SubType: c.SubType,
		SubComponents: map[string][]componentExport{}, Config: c.Config}
}

// exportComponents exports key providers (with private keys, as Keycloak's
// full export does) and the user profile.
func exportComponents(ctx context.Context, st *store.Store, realm *model.Realm, rep *RealmRep) error {
	comps, err := st.ListComponents(ctx, realm.ID, "")
	if err != nil {
		return err
	}
	addComponentTree(rep, comps, false)
	return nil
}

// addComponentTree adds components to an export, sub components (LDAP
// mappers) nested under their parent as Keycloak does.
func addComponentTree(rep *RealmRep, comps []*model.Component, mask bool) {
	byParent := map[string][]*model.Component{}
	ids := map[string]bool{}
	for _, c := range comps {
		ids[c.ID] = true
	}
	for _, c := range comps {
		if ids[c.ParentID] {
			byParent[c.ParentID] = append(byParent[c.ParentID], c)
		}
	}
	var build func(c *model.Component) componentExport
	build = func(c *model.Component) componentExport {
		ce := componentToExport(c)
		if mask {
			cfg := map[string][]string{}
			for k, v := range c.Config {
				if maskedComponentConfig[k] && len(v) > 0 && v[0] != "" {
					v = []string{maskedSecret}
				}
				cfg[k] = v
			}
			ce.Config = cfg
		}
		for _, sub := range byParent[c.ID] {
			ce.SubComponents[sub.ProviderType] = append(ce.SubComponents[sub.ProviderType], build(sub))
		}
		return ce
	}
	for _, c := range comps {
		if ids[c.ParentID] {
			continue
		}
		if rep.Components == nil {
			rep.Components = map[string][]componentExport{}
		}
		rep.Components[c.ProviderType] = append(rep.Components[c.ProviderType], build(c))
	}
}

func exportUserProfile(ctx context.Context, st *store.Store, realm *model.Realm, rep *RealmRep) error {
	comps, err := st.ListComponents(ctx, realm.ID, service.UserProfileProviderType)
	if err != nil {
		return err
	}
	for _, c := range comps {
		if rep.Components == nil {
			rep.Components = map[string][]componentExport{}
		}
		rep.Components[c.ProviderType] = append(rep.Components[c.ProviderType], componentToExport(c))
	}
	return nil
}
