package admin

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// roleContainer identifies where roles live: the realm (clientUUID == "")
// or a client.
type roleContainer struct {
	realm  *model.Realm
	client *model.Client
}

func (c roleContainer) clientUUID() string {
	if c.client == nil {
		return ""
	}
	return c.client.ID
}

// container resolves the realm (and client, for /clients/{id}/roles routes)
// and checks the permission needed for the operation.
func (h *Handler) container(r *http.Request, p *principal, clientRoles, write bool) (roleContainer, error) {
	perm := permViewRealm
	switch {
	case clientRoles && write:
		perm = permManageClients
	case clientRoles:
		perm = permViewClients
	case write:
		perm = permManageRealm
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return roleContainer{}, err
	}
	rc := roleContainer{realm: realm}
	if clientRoles {
		if rc.client, err = h.loadClient(r, realm); err != nil {
			return roleContainer{}, err
		}
	}
	return rc, nil
}

func (h *Handler) loadRole(ctx context.Context, rc roleContainer, name string) (*model.Role, error) {
	role, err := h.Svc.Store.GetRoleByName(ctx, rc.realm.ID, rc.clientUUID(), name)
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find role")
	}
	return role, err
}

// ---------------------------------------------------------------- CRUD

func (h *Handler) listRoles(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, false)
	if err != nil {
		return err
	}
	roles, err := h.Svc.Store.ListRoles(r.Context(), rc.realm.ID, rc.clientUUID(), r.URL.Query().Get("search"),
		intParam(r, "first", 0), intParam(r, "max", -1))
	if err != nil {
		return err
	}
	return ok(w, rolesToRep(roles, rc.realm.ID))
}

func (h *Handler) createRole(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, true)
	if err != nil {
		return err
	}
	var rep RoleRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Name == nil || *rep.Name == "" {
		return badRequest("Role name is missing")
	}
	role := &model.Role{ID: service.NewID(), RealmID: rc.realm.ID, ClientID: rc.clientUUID()}
	applyRoleRep(role, &rep)
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := tx.CreateRole(r.Context(), role); err != nil {
			return err
		}
		if rep.Composites != nil {
			return addCompositesByName(r.Context(), tx, rc.realm, role, rep.Composites)
		}
		return nil
	})
	if errors.Is(err, store.ErrConflict) {
		return conflict("Role with name " + role.Name + " already exists")
	}
	if err != nil {
		return err
	}
	return created(w, r, role.Name)
}

func (h *Handler) getRole(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, false)
	if err != nil {
		return err
	}
	role, err := h.loadRole(r.Context(), rc, r.PathValue("roleName"))
	if err != nil {
		return err
	}
	return ok(w, roleToRep(role, rc.realm.ID))
}

func (h *Handler) updateRole(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, true)
	if err != nil {
		return err
	}
	role, err := h.loadRole(r.Context(), rc, r.PathValue("roleName"))
	if err != nil {
		return err
	}
	return h.saveRole(w, r, rc.realm, role)
}

func (h *Handler) saveRole(w http.ResponseWriter, r *http.Request, realm *model.Realm, role *model.Role) error {
	var rep RoleRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	applyRoleRep(role, &rep)
	if err := h.Svc.Store.UpdateRole(r.Context(), role); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Role with name " + role.Name + " already exists")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteRole(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, true)
	if err != nil {
		return err
	}
	role, err := h.loadRole(r.Context(), rc, r.PathValue("roleName"))
	if err != nil {
		return err
	}
	if role.ID == rc.realm.DefaultRoleID {
		return badRequest("You can't delete the default role")
	}
	if err := h.Svc.Store.DeleteRole(r.Context(), role.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) roleUsers(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, false)
	if err != nil {
		return err
	}
	if !p.can(rc.realm, permQueryUsers) {
		return forbidden()
	}
	role, err := h.loadRole(r.Context(), rc, r.PathValue("roleName"))
	if err != nil {
		return err
	}
	users, err := h.Svc.Store.UsersWithRole(r.Context(), role.ID, intParam(r, "first", 0), intParam(r, "max", 100))
	if err != nil {
		return err
	}
	return ok(w, usersToRep(users))
}

func (h *Handler) listRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.listRoles(w, r, p, false)
}
func (h *Handler) createRealmRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.createRole(w, r, p, false)
}
func (h *Handler) getRealmRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.getRole(w, r, p, false)
}
func (h *Handler) updateRealmRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.updateRole(w, r, p, false)
}
func (h *Handler) deleteRealmRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.deleteRole(w, r, p, false)
}
func (h *Handler) realmRoleUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.roleUsers(w, r, p, false)
}
func (h *Handler) listClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.listRoles(w, r, p, true)
}
func (h *Handler) createClientRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.createRole(w, r, p, true)
}
func (h *Handler) getClientRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.getRole(w, r, p, true)
}
func (h *Handler) updateClientRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.updateRole(w, r, p, true)
}
func (h *Handler) deleteClientRole(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.deleteRole(w, r, p, true)
}
func (h *Handler) clientRoleUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.roleUsers(w, r, p, true)
}

// ---------------------------------------------------------------- roles-by-id

func (h *Handler) roleByID(r *http.Request, p *principal, write bool) (*model.Realm, *model.Role, error) {
	perm := permViewRealm
	if write {
		perm = permManageRealm
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, nil, err
	}
	role, err := h.Svc.Store.GetRole(r.Context(), realm.ID, r.PathValue("roleId"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil, notFound("Could not find role with id")
	}
	return realm, role, err
}

func (h *Handler) getRoleByID(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, role, err := h.roleByID(r, p, false)
	if err != nil {
		return err
	}
	return ok(w, roleToRep(role, realm.ID))
}

func (h *Handler) updateRoleByID(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, role, err := h.roleByID(r, p, true)
	if err != nil {
		return err
	}
	return h.saveRole(w, r, realm, role)
}

func (h *Handler) deleteRoleByID(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, role, err := h.roleByID(r, p, true)
	if err != nil {
		return err
	}
	if role.ID == realm.DefaultRoleID {
		return badRequest("You can't delete the default role")
	}
	if err := h.Svc.Store.DeleteRole(r.Context(), role.ID); err != nil {
		return err
	}
	return noContent(w)
}

// ---------------------------------------------------------------- composites

// resolveRoles looks up role representations by id, or by name within the
// realm (clientUUID == "") or a client.
func (h *Handler) resolveRoles(ctx context.Context, realm *model.Realm, clientUUID string, reps []RoleRep) ([]*model.Role, error) {
	var out []*model.Role
	for _, rep := range reps {
		var role *model.Role
		var err error
		switch {
		case rep.Name != nil && *rep.Name != "":
			cid := clientUUID
			if rep.ClientRole != nil && *rep.ClientRole && rep.ContainerID != nil {
				cid = *rep.ContainerID
			}
			role, err = h.Svc.Store.GetRoleByName(ctx, realm.ID, cid, *rep.Name)
			if errors.Is(err, store.ErrNotFound) && rep.ID != nil {
				role, err = h.Svc.Store.GetRole(ctx, realm.ID, *rep.ID)
			}
		case rep.ID != nil:
			role, err = h.Svc.Store.GetRole(ctx, realm.ID, *rep.ID)
		default:
			return nil, badRequest("Role name or id is required")
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("Role")
		}
		if err != nil {
			return nil, err
		}
		if clientUUID != "" && role.ClientID != clientUUID && (rep.ClientRole == nil || !*rep.ClientRole) {
			return nil, notFound("Role")
		}
		out = append(out, role)
	}
	return out, nil
}

// resolveAnyRoles resolves composite children, which may be realm or client roles.
func (h *Handler) resolveAnyRoles(ctx context.Context, realm *model.Realm, reps []RoleRep) ([]*model.Role, error) {
	var out []*model.Role
	for _, rep := range reps {
		var role *model.Role
		var err error
		if rep.ID != nil && *rep.ID != "" {
			role, err = h.Svc.Store.GetRole(ctx, realm.ID, *rep.ID)
		} else {
			roles, rerr := h.resolveRoles(ctx, realm, "", []RoleRep{rep})
			if rerr != nil {
				return nil, rerr
			}
			role = roles[0]
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, notFound("Role")
		}
		if err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, nil
}

func (h *Handler) composites(w http.ResponseWriter, r *http.Request, p *principal, clientRoles bool) error {
	rc, err := h.container(r, p, clientRoles, false)
	if err != nil {
		return err
	}
	role, err := h.loadRole(r.Context(), rc, r.PathValue("roleName"))
	if err != nil {
		return err
	}
	children, err := h.Svc.Store.ListComposites(r.Context(), role.ID)
	if err != nil {
		return err
	}
	return ok(w, rolesToRep(children, rc.realm.ID))
}

func (h *Handler) changeComposites(w http.ResponseWriter, r *http.Request, p *principal, clientRoles, add bool) error {
	rc, err := h.container(r, p, clientRoles, true)
	if err != nil {
		return err
	}
	role, err := h.loadRole(r.Context(), rc, r.PathValue("roleName"))
	if err != nil {
		return err
	}
	var reps []RoleRep
	if err := decode(r, &reps); err != nil {
		return err
	}
	children, err := h.resolveAnyRoles(r.Context(), rc.realm, reps)
	if err != nil {
		return err
	}
	if add {
		if err := h.checkGrantable(r.Context(), p, rc.realm, children); err != nil {
			return err
		}
	}
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		for _, c := range children {
			if c.ID == role.ID {
				return badRequest("A role cannot be a composite of itself")
			}
			var err error
			if add {
				err = tx.AddComposite(r.Context(), role.ID, c.ID)
			} else {
				err = tx.RemoveComposite(r.Context(), role.ID, c.ID)
			}
			if err != nil {
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

// addCompositesByName adds composites described by name (as in realm exports).
func addCompositesByName(ctx context.Context, tx *store.Store, realm *model.Realm, role *model.Role, comp *CompositesRep) error {
	for _, name := range comp.Realm {
		child, err := tx.GetRoleByName(ctx, realm.ID, "", name)
		if err != nil {
			return roleNotFound(err, name)
		}
		if err := tx.AddComposite(ctx, role.ID, child.ID); err != nil {
			return err
		}
	}
	for clientID, names := range comp.Client {
		c, err := tx.GetClientByClientID(ctx, realm.ID, clientID)
		if err != nil {
			return roleNotFound(err, clientID)
		}
		for _, name := range names {
			child, err := tx.GetRoleByName(ctx, realm.ID, c.ID, name)
			if err != nil {
				return roleNotFound(err, clientID+"/"+name)
			}
			if err := tx.AddComposite(ctx, role.ID, child.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func roleNotFound(err error, name string) error {
	if errors.Is(err, store.ErrNotFound) {
		return badRequest("Role not found: " + name)
	}
	return err
}

func (h *Handler) realmRoleComposites(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.composites(w, r, p, false)
}
func (h *Handler) addRealmRoleComposites(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.changeComposites(w, r, p, false, true)
}
func (h *Handler) removeRealmRoleComposites(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.changeComposites(w, r, p, false, false)
}
func (h *Handler) clientRoleComposites(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.composites(w, r, p, true)
}
func (h *Handler) addClientRoleComposites(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.changeComposites(w, r, p, true, true)
}
func (h *Handler) removeClientRoleComposites(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.changeComposites(w, r, p, true, false)
}

// ---------------------------------------------------------------- role mappings

// mappingSubject is a user or a group that roles can be mapped to.
type mappingSubject struct {
	p            *principal
	noGrantCheck bool // scope mappings do not grant roles
	realm        *model.Realm
	direct       func(ctx context.Context) ([]*model.Role, error)
	effective    func(ctx context.Context) ([]*model.Role, error)
	grant        func(ctx context.Context, roleID string) error
	revoke       func(ctx context.Context, roleID string) error
}

func (h *Handler) userSubject(r *http.Request, p *principal, write bool) (*mappingSubject, error) {
	perm := permViewUsers
	if write {
		perm = permManageUsers
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return nil, err
	}
	st := h.Svc.Store
	return &mappingSubject{
		p:         p,
		realm:     realm,
		direct:    func(ctx context.Context) ([]*model.Role, error) { return st.UserRoles(ctx, u.ID) },
		effective: func(ctx context.Context) ([]*model.Role, error) { return h.Svc.EffectiveRoles(ctx, realm.ID, u.ID) },
		grant:     func(ctx context.Context, id string) error { return st.GrantUserRole(ctx, u.ID, id) },
		revoke:    func(ctx context.Context, id string) error { return st.RevokeUserRole(ctx, u.ID, id) },
	}, nil
}

func (h *Handler) groupSubject(r *http.Request, p *principal, write bool) (*mappingSubject, error) {
	perm := permViewUsers
	if write {
		perm = permManageUsers
	}
	realm, err := h.realmFor(r, p, perm)
	if err != nil {
		return nil, err
	}
	g, err := h.loadGroup(r, realm)
	if err != nil {
		return nil, err
	}
	st := h.Svc.Store
	direct := func(ctx context.Context) ([]*model.Role, error) { return st.GroupRoles(ctx, g.ID) }
	return &mappingSubject{
		p:      p,
		realm:  realm,
		direct: direct,
		effective: func(ctx context.Context) ([]*model.Role, error) {
			roles, err := direct(ctx)
			if err != nil {
				return nil, err
			}
			return h.Svc.ExpandComposites(ctx, realm.ID, roles)
		},
		grant:  func(ctx context.Context, id string) error { return st.GrantGroupRole(ctx, g.ID, id) },
		revoke: func(ctx context.Context, id string) error { return st.RevokeGroupRole(ctx, g.ID, id) },
	}, nil
}

func filterRoles(roles []*model.Role, clientUUID string) []*model.Role {
	out := []*model.Role{}
	for _, r := range roles {
		if r.ClientID == clientUUID {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// mappingClient resolves the {client} path value ("" for realm mappings).
func (h *Handler) mappingClient(r *http.Request, realm *model.Realm) (string, error) {
	id := r.PathValue("client")
	if id == "" {
		return "", nil
	}
	c, err := h.Svc.Store.GetClient(r.Context(), realm.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		return "", notFound("Client")
	}
	if err != nil {
		return "", err
	}
	return c.ID, nil
}

type mappingKind int

const (
	mappingDirect mappingKind = iota
	mappingComposite
	mappingAvailable
)

func (h *Handler) getMappings(w http.ResponseWriter, r *http.Request, s *mappingSubject, kind mappingKind) error {
	ctx := r.Context()
	cid, err := h.mappingClient(r, s.realm)
	if err != nil {
		return err
	}
	var roles []*model.Role
	switch kind {
	case mappingDirect:
		roles, err = s.direct(ctx)
	case mappingComposite:
		roles, err = s.effective(ctx)
	case mappingAvailable:
		var have []*model.Role
		if have, err = s.effective(ctx); err != nil {
			return err
		}
		has := map[string]bool{}
		for _, r := range have {
			has[r.ID] = true
		}
		var all []*model.Role
		if all, err = h.Svc.Store.ListRoles(ctx, s.realm.ID, cid, "", 0, -1); err != nil {
			return err
		}
		for _, role := range all {
			if !has[role.ID] {
				roles = append(roles, role)
			}
		}
	}
	if err != nil {
		return err
	}
	return ok(w, rolesToRep(filterRoles(roles, cid), s.realm.ID))
}

func (h *Handler) changeMappings(w http.ResponseWriter, r *http.Request, s *mappingSubject, add bool) error {
	cid, err := h.mappingClient(r, s.realm)
	if err != nil {
		return err
	}
	var reps []RoleRep
	if err := decode(r, &reps); err != nil {
		return err
	}
	roles, err := h.resolveRoles(r.Context(), s.realm, cid, reps)
	if err != nil {
		return err
	}
	if add && !s.noGrantCheck {
		if err := h.checkGrantable(r.Context(), s.p, s.realm, roles); err != nil {
			return err
		}
	}
	for _, role := range roles {
		if role.ClientID != cid {
			return notFound("Role")
		}
		if add {
			err = s.grant(r.Context(), role.ID)
		} else {
			err = s.revoke(r.Context(), role.ID)
		}
		if err != nil {
			return err
		}
	}
	return noContent(w)
}

// allMappings builds the GET .../role-mappings response.
func (h *Handler) allMappings(w http.ResponseWriter, r *http.Request, s *mappingSubject) error {
	ctx := r.Context()
	roles, err := s.direct(ctx)
	if err != nil {
		return err
	}
	rep := MappingsRep{}
	byClient := map[string][]*model.Role{}
	for _, role := range roles {
		if role.ClientID == "" {
			rep.RealmMappings = append(rep.RealmMappings, roleToRep(role, s.realm.ID))
		} else {
			byClient[role.ClientID] = append(byClient[role.ClientID], role)
		}
	}
	if len(byClient) > 0 {
		rep.ClientMappings = map[string]ClientMappingsRep{}
		for cid, rs := range byClient {
			c, err := h.Svc.Store.GetClient(ctx, s.realm.ID, cid)
			if err != nil {
				return err
			}
			rep.ClientMappings[c.ClientID] = ClientMappingsRep{ID: c.ID, Client: c.ClientID, Mappings: rolesToRep(rs, s.realm.ID)}
		}
	}
	return ok(w, rep)
}

func (h *Handler) userMappingsHandler(write bool, fn func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		s, err := h.userSubject(r, p, write)
		if err != nil {
			return err
		}
		return fn(w, r, s)
	}
}

func (h *Handler) groupMappingsHandler(write bool, fn func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error) handlerFunc {
	return func(w http.ResponseWriter, r *http.Request, p *principal) error {
		s, err := h.groupSubject(r, p, write)
		if err != nil {
			return err
		}
		return fn(w, r, s)
	}
}

func get(kind mappingKind, h *Handler) func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error {
	return func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error {
		return h.getMappings(w, r, s, kind)
	}
}

func change(add bool, h *Handler) func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error {
	return func(w http.ResponseWriter, r *http.Request, s *mappingSubject) error {
		return h.changeMappings(w, r, s, add)
	}
}

func (h *Handler) userRoleMappings(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, h.allMappings)(w, r, p)
}
func (h *Handler) userRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, get(mappingDirect, h))(w, r, p)
}
func (h *Handler) userRealmRolesComposite(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, get(mappingComposite, h))(w, r, p)
}
func (h *Handler) userRealmRolesAvailable(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, get(mappingAvailable, h))(w, r, p)
}
func (h *Handler) addUserRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(true, change(true, h))(w, r, p)
}
func (h *Handler) removeUserRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(true, change(false, h))(w, r, p)
}
func (h *Handler) userClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, get(mappingDirect, h))(w, r, p)
}
func (h *Handler) userClientRolesComposite(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, get(mappingComposite, h))(w, r, p)
}
func (h *Handler) userClientRolesAvailable(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(false, get(mappingAvailable, h))(w, r, p)
}
func (h *Handler) addUserClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(true, change(true, h))(w, r, p)
}
func (h *Handler) removeUserClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.userMappingsHandler(true, change(false, h))(w, r, p)
}
func (h *Handler) groupRoleMappings(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(false, h.allMappings)(w, r, p)
}
func (h *Handler) groupRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(false, get(mappingDirect, h))(w, r, p)
}
func (h *Handler) addGroupRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(true, change(true, h))(w, r, p)
}
func (h *Handler) removeGroupRealmRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(true, change(false, h))(w, r, p)
}
func (h *Handler) groupClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(false, get(mappingDirect, h))(w, r, p)
}
func (h *Handler) addGroupClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(true, change(true, h))(w, r, p)
}
func (h *Handler) removeGroupClientRoles(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.groupMappingsHandler(true, change(false, h))(w, r, p)
}
