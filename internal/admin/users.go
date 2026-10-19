package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

func (h *Handler) loadUser(r *http.Request, realm *model.Realm) (*model.User, error) {
	u, err := h.Svc.Store.GetUser(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("User")
	}
	return u, err
}

func userQuery(r *http.Request) store.UserQuery {
	q := r.URL.Query()
	uq := store.UserQuery{
		Search: q.Get("search"), Username: q.Get("username"), Email: q.Get("email"),
		FirstName: q.Get("firstName"), LastName: q.Get("lastName"), Enabled: boolParam(r, "enabled"),
		Exact: q.Get("exact") == "true", First: intParam(r, "first", 0), Max: intParam(r, "max", 100),
	}
	// q=key1:value1 key2:value2 matches exact attribute values.
	for _, pair := range strings.Fields(q.Get("q")) {
		if k, v, ok := strings.Cut(pair, ":"); ok && k != "" {
			if uq.Attributes == nil {
				uq.Attributes = map[string]string{}
			}
			uq.Attributes[k] = v
		}
	}
	return uq
}

func usersToRep(users []*model.User) []UserRep {
	out := make([]UserRep, 0, len(users))
	for _, u := range users {
		out = append(out, userToRep(u))
	}
	return out
}

// briefUsers drops attributes, as Keycloak's briefRepresentation does.
func briefUsers(reps []UserRep) []UserRep {
	for i := range reps {
		reps[i].Attributes = nil
	}
	return reps
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryUsers)
	if err != nil {
		return err
	}
	users, err := h.Svc.Store.SearchUsers(r.Context(), realm.ID, userQuery(r))
	if err != nil {
		return err
	}
	if r.URL.Query().Get("briefRepresentation") == "true" {
		return ok(w, briefUsers(usersToRep(users)))
	}
	return ok(w, usersToRep(users))
}

func (h *Handler) countUsers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryUsers)
	if err != nil {
		return err
	}
	n, err := h.Svc.Store.CountUsers(r.Context(), realm.ID, userQuery(r))
	if err != nil {
		return err
	}
	return ok(w, n)
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	var rep UserRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Username == nil || *rep.Username == "" {
		// Keycloak falls back to the email when it is used as username.
		if rep.Email == nil || *rep.Email == "" {
			return badRequest("User name is missing")
		}
		rep.Username = rep.Email
	}
	granted, err := h.repRoles(r.Context(), realm, rep.RealmRoles, rep.ClientRoles, rep.Groups)
	if err != nil {
		return err
	}
	if err := h.checkGrantable(r.Context(), p, realm, granted); err != nil {
		return err
	}
	var u *model.User
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		var err error
		u, err = importUser(r.Context(), h.Svc, tx, realm, &rep)
		return err
	})
	if err != nil {
		return err
	}
	return created(w, r, u.ID)
}

func (h *Handler) getUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	return ok(w, userToRep(u))
}

func (h *Handler) updateUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	var rep UserRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	applyUserRep(u, &rep)
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		if err := h.Svc.UpdateUser(r.Context(), tx, u); err != nil {
			return err
		}
		for _, c := range rep.Credentials {
			if c.Type == model.CredentialPassword && c.Value != "" {
				if err := h.Svc.SetPassword(r.Context(), tx, u, c.Value, c.Temporary != nil && *c.Temporary); err != nil {
					return err
				}
			}
		}
		if !u.Enabled {
			return tx.DeleteUserSessionsOfUser(r.Context(), u.ID)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	if u.ServiceAccountClientID != "" {
		return badRequest("Service account user cannot be deleted")
	}
	if err := h.Svc.Store.DeleteUser(r.Context(), realm.ID, u.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) resetPassword(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	var rep CredentialRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Type != "" && rep.Type != model.CredentialPassword {
		return badRequest("Unsupported credential type")
	}
	if rep.Value == "" {
		return badRequest("Password must not be empty")
	}
	temporary := rep.Temporary == nil || *rep.Temporary // Keycloak's default is temporary
	err = h.withTx(r.Context(), func(tx *store.Store) error {
		return h.Svc.SetPassword(r.Context(), tx, u, rep.Value, temporary)
	})
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) listCredentials(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	creds, err := h.Svc.Store.ListCredentials(r.Context(), u.ID)
	if err != nil {
		return err
	}
	out := []CredentialRep{}
	for _, c := range creds {
		// Secrets are never returned; credentialData only holds hash parameters.
		out = append(out, CredentialRep{ID: c.ID, Type: c.Type, UserLabel: c.UserLabel, CreatedDate: c.CreatedDate,
			CredentialData: c.CredentialData, Priority: c.Priority})
	}
	return ok(w, out)
}

func (h *Handler) deleteCredential(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteCredential(r.Context(), u.ID, r.PathValue("credId")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("Credential")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) sessionsToRep(r *http.Request, realm *model.Realm, sessions []*model.UserSession, users map[string]*model.User) ([]UserSessionRep, error) {
	out := []UserSessionRep{}
	clientIDs := map[string]string{}
	for _, s := range sessions {
		if !h.Svc.SessionValid(realm, s) {
			continue
		}
		u := users[s.UserID]
		if u == nil {
			var err error
			if u, err = h.Svc.Store.GetUser(r.Context(), realm.ID, s.UserID); err != nil {
				return nil, err
			}
			users[s.UserID] = u
		}
		rep := UserSessionRep{ID: s.ID, Username: u.Username, UserID: u.ID, IPAddress: s.IPAddress,
			Start: s.Started.UnixMilli(), LastAccess: s.LastRefresh.UnixMilli(), RememberMe: s.RememberMe,
			Clients: map[string]string{}}
		for cid := range s.Clients {
			name, ok := clientIDs[cid]
			if !ok {
				if c, err := h.Svc.Store.GetClient(r.Context(), realm.ID, cid); err == nil {
					name = c.ClientID
				}
				clientIDs[cid] = name
			}
			rep.Clients[cid] = name
		}
		out = append(out, rep)
	}
	return out, nil
}

func (h *Handler) userSessions(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	sessions, err := h.Svc.Store.ListUserSessions(r.Context(), u.ID)
	if err != nil {
		return err
	}
	out, err := h.sessionsToRep(r, realm, sessions, map[string]*model.User{u.ID: u})
	if err != nil {
		return err
	}
	return ok(w, out)
}

func (h *Handler) logoutUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteUserSessionsOfUser(r.Context(), u.ID); err != nil {
		return err
	}
	return noContent(w)
}

// ---------------------------------------------------------------- group membership

func (h *Handler) userGroups(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	groups, err := h.Svc.Store.UserGroups(r.Context(), u.ID)
	if err != nil {
		return err
	}
	all, err := h.Svc.Store.ListAllGroups(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	paths := groupPaths(all)
	out := []GroupRep{}
	for _, g := range groups {
		out = append(out, groupToRep(g, paths[g.ID], 0))
	}
	return ok(w, out)
}

func (h *Handler) userGroupsCount(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	groups, err := h.Svc.Store.UserGroups(r.Context(), u.ID)
	if err != nil {
		return err
	}
	return ok(w, map[string]int{"count": len(groups)})
}

func (h *Handler) membership(w http.ResponseWriter, r *http.Request, p *principal, join bool) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	g, err := h.Svc.Store.GetGroup(r.Context(), realm.ID, r.PathValue("groupId"))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("Group")
		}
		return err
	}
	if join {
		roles, err := h.groupRolesWithAncestors(r.Context(), realm, g)
		if err != nil {
			return err
		}
		if err := h.checkGrantable(r.Context(), p, realm, roles); err != nil {
			return err
		}
		err = h.Svc.Store.AddUserToGroup(r.Context(), u.ID, g.ID)
	} else {
		err = h.Svc.Store.RemoveUserFromGroup(r.Context(), u.ID, g.ID)
	}
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) joinGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.membership(w, r, p, true)
}

func (h *Handler) leaveGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.membership(w, r, p, false)
}

// groupRolesWithAncestors returns the roles mapped to g and its parents,
// which a member of g inherits.
func (h *Handler) groupRolesWithAncestors(ctx context.Context, realm *model.Realm, g *model.Group) ([]*model.Role, error) {
	var out []*model.Role
	for depth := 0; g != nil && depth < 100; depth++ {
		roles, err := h.Svc.Store.GroupRoles(ctx, g.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, roles...)
		if g.ParentID == "" {
			break
		}
		if g, err = h.Svc.Store.GetGroup(ctx, realm.ID, g.ParentID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// repRoles resolves the roles a user representation would grant, so they
// can be checked before the user is created. Unknown names are left for the
// import itself to report.
func (h *Handler) repRoles(ctx context.Context, realm *model.Realm, realmRoles []string, clientRoles map[string][]string, groups []string) ([]*model.Role, error) {
	st := h.Svc.Store
	var out []*model.Role
	for _, name := range realmRoles {
		if role, err := st.GetRoleByName(ctx, realm.ID, "", name); err == nil {
			out = append(out, role)
		}
	}
	for clientID, names := range clientRoles {
		c, err := st.GetClientByClientID(ctx, realm.ID, clientID)
		if err != nil {
			continue
		}
		for _, name := range names {
			if role, err := st.GetRoleByName(ctx, realm.ID, c.ID, name); err == nil {
				out = append(out, role)
			}
		}
	}
	if len(groups) > 0 {
		t, err := h.groupTree(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		for _, path := range groups {
			if g := t.find(splitPath(path)); g != nil {
				roles, err := h.groupRolesWithAncestors(ctx, realm, g)
				if err != nil {
					return nil, err
				}
				out = append(out, roles...)
			}
		}
	}
	return out, nil
}
