package admin

import (
	"context"
	"errors"
	"fmt"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Import creates a realm from a Keycloak RealmRepresentation, including the
// nested roles, clients, groups and users of a realm export. Built-in
// entities (account, admin-cli, realm-management, default roles...) that
// already exist are updated rather than duplicated.
func Import(ctx context.Context, svc *service.Service, rep *RealmRep) (*model.Realm, error) {
	if rep.Realm == nil || *rep.Realm == "" {
		return nil, badRequest("Realm name cannot be empty")
	}
	realm := service.NewRealm(*rep.Realm)
	if rep.ID != nil && *rep.ID != "" {
		realm.ID = *rep.ID
	}
	applyRealmRep(realm, rep)
	realm.Settings = rep.RealmSettings
	err := svc.Store.WithTx(ctx, func(tx *store.Store) error {
		if err := svc.CreateRealm(ctx, tx, realm); err != nil {
			return err
		}
		return importContent(ctx, svc, tx, realm, rep)
	})
	if errors.Is(err, store.ErrConflict) {
		return nil, conflict(err.Error())
	}
	if err != nil {
		return nil, err
	}
	return realm, nil
}

func importContent(ctx context.Context, svc *service.Service, tx *store.Store, realm *model.Realm, rep *RealmRep) error {
	type pending struct {
		role *model.Role
		comp *CompositesRep
	}
	var composites []pending
	upsertRole := func(clientUUID string, rr RoleRep) error {
		if rr.Name == nil || *rr.Name == "" {
			return badRequest("Role name is missing")
		}
		role, err := tx.GetRoleByName(ctx, realm.ID, clientUUID, *rr.Name)
		switch {
		case err == nil:
			applyRoleRep(role, &rr)
			err = tx.UpdateRole(ctx, role)
		case errors.Is(err, store.ErrNotFound):
			role = &model.Role{ID: service.NewID(), RealmID: realm.ID, ClientID: clientUUID}
			applyRoleRep(role, &rr)
			err = tx.CreateRole(ctx, role)
		}
		if err != nil {
			return err
		}
		if rr.Composites != nil {
			composites = append(composites, pending{role, rr.Composites})
		}
		return nil
	}

	// Clients first: client roles and service accounts depend on them.
	for i := range rep.Clients {
		cr := &rep.Clients[i]
		if cr.ClientID == nil || *cr.ClientID == "" {
			return badRequest("clientId is required")
		}
		c, err := tx.GetClientByClientID(ctx, realm.ID, *cr.ClientID)
		if err == nil {
			applyClientRep(c, cr)
			if err := tx.UpdateClient(ctx, c); err != nil {
				return err
			}
			if err := svc.SyncServiceAccount(ctx, tx, c); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		c = newClient(realm.ID)
		if cr.ID != nil {
			c.ID = *cr.ID
		}
		applyClientRep(c, cr)
		if err := svc.CreateClient(ctx, tx, c); err != nil {
			return err
		}
	}

	if rep.Roles != nil {
		for _, rr := range rep.Roles.Realm {
			if err := upsertRole("", rr); err != nil {
				return err
			}
		}
		for clientID, roles := range rep.Roles.Client {
			c, err := tx.GetClientByClientID(ctx, realm.ID, clientID)
			if err != nil {
				return fmt.Errorf("roles of client %s: %w", clientID, err)
			}
			for _, rr := range roles {
				if err := upsertRole(c.ID, rr); err != nil {
					return err
				}
			}
		}
	}
	for _, p := range composites {
		if err := addCompositesByName(ctx, tx, realm, p.role, p.comp); err != nil {
			return err
		}
	}
	if rep.DefaultRole != nil && rep.DefaultRole.Name != nil {
		// The export names its own default role (e.g. when a realm is
		// imported under a new name): use it and drop the generated one.
		if role, err := tx.GetRoleByName(ctx, realm.ID, "", *rep.DefaultRole.Name); err == nil && role.ID != realm.DefaultRoleID {
			generated := realm.DefaultRoleID
			realm.DefaultRoleID = role.ID
			if err := tx.UpdateRealm(ctx, realm); err != nil {
				return err
			}
			if err := tx.DeleteRole(ctx, generated); err != nil {
				return err
			}
		}
	}

	for i := range rep.Groups {
		if err := importGroup(ctx, tx, realm, "", &rep.Groups[i]); err != nil {
			return err
		}
	}
	for i := range rep.Users {
		if _, err := importUser(ctx, svc, tx, realm, &rep.Users[i]); err != nil {
			return err
		}
	}
	return nil
}

func importGroup(ctx context.Context, tx *store.Store, realm *model.Realm, parentID string, gr *GroupRep) error {
	if gr.Name == nil || *gr.Name == "" {
		return badRequest("Group name is missing")
	}
	g := &model.Group{ID: service.NewID(), RealmID: realm.ID, ParentID: parentID, Name: *gr.Name, Attributes: gr.Attributes}
	if err := tx.CreateGroup(ctx, g); err != nil {
		return err
	}
	if err := grantRoles(ctx, tx, realm, gr.RealmRoles, gr.ClientRoles, func(id string) error {
		return tx.GrantGroupRole(ctx, g.ID, id)
	}); err != nil {
		return err
	}
	for i := range gr.SubGroups {
		if err := importGroup(ctx, tx, realm, g.ID, &gr.SubGroups[i]); err != nil {
			return err
		}
	}
	return nil
}

// importUser creates a user from a representation, with its credentials,
// role mappings and group memberships. It backs both POST /users and realm import.
func importUser(ctx context.Context, svc *service.Service, tx *store.Store, realm *model.Realm, ur *UserRep) (*model.User, error) {
	u := &model.User{RealmID: realm.ID}
	if ur.ID != nil {
		u.ID = *ur.ID
	}
	applyUserRep(u, ur)
	if ur.CreatedTimestamp != nil {
		u.CreatedTimestamp = *ur.CreatedTimestamp
	}

	existing := false
	if ur.ServiceAccountClientID != nil && *ur.ServiceAccountClientID != "" {
		c, err := tx.GetClientByClientID(ctx, realm.ID, *ur.ServiceAccountClientID)
		if err != nil {
			return nil, fmt.Errorf("service account client %s: %w", *ur.ServiceAccountClientID, err)
		}
		// The service account user may already exist (created with its client).
		if sa, err := tx.GetServiceAccountUser(ctx, c.ID); err == nil {
			sa.Enabled = u.Enabled
			sa.Attributes = u.Attributes
			if err := tx.UpdateUser(ctx, sa); err != nil {
				return nil, err
			}
			u, existing = sa, true
		} else {
			u.ServiceAccountClientID = c.ID
		}
	}
	if !existing {
		if err := svc.CreateUser(ctx, tx, u); err != nil {
			return nil, err
		}
	}

	for _, cr := range ur.Credentials {
		if cr.Type != "" && cr.Type != model.CredentialPassword {
			continue // only passwords are supported
		}
		switch {
		case cr.Value != "":
			if err := svc.SetPassword(ctx, tx, u, cr.Value, cr.Temporary != nil && *cr.Temporary); err != nil {
				return nil, err
			}
		case cr.SecretData != "" && cr.CredentialData != "":
			// Pre-hashed credential from a Keycloak export.
			created := cr.CreatedDate
			if created == 0 {
				created = svc.Now().UnixMilli()
			}
			if err := tx.CreateCredential(ctx, &model.Credential{ID: service.NewID(), UserID: u.ID, Type: model.CredentialPassword,
				UserLabel: cr.UserLabel, SecretData: cr.SecretData, CredentialData: cr.CredentialData, CreatedDate: created, Priority: 10}); err != nil {
				return nil, err
			}
		}
	}

	if err := grantRoles(ctx, tx, realm, ur.RealmRoles, ur.ClientRoles, func(id string) error {
		return tx.GrantUserRole(ctx, u.ID, id)
	}); err != nil {
		return nil, err
	}

	if len(ur.Groups) > 0 {
		all, err := tx.ListAllGroups(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		t := &groupTree{paths: groupPaths(all), children: map[string][]*model.Group{}}
		for _, g := range all {
			t.children[g.ParentID] = append(t.children[g.ParentID], g)
		}
		for _, path := range ur.Groups {
			g := t.find(splitPath(path))
			if g == nil {
				return nil, badRequest("Group " + path + " not found")
			}
			if err := tx.AddUserToGroup(ctx, u.ID, g.ID); err != nil {
				return nil, err
			}
		}
	}
	return u, nil
}

// grantRoles maps realm and client roles given by name.
func grantRoles(ctx context.Context, tx *store.Store, realm *model.Realm, realmRoles []string, clientRoles map[string][]string, grant func(roleID string) error) error {
	for _, name := range realmRoles {
		role, err := tx.GetRoleByName(ctx, realm.ID, "", name)
		if err != nil {
			return roleNotFound(err, name)
		}
		if err := grant(role.ID); err != nil {
			return err
		}
	}
	for clientID, names := range clientRoles {
		c, err := tx.GetClientByClientID(ctx, realm.ID, clientID)
		if err != nil {
			return roleNotFound(err, clientID)
		}
		for _, name := range names {
			role, err := tx.GetRoleByName(ctx, realm.ID, c.ID, name)
			if err != nil {
				return roleNotFound(err, clientID+"/"+name)
			}
			if err := grant(role.ID); err != nil {
				return err
			}
		}
	}
	return nil
}
