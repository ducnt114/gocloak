package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ducnt114/gocloak/internal/authz"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// UMAProtectionRole is the client role of a resource server that lets its
// service account use the protection API.
const UMAProtectionRole = "uma_protection"

// EnableAuthorization makes a client a resource server with Keycloak's
// defaults: a default resource, the default (granting) policy and a
// permission applying it to the default resource type.
func (s *Service) EnableAuthorization(ctx context.Context, st *store.Store, c *model.Client) error {
	if _, err := st.GetResourceServer(ctx, c.ID); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if c.PublicClient || c.BearerOnly {
		return validationf("Authorization services can only be enabled on confidential clients")
	}
	if !c.ServiceAccountsEnabled {
		c.ServiceAccountsEnabled = true
		if err := st.UpdateClient(ctx, c); err != nil {
			return err
		}
		if err := s.SyncServiceAccount(ctx, st, c); err != nil {
			return err
		}
	}
	rs := &model.ResourceServer{ClientID: c.ID, RealmID: c.RealmID, PolicyEnforcementMode: authz.Enforcing,
		DecisionStrategy: authz.Unanimous, AllowRemoteResourceManagement: true}
	if err := st.CreateResourceServer(ctx, rs); err != nil {
		return err
	}
	resourceType := "urn:" + c.ClientID + ":resources:default"
	if err := st.CreateAuthzResource(ctx, &model.AuthzResource{ID: NewID(), ResourceServerID: c.ID, Name: "Default Resource",
		Type: resourceType, Owner: c.ID, URIs: []string{"/*"}}); err != nil {
		return err
	}
	policy := &model.AuthzPolicy{ID: NewID(), ResourceServerID: c.ID, Name: "Default Policy", Type: "js", Logic: authz.Positive,
		DecisionStrategy: authz.Affirmative, Description: "A policy that grants access only for users within this realm",
		Config: map[string]string{"code": authz.DefaultPolicyCode}}
	if err := st.CreateAuthzPolicy(ctx, policy); err != nil {
		return err
	}
	if err := st.CreateAuthzPolicy(ctx, &model.AuthzPolicy{ID: NewID(), ResourceServerID: c.ID, Name: "Default Permission",
		Type: authz.TypeResource, Logic: authz.Positive, DecisionStrategy: authz.Unanimous,
		Description: "A permission that applies to the default resource type", Config: map[string]string{"defaultResourceType": resourceType},
		AssociatedIDs: []string{policy.ID}}); err != nil {
		return err
	}
	return s.grantUMAProtection(ctx, st, c)
}

// grantUMAProtection creates the uma_protection role of a resource server
// and grants it to its service account.
func (s *Service) grantUMAProtection(ctx context.Context, st *store.Store, c *model.Client) error {
	role, err := st.GetRoleByName(ctx, c.RealmID, c.ID, UMAProtectionRole)
	if errors.Is(err, store.ErrNotFound) {
		role = &model.Role{ID: NewID(), RealmID: c.RealmID, ClientID: c.ID, Name: UMAProtectionRole}
		err = st.CreateRole(ctx, role)
	}
	if err != nil {
		return err
	}
	sa, err := st.GetServiceAccountUser(ctx, c.ID)
	if err != nil {
		return err
	}
	return st.GrantUserRole(ctx, sa.ID, role.ID)
}

// DisableAuthorization removes a client's resource server.
func (s *Service) DisableAuthorization(ctx context.Context, st *store.Store, c *model.Client) error {
	return st.DeleteResourceServer(ctx, c.ID)
}

// LoadAuthz loads a resource server with its resources, scopes, policies
// and permission tickets.
func (s *Service) LoadAuthz(ctx context.Context, st *store.Store, clientUUID string) (*authz.Data, error) {
	rs, err := st.GetResourceServer(ctx, clientUUID)
	if err != nil {
		return nil, err
	}
	d := &authz.Data{Server: rs}
	if d.Resources, err = st.ListAuthzResources(ctx, rs.ClientID); err != nil {
		return nil, err
	}
	if d.Scopes, err = st.ListAuthzScopes(ctx, rs.ClientID); err != nil {
		return nil, err
	}
	if d.Policies, err = st.ListAuthzPolicies(ctx, rs.ClientID); err != nil {
		return nil, err
	}
	if d.Tickets, err = st.ListPermissionTickets(ctx, rs.ClientID); err != nil {
		return nil, err
	}
	d.Index()
	return d, nil
}

// AuthzIdentity builds the identity of a user for policy evaluation: its
// effective roles and groups, the client the token was issued to, the
// client scopes of the token and its claims.
func (s *Service) AuthzIdentity(ctx context.Context, realm *model.Realm, u *model.User, clientUUID string, claims map[string]any) (*authz.Identity, error) {
	id := &authz.Identity{UserID: u.ID, Roles: map[string]bool{}, ClientID: clientUUID, ClientScopes: map[string]bool{},
		Claims: claims, Attributes: map[string][]string{}, Now: s.Now()}
	roles, err := s.EffectiveRoles(ctx, realm.ID, u.ID)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		id.Roles[r.ID] = true
	}
	groups, err := s.Store.UserGroups(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	all, err := s.Store.ListAllGroups(ctx, realm.ID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.Group{}
	for _, g := range all {
		byID[g.ID] = g
	}
	for _, g := range groups {
		path := ""
		for x := g; x != nil; x = byID[x.ParentID] {
			path = "/" + x.Name + path
			if x.ParentID == "" {
				break
			}
		}
		id.Groups = append(id.Groups, authz.Group{ID: g.ID, Path: path})
	}
	if scope, ok := claims["scope"].(string); ok {
		names := map[string]bool{}
		for _, n := range strings.Fields(scope) {
			names[n] = true
		}
		scopes, err := s.Store.ListClientScopes(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		for _, cs := range scopes {
			if names[cs.Name] {
				id.ClientScopes[cs.ID] = true
			}
		}
	}
	return id, nil
}

// PolicyConfigList encodes a list for a policy config entry.
func PolicyConfigList(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
