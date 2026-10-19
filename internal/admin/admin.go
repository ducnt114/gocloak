// Package admin implements a Keycloak compatible admin REST API under
// /admin/realms. Requests are authorized with bearer tokens issued by
// gocloak itself, using the same roles Keycloak uses: the master realm
// "admin" role grants access to every realm, and the realm-management
// client roles (realm-admin, manage-users, view-clients, ...) grant access
// to their own realm.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Handler serves the admin API.
type Handler struct {
	Svc  *service.Service
	URLs oidc.URLs
	Log  *slog.Logger
}

// httpError is an error with an HTTP status, rendered as Keycloak does.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errStatus(status int, format string, a ...any) error {
	return &httpError{status: status, msg: fmt.Sprintf(format, a...)}
}

func notFound(what string) error    { return errStatus(http.StatusNotFound, "%s not found", what) }
func badRequest(msg string) error   { return errStatus(http.StatusBadRequest, "%s", msg) }
func conflict(msg string) error     { return errStatus(http.StatusConflict, "%s", msg) }
func forbidden() error              { return errStatus(http.StatusForbidden, "HTTP 403 Forbidden") }
func unauthorized(msg string) error { return errStatus(http.StatusUnauthorized, "%s", msg) }

// Permissions, named after the realm-management client roles.
const (
	permViewRealm     = "view-realm"
	permManageRealm   = "manage-realm"
	permViewUsers     = "view-users"
	permQueryUsers    = "query-users"
	permManageUsers   = "manage-users"
	permViewClients   = "view-clients"
	permQueryClients  = "query-clients"
	permManageClients = "manage-clients"
	permCreateClient  = "create-client"
	permQueryGroups   = "query-groups"
)

// implied lists the permissions that also grant the key permission.
var implied = map[string][]string{
	permViewRealm:    {permManageRealm},
	permViewUsers:    {permManageUsers},
	permQueryUsers:   {permViewUsers, permManageUsers},
	permQueryGroups:  {permViewUsers, permManageUsers},
	permViewClients:  {permManageClients},
	permQueryClients: {permViewClients, permManageClients},
	permCreateClient: {permManageClients},
}

// principal is the authenticated caller.
type principal struct {
	realm       *model.Realm // realm that issued the token
	user        *model.User
	superAdmin  bool            // master realm "admin"
	createRealm bool            // master realm "create-realm"
	mgmtRoles   map[string]bool // realm-management roles in principal's realm
	mgmtClient  string          // realm-management client UUID of principal's realm
}

// can reports whether the caller holds perm in the realm target.
func (p *principal) can(target *model.Realm, perm string) bool {
	if p.superAdmin {
		return true
	}
	if target == nil || target.ID != p.realm.ID {
		return false
	}
	if p.mgmtRoles[perm] {
		return true
	}
	for _, alt := range implied[perm] {
		if p.mgmtRoles[alt] {
			return true
		}
	}
	return false
}

func (p *principal) require(target *model.Realm, perm string) error {
	if !p.can(target, perm) {
		return forbidden()
	}
	return nil
}

// checkGrantable prevents privilege escalation: as in Keycloak, an admin
// may only hand out admin roles (realm-management client roles, the master
// admin roles, or composites containing them) that they hold themselves.
func (h *Handler) checkGrantable(ctx context.Context, p *principal, realm *model.Realm, roles []*model.Role) error {
	if p.superAdmin || len(roles) == 0 {
		return nil
	}
	expanded, err := h.Svc.ExpandComposites(ctx, realm.ID, roles)
	if err != nil {
		return err
	}
	for _, r := range expanded {
		switch {
		case r.ClientID != "" && r.ClientID == p.mgmtClient && !p.mgmtRoles[r.Name],
			r.ClientID == "" && realm.Name == service.MasterRealm && (r.Name == service.AdminRole || r.Name == service.CreateRealmRole):
			return errStatus(http.StatusForbidden, "You may not grant the role %s that you do not have yourself", r.Name)
		}
	}
	return nil
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, p *principal) error

// authenticate validates the bearer token and resolves the caller's roles
// from the database (not from the token), so revoked roles apply at once.
func (h *Handler) authenticate(r *http.Request) (*principal, error) {
	ctx := r.Context()
	a := r.Header.Get("Authorization")
	if len(a) < 8 || !strings.EqualFold(a[:7], "bearer ") {
		return nil, unauthorized("HTTP 401 Unauthorized")
	}
	tok := strings.TrimSpace(a[7:])
	_, claims, err := jwt.Parse(tok)
	if err != nil {
		return nil, unauthorized("HTTP 401 Unauthorized")
	}
	iss := claims.String("iss")
	i := strings.LastIndex(iss, "/realms/")
	if i < 0 {
		return nil, unauthorized("HTTP 401 Unauthorized")
	}
	realm, err := h.Svc.Store.GetRealmByName(ctx, iss[i+len("/realms/"):])
	if err != nil {
		return nil, unauthorized("HTTP 401 Unauthorized")
	}
	vt, err := h.Svc.VerifyToken(ctx, realm, tok, h.URLs.Issuer(r, realm.Name), service.TokenBearer)
	if err != nil || vt.User == nil {
		if err != nil && !errors.Is(err, service.ErrInvalidToken) {
			return nil, err
		}
		return nil, unauthorized("HTTP 401 Unauthorized")
	}
	roles, err := h.Svc.EffectiveRoles(ctx, realm.ID, vt.User.ID)
	if err != nil {
		return nil, err
	}
	mgmt, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, service.RealmManagementClient)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	p := &principal{realm: realm, user: vt.User, mgmtRoles: map[string]bool{}}
	if mgmt != nil {
		p.mgmtClient = mgmt.ID
	}
	for _, role := range roles {
		switch {
		case role.ClientID == "" && realm.Name == service.MasterRealm && role.Name == service.AdminRole:
			p.superAdmin = true
		case role.ClientID == "" && realm.Name == service.MasterRealm && role.Name == service.CreateRealmRole:
			p.createRealm = true
		case mgmt != nil && role.ClientID == mgmt.ID:
			p.mgmtRoles[role.Name] = true
		}
	}
	return p, nil
}

func (h *Handler) wrap(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := h.authenticate(r)
		if err == nil {
			err = fn(w, r, p)
		}
		if err != nil {
			h.writeError(w, r, err)
		}
	}
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	switch {
	case errors.As(err, &he):
	case errors.Is(err, store.ErrNotFound):
		he = &httpError{http.StatusNotFound, "Resource not found"}
	case errors.Is(err, store.ErrConflict):
		msg := strings.TrimPrefix(err.Error(), store.ErrConflict.Error()+": ")
		if strings.Contains(msg, "constraint failed") {
			msg = "Conflict detected. See logs for details"
		}
		he = &httpError{http.StatusConflict, msg}
	case errors.Is(err, service.ErrValidation):
		he = &httpError{http.StatusBadRequest, strings.TrimPrefix(err.Error(), service.ErrValidation.Error()+": ")}
	default:
		h.Log.Error("admin api error", "method", r.Method, "path", r.URL.Path, "err", err)
		he = &httpError{http.StatusInternalServerError, "unknown_error"}
	}
	body := map[string]string{"error": he.msg}
	if he.status == http.StatusBadRequest || he.status == http.StatusConflict {
		body = map[string]string{"errorMessage": he.msg}
	}
	if he.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	writeJSON(w, he.status, body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		json.NewEncoder(w).Encode(v)
	}
}

func ok(w http.ResponseWriter, v any) error {
	writeJSON(w, http.StatusOK, v)
	return nil
}

func noContent(w http.ResponseWriter) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func created(w http.ResponseWriter, r *http.Request, id string) error {
	w.Header().Set("Location", strings.TrimSuffix(requestURL(r), "/")+"/"+id)
	w.WriteHeader(http.StatusCreated)
	return nil
}

func requestURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + r.URL.Path
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 10<<20))
	if err := dec.Decode(v); err != nil {
		return badRequest("Invalid JSON: " + err.Error())
	}
	return nil
}

func intParam(r *http.Request, name string, def int) int {
	if v := r.URL.Query().Get(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

func boolParam(r *http.Request, name string) *bool {
	switch r.URL.Query().Get(name) {
	case "true":
		return ptr(true)
	case "false":
		return ptr(false)
	}
	return nil
}

// targetRealm loads the realm named in the URL.
func (h *Handler) targetRealm(r *http.Request) (*model.Realm, error) {
	realm, err := h.Svc.Store.GetRealmByName(r.Context(), r.PathValue("realm"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Realm")
	}
	return realm, err
}

// realmFor loads the target realm and checks perm on it. A caller without
// any access gets 404-like 403s, as in Keycloak.
func (h *Handler) realmFor(r *http.Request, p *principal, perm string) (*model.Realm, error) {
	realm, err := h.targetRealm(r)
	if err != nil {
		if !p.superAdmin {
			return nil, forbidden()
		}
		return nil, err
	}
	if err := p.require(realm, perm); err != nil {
		return nil, err
	}
	return realm, nil
}

// ---------------------------------------------------------------- routes

// Register adds the admin routes to mux.
func (h *Handler) Register(mux *http.ServeMux) {
	const R = "/admin/realms/{realm}"
	routes := []struct {
		pattern string
		fn      handlerFunc
	}{
		// realms
		{"GET /admin/realms", h.listRealms},
		{"POST /admin/realms", h.createRealm},
		{"GET " + R, h.getRealm},
		{"PUT " + R, h.updateRealm},
		{"DELETE " + R, h.deleteRealm},
		{"POST " + R + "/logout-all", h.logoutAll},
		{"GET " + R + "/keys", h.getKeys},
		{"POST " + R + "/partial-export", h.partialExport},
		{"GET " + R + "/default-default-client-scopes", h.emptyList},
		{"GET " + R + "/client-scopes", h.emptyList},

		// users
		{"GET " + R + "/users", h.listUsers},
		{"POST " + R + "/users", h.createUser},
		{"GET " + R + "/users/count", h.countUsers},
		{"GET " + R + "/users/{id}", h.getUser},
		{"PUT " + R + "/users/{id}", h.updateUser},
		{"DELETE " + R + "/users/{id}", h.deleteUser},
		{"PUT " + R + "/users/{id}/reset-password", h.resetPassword},
		{"GET " + R + "/users/{id}/credentials", h.listCredentials},
		{"DELETE " + R + "/users/{id}/credentials/{credId}", h.deleteCredential},
		{"GET " + R + "/users/{id}/sessions", h.userSessions},
		{"POST " + R + "/users/{id}/logout", h.logoutUser},
		{"GET " + R + "/users/{id}/groups", h.userGroups},
		{"GET " + R + "/users/{id}/groups/count", h.userGroupsCount},
		{"PUT " + R + "/users/{id}/groups/{groupId}", h.joinGroup},
		{"DELETE " + R + "/users/{id}/groups/{groupId}", h.leaveGroup},
		{"GET " + R + "/users/{id}/role-mappings", h.userRoleMappings},
		{"GET " + R + "/users/{id}/role-mappings/realm", h.userRealmRoles},
		{"POST " + R + "/users/{id}/role-mappings/realm", h.addUserRealmRoles},
		{"DELETE " + R + "/users/{id}/role-mappings/realm", h.removeUserRealmRoles},
		{"GET " + R + "/users/{id}/role-mappings/realm/composite", h.userRealmRolesComposite},
		{"GET " + R + "/users/{id}/role-mappings/realm/available", h.userRealmRolesAvailable},
		{"GET " + R + "/users/{id}/role-mappings/clients/{client}", h.userClientRoles},
		{"POST " + R + "/users/{id}/role-mappings/clients/{client}", h.addUserClientRoles},
		{"DELETE " + R + "/users/{id}/role-mappings/clients/{client}", h.removeUserClientRoles},
		{"GET " + R + "/users/{id}/role-mappings/clients/{client}/composite", h.userClientRolesComposite},
		{"GET " + R + "/users/{id}/role-mappings/clients/{client}/available", h.userClientRolesAvailable},

		// clients
		{"GET " + R + "/clients", h.listClients},
		{"POST " + R + "/clients", h.createClient},
		{"GET " + R + "/clients/{id}", h.getClient},
		{"PUT " + R + "/clients/{id}", h.updateClient},
		{"DELETE " + R + "/clients/{id}", h.deleteClient},
		{"GET " + R + "/clients/{id}/client-secret", h.getClientSecret},
		{"POST " + R + "/clients/{id}/client-secret", h.regenerateClientSecret},
		{"GET " + R + "/clients/{id}/service-account-user", h.serviceAccountUser},
		{"GET " + R + "/clients/{id}/user-sessions", h.clientSessions},
		{"GET " + R + "/clients/{id}/roles", h.listClientRoles},
		{"POST " + R + "/clients/{id}/roles", h.createClientRole},
		{"GET " + R + "/clients/{id}/roles/{roleName}", h.getClientRole},
		{"PUT " + R + "/clients/{id}/roles/{roleName}", h.updateClientRole},
		{"DELETE " + R + "/clients/{id}/roles/{roleName}", h.deleteClientRole},
		{"GET " + R + "/clients/{id}/roles/{roleName}/composites", h.clientRoleComposites},
		{"POST " + R + "/clients/{id}/roles/{roleName}/composites", h.addClientRoleComposites},
		{"DELETE " + R + "/clients/{id}/roles/{roleName}/composites", h.removeClientRoleComposites},
		{"GET " + R + "/clients/{id}/roles/{roleName}/users", h.clientRoleUsers},

		// realm roles
		{"GET " + R + "/roles", h.listRealmRoles},
		{"POST " + R + "/roles", h.createRealmRole},
		{"GET " + R + "/roles/{roleName}", h.getRealmRole},
		{"PUT " + R + "/roles/{roleName}", h.updateRealmRole},
		{"DELETE " + R + "/roles/{roleName}", h.deleteRealmRole},
		{"GET " + R + "/roles/{roleName}/composites", h.realmRoleComposites},
		{"POST " + R + "/roles/{roleName}/composites", h.addRealmRoleComposites},
		{"DELETE " + R + "/roles/{roleName}/composites", h.removeRealmRoleComposites},
		{"GET " + R + "/roles/{roleName}/users", h.realmRoleUsers},
		{"GET " + R + "/roles-by-id/{roleId}", h.getRoleByID},
		{"PUT " + R + "/roles-by-id/{roleId}", h.updateRoleByID},
		{"DELETE " + R + "/roles-by-id/{roleId}", h.deleteRoleByID},

		// groups
		{"GET " + R + "/groups", h.listGroups},
		{"POST " + R + "/groups", h.createGroup},
		{"GET " + R + "/groups/count", h.countGroups},
		{"GET " + R + "/group-by-path/{path...}", h.groupByPath},
		{"GET " + R + "/groups/{id}", h.getGroup},
		{"PUT " + R + "/groups/{id}", h.updateGroup},
		{"DELETE " + R + "/groups/{id}", h.deleteGroup},
		{"GET " + R + "/groups/{id}/children", h.groupChildren},
		{"POST " + R + "/groups/{id}/children", h.createChildGroup},
		{"GET " + R + "/groups/{id}/members", h.groupMembers},
		{"GET " + R + "/groups/{id}/role-mappings", h.groupRoleMappings},
		{"GET " + R + "/groups/{id}/role-mappings/realm", h.groupRealmRoles},
		{"POST " + R + "/groups/{id}/role-mappings/realm", h.addGroupRealmRoles},
		{"DELETE " + R + "/groups/{id}/role-mappings/realm", h.removeGroupRealmRoles},
		{"GET " + R + "/groups/{id}/role-mappings/clients/{client}", h.groupClientRoles},
		{"POST " + R + "/groups/{id}/role-mappings/clients/{client}", h.addGroupClientRoles},
		{"DELETE " + R + "/groups/{id}/role-mappings/clients/{client}", h.removeGroupClientRoles},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pattern, h.wrap(rt.fn))
	}
}

func (h *Handler) emptyList(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permViewRealm); err != nil {
		return err
	}
	return ok(w, []any{})
}

// withTx is a small helper for handlers that write several rows.
func (h *Handler) withTx(ctx context.Context, fn func(tx *store.Store) error) error {
	return h.Svc.Store.WithTx(ctx, fn)
}
