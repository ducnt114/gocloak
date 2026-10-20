package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/authz"
	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// UMA 2.0 and the authorization services: the uma-ticket grant (RPTs
// and decisions), the protection API of resource servers, and the UMA
// discovery document.

const grantUMATicket = "urn:ietf:params:oauth:grant-type:uma-ticket"

func errAccessDenied(desc string) *oauthError {
	return &oauthError{http.StatusForbidden, "access_denied", desc}
}

func (h *Handler) registerUMA(mux *http.ServeMux) {
	mux.HandleFunc("GET /realms/{realm}/.well-known/uma2-configuration", h.umaConfiguration)
	const P = "/realms/{realm}/authz/protection"
	mux.HandleFunc("GET "+P+"/resource_set", h.protection(h.listResourceSet))
	mux.HandleFunc("POST "+P+"/resource_set", h.protection(h.createResourceSet))
	mux.HandleFunc("GET "+P+"/resource_set/{id}", h.protection(h.getResourceSet))
	mux.HandleFunc("PUT "+P+"/resource_set/{id}", h.protection(h.updateResourceSet))
	mux.HandleFunc("DELETE "+P+"/resource_set/{id}", h.protection(h.deleteResourceSet))
	mux.HandleFunc("POST "+P+"/permission", h.protection(h.createPermissionTicket))
	mux.HandleFunc("GET "+P+"/permission/ticket", h.protection(h.listTickets))
	mux.HandleFunc("POST "+P+"/permission/ticket", h.protection(h.createGrantedTicket))
	mux.HandleFunc("PUT "+P+"/permission/ticket", h.protection(h.updateTicket))
	mux.HandleFunc("DELETE "+P+"/permission/ticket/{id}", h.protection(h.deleteTicket))
}

func (h *Handler) umaConfiguration(w http.ResponseWriter, r *http.Request) {
	realm, err := h.realm(r)
	if err != nil {
		h.writeError(w, err)
		return
	}
	iss := h.URLs.Issuer(r, realm.Name)
	p := iss + "/protocol/openid-connect"
	scopes, _ := h.Svc.Store.ListClientScopes(r.Context(), realm.ID)
	names := []string{"openid"}
	for _, s := range scopes {
		names = append(names, s.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": iss, "authorization_endpoint": p + "/auth", "token_endpoint": p + "/token",
		"introspection_endpoint": p + "/token/introspect", "end_session_endpoint": p + "/logout", "jwks_uri": p + "/certs",
		"frontchannel_logout_session_supported": false, "frontchannel_logout_supported": false,
		"grant_types_supported":                            []string{"authorization_code", "refresh_token", "password", "client_credentials", grantUMATicket},
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query", "fragment", "form_post"},
		"token_endpoint_auth_methods_supported":            []string{"private_key_jwt", "client_secret_basic", "client_secret_post", "client_secret_jwt"},
		"token_endpoint_auth_signing_alg_values_supported": append(append([]string{}, asymmetricAlgs...), "HS256", "HS512", "HS384"),
		"scopes_supported":                                 names,
		"resource_registration_endpoint":                   iss + "/authz/protection/resource_set",
		"permission_endpoint":                              iss + "/authz/protection/permission",
		"policy_endpoint":                                  iss + "/authz/protection/uma-policy",
	})
}

// ---------------------------------------------------------------- uma-ticket grant

// requestedPermission parses a permission parameter: "resource#scope1,scope2",
// "resource" or "#scope".
func requestedPermission(d *authz.Data, value string) (authz.Requested, error) {
	name, scopes, _ := strings.Cut(value, "#")
	var req authz.Requested
	if name != "" {
		res := d.Resource(name)
		if res == nil {
			res = d.ResourceByName(name)
		}
		if res == nil {
			return req, &oauthError{http.StatusBadRequest, "invalid_resource", "Resource with id [" + name + "] does not exist."}
		}
		req.ResourceID = res.ID
	}
	for _, s := range strings.Split(scopes, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		sc := d.ScopeByName(s)
		if sc == nil {
			sc = d.Scope(s)
		}
		if sc == nil {
			return req, &oauthError{http.StatusBadRequest, "invalid_scope", "Invalid scope [" + s + "]."}
		}
		req.Scopes = append(req.Scopes, sc.ID)
	}
	return req, nil
}

// rptResponse is the token response of the uma-ticket grant.
type rptResponse struct {
	Upgraded         bool   `json:"upgraded"`
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
}

// grantUMA implements the uma-ticket grant: the bearer token's user asks a
// resource server (audience, or the ticket's) for permissions.
func (h *Handler) grantUMA(w http.ResponseWriter, r *http.Request, realm *model.Realm) {
	ctx := r.Context()
	vt, err := h.Svc.VerifyToken(ctx, realm, bearerToken(r), h.URLs.Issuer(r, realm.Name), service.TokenBearer)
	if err != nil || vt.User == nil {
		h.writeError(w, errInvalidGrant("Invalid bearer token"))
		return
	}
	var ticketPerms []authz.Permission
	audience := r.PostFormValue("audience")
	if t := r.PostFormValue("ticket"); t != "" {
		claims, err := jwt.Verify(t, func(kid, alg string) *jwt.Key { return h.Svc.VerificationKey(ctx, realm.ID, kid, alg) })
		if err != nil || claims.Int("exp") < h.Svc.Now().Unix() || claims.String("aud") != h.URLs.Issuer(r, realm.Name) {
			h.writeError(w, errInvalidGrant("Invalid ticket"))
			return
		}
		b, _ := json.Marshal(claims["permissions"])
		json.Unmarshal(b, &ticketPerms)
		audience = claims.String("azp")
	}
	if audience == "" {
		h.writeError(w, errInvalidRequest("You must provide the issuedFor"))
		return
	}
	rsClient, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, audience)
	if err != nil {
		h.writeError(w, errInvalidRequest("Audience ["+audience+"] does not exist."))
		return
	}
	d, err := h.Svc.LoadAuthz(ctx, h.Svc.Store, rsClient.ID)
	if errors.Is(err, store.ErrNotFound) {
		h.writeError(w, errInvalidRequest("Client does not support permissions"))
		return
	}
	if err != nil {
		h.writeError(w, err)
		return
	}
	issuedTo := ""
	if c, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, vt.Claims.String("azp")); err == nil {
		issuedTo = c.ID
	}
	id, err := h.Svc.AuthzIdentity(ctx, realm, vt.User, issuedTo, vt.Claims)
	if err != nil {
		h.writeError(w, err)
		return
	}
	var requests []authz.Requested
	for _, tp := range ticketPerms {
		req := authz.Requested{ResourceID: tp.ResourceID}
		for _, s := range tp.Scopes {
			if sc := d.ScopeByName(s); sc != nil {
				req.Scopes = append(req.Scopes, sc.ID)
			}
		}
		requests = append(requests, req)
	}
	for _, v := range r.PostForm["permission"] {
		req, err := requestedPermission(d, v)
		if err != nil {
			h.writeError(w, err)
			return
		}
		requests = append(requests, req)
	}
	results := authz.Evaluate(d, id, requests)
	perms := authz.Permissions(results, r.PostFormValue("response_include_resource_name") != "false")
	ev := &eventInfo{client: rsClient, userID: vt.User.ID, details: map[string]string{"grant_type": grantUMATicket, "audience": audience}}
	if len(perms) == 0 {
		ev.err = "access_denied"
		h.event(r, realm, "PERMISSION_TOKEN_ERROR", ev)
		if r.PostFormValue("submit_request") == "true" && len(ticketPerms) > 0 && h.submitRequests(ctx, d, vt.User, results) {
			h.writeError(w, errAccessDenied("request_submitted"))
			return
		}
		h.writeError(w, errAccessDenied("not_authorized"))
		return
	}

	// a previous RPT is upgraded with the new permissions
	upgraded := false
	if old := r.PostFormValue("rpt"); old != "" {
		ovt, err := h.Svc.VerifyToken(ctx, realm, old, h.URLs.Issuer(r, realm.Name), service.TokenBearer)
		if err == nil && ovt.Claims.String("azp") == rsClient.ClientID {
			var prev struct {
				Permissions []authz.Permission `json:"permissions"`
			}
			b, _ := json.Marshal(ovt.Claims["authorization"])
			json.Unmarshal(b, &prev)
			perms = authz.Merge(prev.Permissions, perms)
			upgraded = true
		}
	}
	if limit, err := strconv.Atoi(r.PostFormValue("response_permissions_limit")); err == nil && limit > 0 && len(perms) > limit {
		perms = perms[:limit]
	}
	switch r.PostFormValue("response_mode") {
	case "decision":
		writeJSON(w, http.StatusOK, map[string]bool{"result": true})
		return
	case "permissions":
		writeJSON(w, http.StatusOK, perms)
		return
	}
	resp, err := h.issue(r, &issueRequest{realm: realm, client: rsClient, user: vt.User, session: vt.Session,
		scope: vt.Claims.String("scope"), refresh: vt.Session != nil,
		extra: jwt.Claims{"authorization": map[string]any{"permissions": perms}, "aud": rsClient.ClientID}})
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.event(r, realm, "PERMISSION_TOKEN", ev)
	writeJSON(w, http.StatusOK, rptResponse{Upgraded: upgraded, AccessToken: resp.AccessToken, ExpiresIn: resp.ExpiresIn,
		RefreshExpiresIn: resp.RefreshExpiresIn, RefreshToken: resp.RefreshToken, TokenType: resp.TokenType, NotBeforePolicy: resp.NotBeforePolicy})
}

// submitRequests records permission requests on owner managed resources
// the user was denied, for their owners to approve.
func (h *Handler) submitRequests(ctx context.Context, d *authz.Data, user *model.User, results []*authz.Result) bool {
	submitted := false
	for _, res := range results {
		if !res.Resource.OwnerManagedAccess || res.Resource.Owner == user.ID {
			continue
		}
		scopes := res.Requested
		if len(scopes) == 0 {
			scopes = []*model.AuthzScope{nil}
		}
		for _, s := range scopes {
			scopeID := ""
			if s != nil {
				if slices.ContainsFunc(res.Granted, func(g *model.AuthzScope) bool { return g.ID == s.ID }) {
					continue
				}
				scopeID = s.ID
			}
			exists := slices.ContainsFunc(d.Tickets, func(t *model.PermissionTicket) bool {
				return t.ResourceID == res.Resource.ID && t.ScopeID == scopeID && t.Requester == user.ID
			})
			if exists {
				submitted = true
				continue
			}
			t := &model.PermissionTicket{ID: service.NewID(), ResourceServerID: d.Server.ClientID, ResourceID: res.Resource.ID,
				ScopeID: scopeID, Owner: res.Resource.Owner, Requester: user.ID, CreatedTimestamp: h.Svc.Now().UnixMilli()}
			if err := h.Svc.Store.CreatePermissionTicket(ctx, t); err == nil {
				submitted = true
			}
		}
	}
	return submitted
}

// ---------------------------------------------------------------- protection API

// protectionCtx is the resource server calling the protection API with
// its PAT (a token of its service account holding uma_protection).
type protectionCtx struct {
	realm  *model.Realm
	client *model.Client
	data   *authz.Data
	sub    string
}

func (h *Handler) protection(fn func(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		realm, err := h.realm(r)
		if err != nil {
			h.writeError(w, err)
			return
		}
		deny := func(status int, code, desc string) {
			writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
		}
		vt, err := h.Svc.VerifyToken(ctx, realm, bearerToken(r), h.URLs.Issuer(r, realm.Name), service.TokenBearer)
		if err != nil || vt.User == nil {
			deny(http.StatusUnauthorized, "invalid_token", "Invalid bearer token")
			return
		}
		c, err := h.Svc.Store.GetClientByClientID(ctx, realm.ID, vt.Claims.String("azp"))
		if err != nil {
			deny(http.StatusUnauthorized, "invalid_token", "Invalid bearer token")
			return
		}
		roles, err := h.Svc.EffectiveRoles(ctx, realm.ID, vt.User.ID)
		if err != nil {
			h.writeError(w, err)
			return
		}
		if !slices.ContainsFunc(roles, func(role *model.Role) bool { return role.ClientID == c.ID && role.Name == service.UMAProtectionRole }) {
			deny(http.StatusForbidden, "invalid_clientId", "Client application ["+c.ClientID+"] is not registered as a resource server.")
			return
		}
		d, err := h.Svc.LoadAuthz(ctx, h.Svc.Store, c.ID)
		if err != nil {
			deny(http.StatusForbidden, "invalid_clientId", "Client application ["+c.ClientID+"] is not registered as a resource server.")
			return
		}
		if err := fn(w, r, &protectionCtx{realm: realm, client: c, data: d, sub: vt.User.ID}); err != nil {
			var oe *oauthError
			if errors.As(err, &oe) {
				writeJSON(w, oe.Status, oe)
				return
			}
			h.writeError(w, err)
		}
	}
}

type umaResource struct {
	ID                 string              `json:"_id,omitempty"`
	Name               string              `json:"name"`
	DisplayName        string              `json:"displayName,omitempty"`
	Type               string              `json:"type,omitempty"`
	Owner              any                 `json:"owner,omitempty"`
	OwnerManagedAccess bool                `json:"ownerManagedAccess"`
	URIs               []string            `json:"uris,omitempty"`
	IconURI            string              `json:"icon_uri,omitempty"`
	ResourceScopes     []map[string]string `json:"resource_scopes,omitempty"`
	Scopes             []map[string]string `json:"scopes,omitempty"`
	Attributes         any                 `json:"attributes,omitempty"`
}

func (h *Handler) umaResourceRep(ctx context.Context, pc *protectionCtx, res *model.AuthzResource, full bool) umaResource {
	rep := umaResource{ID: res.ID, Name: res.Name, DisplayName: res.DisplayName, Type: res.Type, OwnerManagedAccess: res.OwnerManagedAccess,
		URIs: res.URIs, IconURI: res.IconURI}
	owner := map[string]string{"id": res.Owner}
	if full {
		if res.Owner == pc.client.ID {
			owner["name"] = pc.client.ClientID
		} else if u, err := h.Svc.Store.GetUser(ctx, pc.realm.ID, res.Owner); err == nil {
			owner["name"] = u.Username
		}
	} else {
		attrs := res.Attributes
		if attrs == nil {
			attrs = map[string][]string{}
		}
		rep.Attributes = attrs
	}
	rep.Owner = owner
	for _, sid := range res.ScopeIDs {
		if s := pc.data.Scope(sid); s != nil {
			e := map[string]string{"name": s.Name}
			if full {
				e["id"] = s.ID
			}
			rep.ResourceScopes = append(rep.ResourceScopes, e)
		}
	}
	rep.Scopes = rep.ResourceScopes
	return rep
}

// readUMAResource applies a resource_set body to a resource.
func (h *Handler) readUMAResource(r *http.Request, pc *protectionCtx, res *model.AuthzResource) error {
	var in struct {
		Name               string              `json:"name"`
		DisplayName        string              `json:"displayName"`
		Type               string              `json:"type"`
		Owner              json.RawMessage     `json:"owner"`
		OwnerManagedAccess bool                `json:"ownerManagedAccess"`
		URIs               []string            `json:"uris"`
		URI                string              `json:"uri"`
		IconURI            string              `json:"icon_uri"`
		ResourceScopes     json.RawMessage     `json:"resource_scopes"`
		Scopes             json.RawMessage     `json:"scopes"`
		Attributes         map[string][]string `json:"attributes"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		return errInvalidRequest("Invalid JSON")
	}
	if strings.TrimSpace(in.Name) == "" {
		return errInvalidRequest("Name is required")
	}
	res.Name, res.DisplayName, res.Type, res.OwnerManagedAccess, res.IconURI = in.Name, in.DisplayName, in.Type, in.OwnerManagedAccess, in.IconURI
	res.URIs = in.URIs
	if in.URI != "" && len(res.URIs) == 0 {
		res.URIs = []string{in.URI}
	}
	res.Attributes = in.Attributes
	if res.Owner == "" {
		res.Owner = pc.client.ID
	}
	var owner string
	if json.Unmarshal(in.Owner, &owner) != nil {
		var o struct{ ID, Name string }
		json.Unmarshal(in.Owner, &o)
		owner = o.ID
		if owner == "" {
			owner = o.Name
		}
	}
	if owner != "" && owner != pc.client.ID && owner != pc.client.ClientID {
		u, err := h.Svc.Store.GetUser(r.Context(), pc.realm.ID, owner)
		if err != nil {
			u, err = h.Svc.Store.GetUserByUsername(r.Context(), pc.realm.ID, strings.ToLower(owner))
		}
		if err != nil {
			return errInvalidRequest("Owner [" + owner + "] not found")
		}
		res.Owner = u.ID
	}
	raw := in.ResourceScopes
	if len(raw) == 0 || string(raw) == "null" {
		raw = in.Scopes
	}
	var items []json.RawMessage
	json.Unmarshal(raw, &items)
	res.ScopeIDs = nil
	for _, it := range items {
		var name string
		if json.Unmarshal(it, &name) != nil {
			var o struct{ Name string }
			json.Unmarshal(it, &o)
			name = o.Name
		}
		if name == "" {
			continue
		}
		s := pc.data.ScopeByName(name)
		if s == nil {
			s = &model.AuthzScope{ID: service.NewID(), ResourceServerID: pc.client.ID, Name: name}
			if err := h.Svc.Store.CreateAuthzScope(r.Context(), s); err != nil {
				return err
			}
			pc.data.Scopes = append(pc.data.Scopes, s)
			pc.data.Index()
		}
		res.ScopeIDs = append(res.ScopeIDs, s.ID)
	}
	return nil
}

func (h *Handler) listResourceSet(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	q := r.URL.Query()
	var full []umaResource
	ids := []string{}
	for _, res := range pc.data.Resources {
		if n := q.Get("name"); n != "" {
			if q.Get("exactName") == "true" && res.Name != n || q.Get("exactName") != "true" && !strings.Contains(strings.ToLower(res.Name), strings.ToLower(n)) {
				continue
			}
		}
		if u := q.Get("uri"); u != "" && !slices.Contains(res.URIs, u) {
			continue
		}
		if t := q.Get("type"); t != "" && res.Type != t {
			continue
		}
		if o := q.Get("owner"); o != "" && res.Owner != o {
			if u, err := h.Svc.Store.GetUserByUsername(r.Context(), pc.realm.ID, strings.ToLower(o)); err != nil || u.ID != res.Owner {
				if !(o == pc.client.ClientID && res.Owner == pc.client.ID) {
					continue
				}
			}
		}
		if s := q.Get("scope"); s != "" {
			sc := pc.data.ScopeByName(s)
			if sc == nil || !slices.Contains(res.ScopeIDs, sc.ID) {
				continue
			}
		}
		ids = append(ids, res.ID)
		full = append(full, h.umaResourceRep(r.Context(), pc, res, true))
	}
	first, _ := strconv.Atoi(q.Get("first"))
	first = min(max(first, 0), len(ids))
	last := len(ids)
	if m, err := strconv.Atoi(q.Get("max")); err == nil && m >= 0 && first+m < last {
		last = first + m
	}
	if q.Get("deep") == "true" {
		writeJSON(w, http.StatusOK, full[first:last])
		return nil
	}
	writeJSON(w, http.StatusOK, ids[first:last])
	return nil
}

func (h *Handler) createResourceSet(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	if !pc.data.Server.AllowRemoteResourceManagement {
		return &oauthError{http.StatusForbidden, "request_denied", "Remote resource management not enabled for resource server"}
	}
	res := &model.AuthzResource{ID: service.NewID(), ResourceServerID: pc.client.ID}
	if err := h.readUMAResource(r, pc, res); err != nil {
		return err
	}
	for _, other := range pc.data.Resources {
		if other.Name == res.Name && other.Owner == res.Owner {
			return &oauthError{http.StatusConflict, "conflict", "Resource with name [" + res.Name + "] already exists."}
		}
	}
	if err := h.Svc.Store.CreateAuthzResource(r.Context(), res); err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, h.umaResourceRep(r.Context(), pc, res, true))
	return nil
}

func (h *Handler) umaResource(r *http.Request, pc *protectionCtx) (*model.AuthzResource, error) {
	res := pc.data.Resource(r.PathValue("id"))
	if res == nil {
		return nil, &oauthError{http.StatusNotFound, "not_found", "Resource set with id [" + r.PathValue("id") + "] does not exist."}
	}
	return res, nil
}

func (h *Handler) getResourceSet(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	res, err := h.umaResource(r, pc)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, h.umaResourceRep(r.Context(), pc, res, false))
	return nil
}

func (h *Handler) updateResourceSet(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	res, err := h.umaResource(r, pc)
	if err != nil {
		return err
	}
	if err := h.readUMAResource(r, pc, res); err != nil {
		return err
	}
	if err := h.Svc.Store.UpdateAuthzResource(r.Context(), res); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (h *Handler) deleteResourceSet(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	res, err := h.umaResource(r, pc)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteAuthzResource(r.Context(), pc.client.ID, res.ID); err != nil {
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// createPermissionTicket implements POST /permission: a resource server
// asks for a ticket the client exchanges at the token endpoint.
func (h *Handler) createPermissionTicket(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	type request struct {
		ResourceID     string   `json:"resource_id"`
		ResourceScopes []string `json:"resource_scopes"`
	}
	var reqs []request
	if json.Unmarshal(body, &reqs) != nil {
		var one request
		if err := json.Unmarshal(body, &one); err != nil {
			return errInvalidRequest("Invalid permission request")
		}
		reqs = []request{one}
	}
	var perms []authz.Permission
	for _, rq := range reqs {
		p := authz.Permission{}
		if rq.ResourceID != "" {
			res := pc.data.Resource(rq.ResourceID)
			if res == nil {
				res = pc.data.ResourceByName(rq.ResourceID)
			}
			if res == nil {
				return &oauthError{http.StatusBadRequest, "invalid_resource_id", "Resource set with id [" + rq.ResourceID + "] does not exist."}
			}
			p.ResourceID = res.ID
		}
		for _, s := range rq.ResourceScopes {
			if pc.data.ScopeByName(s) == nil {
				return &oauthError{http.StatusBadRequest, "invalid_scope", "Scope [" + s + "] is invalid"}
			}
			p.Scopes = append(p.Scopes, s)
		}
		perms = append(perms, p)
	}
	key, err := h.Svc.SigningKey(r.Context(), pc.realm, "HS512")
	if err != nil {
		return err
	}
	now := h.Svc.Now()
	ticket, err := jwt.Sign(jwt.Claims{"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "permissions": perms,
		"jti": service.NewID(), "aud": h.URLs.Issuer(r, pc.realm.Name), "sub": pc.sub, "azp": pc.client.ClientID}, key)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusCreated, map[string]string{"ticket": ticket})
	return nil
}

type ticketRep struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	OwnerName   string `json:"ownerName,omitempty"`
	Resource    string `json:"resource"`
	ResourceNm  string `json:"resourceName,omitempty"`
	Scope       string `json:"scope,omitempty"`
	ScopeName   string `json:"scopeName,omitempty"`
	Granted     bool   `json:"granted"`
	Requester   string `json:"requester"`
	RequesterNm string `json:"requesterName,omitempty"`
}

func (h *Handler) ticketToRep(ctx context.Context, pc *protectionCtx, t *model.PermissionTicket) ticketRep {
	rep := ticketRep{ID: t.ID, Owner: t.Owner, Resource: t.ResourceID, Scope: t.ScopeID, Granted: t.GrantedTimestamp > 0, Requester: t.Requester}
	if res := pc.data.Resource(t.ResourceID); res != nil {
		rep.ResourceNm = res.Name
	}
	if s := pc.data.Scope(t.ScopeID); s != nil {
		rep.ScopeName = s.Name
	}
	if u, err := h.Svc.Store.GetUser(ctx, pc.realm.ID, t.Owner); err == nil {
		rep.OwnerName = u.Username
	}
	if u, err := h.Svc.Store.GetUser(ctx, pc.realm.ID, t.Requester); err == nil {
		rep.RequesterNm = u.Username
	}
	return rep
}

func (h *Handler) listTickets(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	q := r.URL.Query()
	out := []ticketRep{}
	for _, t := range pc.data.Tickets {
		if (q.Get("resourceId") != "" && t.ResourceID != q.Get("resourceId")) || (q.Get("owner") != "" && t.Owner != q.Get("owner")) ||
			(q.Get("requester") != "" && t.Requester != q.Get("requester")) || (q.Get("granted") != "" && strconv.FormatBool(t.GrantedTimestamp > 0) != q.Get("granted")) {
			continue
		}
		if s := q.Get("scopeId"); s != "" && t.ScopeID != s {
			continue
		}
		out = append(out, h.ticketToRep(r.Context(), pc, t))
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// createGrantedTicket implements POST /permission/ticket: a resource owner
// grants a user access.
func (h *Handler) createGrantedTicket(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	var in struct {
		Resource      string `json:"resource"`
		Scope         string `json:"scope"`
		ScopeName     string `json:"scopeName"`
		Requester     string `json:"requester"`
		RequesterName string `json:"requesterName"`
		Granted       bool   `json:"granted"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		return errInvalidRequest("Invalid JSON")
	}
	res := pc.data.Resource(in.Resource)
	if res == nil {
		return errInvalidRequest("Resource [" + in.Resource + "] does not exist")
	}
	scopeID := in.Scope
	if in.ScopeName != "" {
		if s := pc.data.ScopeByName(in.ScopeName); s != nil {
			scopeID = s.ID
		}
	}
	requester := in.Requester
	if in.RequesterName != "" {
		u, err := h.Svc.Store.GetUserByUsername(r.Context(), pc.realm.ID, strings.ToLower(in.RequesterName))
		if err != nil {
			return errInvalidRequest("Requester does not exist")
		}
		requester = u.ID
	}
	if requester == "" {
		return errInvalidRequest("Requester is required")
	}
	t := &model.PermissionTicket{ID: service.NewID(), ResourceServerID: pc.client.ID, ResourceID: res.ID, ScopeID: scopeID,
		Owner: res.Owner, Requester: requester, CreatedTimestamp: h.Svc.Now().UnixMilli()}
	if in.Granted {
		t.GrantedTimestamp = t.CreatedTimestamp
	}
	if err := h.Svc.Store.CreatePermissionTicket(r.Context(), t); err != nil {
		return err
	}
	pc.data.Tickets = append(pc.data.Tickets, t)
	writeJSON(w, http.StatusOK, h.ticketToRep(r.Context(), pc, t))
	return nil
}

func (h *Handler) updateTicket(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	var in struct {
		ID      string `json:"id"`
		Granted bool   `json:"granted"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		return errInvalidRequest("Invalid JSON")
	}
	for _, t := range pc.data.Tickets {
		if t.ID == in.ID {
			t.GrantedTimestamp = 0
			if in.Granted {
				t.GrantedTimestamp = h.Svc.Now().UnixMilli()
			}
			if err := h.Svc.Store.UpdatePermissionTicket(r.Context(), t); err != nil {
				return err
			}
			w.WriteHeader(http.StatusNoContent)
			return nil
		}
	}
	return &oauthError{http.StatusNotFound, "not_found", "Ticket [" + in.ID + "] not found"}
}

func (h *Handler) deleteTicket(w http.ResponseWriter, r *http.Request, pc *protectionCtx) error {
	if err := h.Svc.Store.DeletePermissionTicket(r.Context(), pc.client.ID, r.PathValue("id")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return &oauthError{http.StatusNotFound, "not_found", "Ticket not found"}
		}
		return err
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}
