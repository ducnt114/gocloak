package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/federation"
	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/policy"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// ---------------------------------------------------------------- components

// ComponentRep mirrors the ComponentRepresentation.
type ComponentRep struct {
	ID           string              `json:"id,omitempty"`
	Name         string              `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	ParentID     string              `json:"parentId,omitempty"`
	SubType      string              `json:"subType,omitempty"`
	Config       map[string][]string `json:"config"`
}

func componentToRep(c *model.Component) ComponentRep {
	cfg := map[string][]string{}
	for k, v := range c.Config {
		if service.SecretKeyConfig[k] {
			continue // private keys and secrets never leave the server
		}
		if maskedComponentConfig[k] && len(v) > 0 && v[0] != "" {
			v = []string{maskedSecret}
		}
		cfg[k] = v
	}
	return ComponentRep{ID: c.ID, Name: c.Name, ProviderID: c.ProviderID, ProviderType: c.ProviderType,
		ParentID: c.ParentID, SubType: c.SubType, Config: cfg}
}

func (h *Handler) listComponents(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	comps, err := h.Svc.Store.ListComponents(r.Context(), realm.ID, r.URL.Query().Get("type"))
	if err != nil {
		return err
	}
	parent, name := r.URL.Query().Get("parent"), r.URL.Query().Get("name")
	if parent == "" {
		parent = r.URL.Query().Get("parentId") // the admin console's name for it
	}
	out := []ComponentRep{}
	for _, c := range comps {
		if (parent != "" && c.ParentID != parent) || (name != "" && c.Name != name) {
			continue
		}
		out = append(out, componentToRep(c))
	}
	return ok(w, out)
}

func (h *Handler) loadComponent(r *http.Request, realm *model.Realm) (*model.Component, error) {
	c, err := h.Svc.Store.GetComponent(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find component")
	}
	return c, err
}

func (h *Handler) getComponent(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	c, err := h.loadComponent(r, realm)
	if err != nil {
		return err
	}
	return ok(w, componentToRep(c))
}

func (h *Handler) createComponent(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	var rep ComponentRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	switch rep.ProviderType {
	case service.KeyProviderType, federation.ProviderType, federation.MapperType, service.RegistrationPolicyType:
	default:
		return badRequest("Unsupported component type: " + rep.ProviderType)
	}
	c := &model.Component{ID: rep.ID, RealmID: realm.ID, Name: rep.Name, ProviderID: rep.ProviderID,
		ProviderType: rep.ProviderType, ParentID: rep.ParentID, SubType: rep.SubType, Config: rep.Config}
	if c.ID == "" {
		c.ID = service.NewID()
	}
	if c.ParentID == "" {
		c.ParentID = realm.ID
	}
	if c.Name == "" {
		c.Name = c.ProviderID
	}
	if c.Config == nil {
		c.Config = map[string][]string{}
	}
	if c.ProviderType == service.RegistrationPolicyType {
		if !registrationPolicyProviders[c.ProviderID] || (c.SubType != "anonymous" && c.SubType != "authenticated") {
			return badRequest("Unknown client registration policy " + c.ProviderID)
		}
		if err := h.Svc.Store.CreateComponent(r.Context(), c); err != nil {
			return err
		}
		return created(w, r, c.ID)
	}
	if c.ProviderType != service.KeyProviderType {
		if err := h.prepareFederationComponent(r.Context(), realm, c, nil); err != nil {
			return err
		}
		if err := h.createFederationComponent(r.Context(), c); err != nil {
			return err
		}
		return created(w, r, c.ID)
	}
	if err := service.PrepareKeyComponent(c, realm.Name, nil); err != nil {
		return err
	}
	if err := h.Svc.Store.CreateComponent(r.Context(), c); err != nil {
		return err
	}
	h.Svc.InvalidateKeys(realm.ID)
	return created(w, r, c.ID)
}

func (h *Handler) updateComponent(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	prev, err := h.loadComponent(r, realm)
	if err != nil {
		return err
	}
	var rep ComponentRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	c := *prev
	if rep.Name != "" {
		c.Name = rep.Name
	}
	c.Config = map[string][]string{}
	for k, v := range prev.Config {
		c.Config[k] = v
	}
	for k, v := range rep.Config {
		c.Config[k] = v
	}
	if c.ProviderType == service.RegistrationPolicyType {
		if rep.Config != nil {
			c.Config = rep.Config
		}
		if err := h.Svc.Store.UpdateComponent(r.Context(), &c); err != nil {
			return err
		}
		return noContent(w)
	}
	if c.ProviderType != service.KeyProviderType {
		if rep.Config != nil && c.ProviderType == federation.ProviderType {
			// a provider update replaces its config
			c.Config = rep.Config
		}
		if err := h.prepareFederationComponent(r.Context(), realm, &c, prev); err != nil {
			return err
		}
		if err := h.Svc.Store.UpdateComponent(r.Context(), &c); err != nil {
			return err
		}
		return noContent(w)
	}
	if err := service.PrepareKeyComponent(&c, realm.Name, prev); err != nil {
		return err
	}
	if err := h.Svc.Store.UpdateComponent(r.Context(), &c); err != nil {
		return err
	}
	h.Svc.InvalidateKeys(realm.ID)
	return noContent(w)
}

func (h *Handler) deleteComponent(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	c, err := h.loadComponent(r, realm)
	if err != nil {
		return err
	}
	if c.ProviderType == federation.ProviderType {
		if err := h.deleteFederationComponent(r.Context(), realm, c); err != nil {
			return err
		}
		return noContent(w)
	}
	if err := h.Svc.Store.DeleteComponent(r.Context(), realm.ID, c.ID); err != nil {
		return err
	}
	h.Svc.InvalidateKeys(realm.ID)
	return noContent(w)
}

// getKeys implements GET /admin/realms/{realm}/keys.
func (h *Handler) getKeys(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	keys, err := h.Svc.RealmKeys(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	type keyRep struct {
		ProviderID       string `json:"providerId"`
		ProviderPriority int64  `json:"providerPriority"`
		Kid              string `json:"kid"`
		Status           string `json:"status"`
		Type             string `json:"type"`
		Algorithm        string `json:"algorithm"`
		PublicKey        string `json:"publicKey,omitempty"`
		Certificate      string `json:"certificate,omitempty"`
		Use              string `json:"use"`
		ValidTo          int64  `json:"validTo,omitempty"`
	}
	out := []keyRep{}
	active := map[string]string{}
	for _, k := range keys {
		kr := keyRep{ProviderID: k.ComponentID, ProviderPriority: k.Priority, Kid: k.Kid, Status: k.Status(),
			Type: jwt.Family(k.Alg), Algorithm: k.Alg, Use: "SIG"}
		if k.Public != nil {
			kr.PublicKey = jwt.PublicKeyBase64(k.Public)
		}
		if k.Certificate != nil {
			kr.Certificate = jwt.EncodeCertificate(k.Certificate)
			kr.ValidTo = k.Certificate.NotAfter.UnixMilli()
		}
		if kr.Status == "ACTIVE" {
			if _, seen := active[k.Alg]; !seen {
				active[k.Alg] = k.Kid
			}
		}
		out = append(out, kr)
	}
	return ok(w, map[string]any{"active": active, "keys": out})
}

// ---------------------------------------------------------------- brute force

func (h *Handler) bruteForceStatus(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	st, err := h.Svc.LockStatus(r.Context(), realm, r.PathValue("id"))
	if err != nil {
		return err
	}
	return ok(w, st)
}

func (h *Handler) clearBruteForceUser(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteLoginFailure(r.Context(), realm.ID, r.PathValue("id")); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) clearBruteForce(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteLoginFailures(r.Context(), realm.ID); err != nil {
		return err
	}
	return noContent(w)
}

// ---------------------------------------------------------------- events

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, "view-events")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	eq := store.EventQuery{Types: q["type"], ClientID: q.Get("client"), UserID: q.Get("user"), IPAddress: q.Get("ipAddress"),
		From: dateParam(q.Get("dateFrom"), false), To: dateParam(q.Get("dateTo"), true),
		First: intParam(r, "first", 0), Max: intParam(r, "max", 100)}
	events, err := h.Svc.Store.ListEvents(r.Context(), realm.ID, eq)
	if err != nil {
		return err
	}
	type eventRep struct {
		Time      int64             `json:"time"`
		Type      string            `json:"type"`
		RealmID   string            `json:"realmId"`
		ClientID  string            `json:"clientId,omitempty"`
		UserID    string            `json:"userId,omitempty"`
		SessionID string            `json:"sessionId,omitempty"`
		IPAddress string            `json:"ipAddress,omitempty"`
		Error     string            `json:"error,omitempty"`
		Details   map[string]string `json:"details,omitempty"`
	}
	out := []eventRep{}
	for _, e := range events {
		out = append(out, eventRep{e.Time, e.Type, e.RealmID, e.ClientID, e.UserID, e.SessionID, e.IPAddress, e.Error, e.Details})
	}
	return ok(w, out)
}

// dateParam parses yyyy-MM-dd (or epoch millis) into millis; end of day for dateTo.
func dateParam(v string, endOfDay bool) int64 {
	if v == "" {
		return 0
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return n
	}
	t, err := parseDay(v)
	if err != nil {
		return 0
	}
	if endOfDay {
		return t.UnixMilli() + 24*3600*1000 - 1
	}
	return t.UnixMilli()
}

func (h *Handler) deleteEvents(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, "manage-events")
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteEvents(r.Context(), realm.ID); err != nil {
		return err
	}
	return noContent(w)
}

type eventsConfigRep struct {
	EventsEnabled             *bool    `json:"eventsEnabled,omitempty"`
	EventsExpiration          *int64   `json:"eventsExpiration,omitempty"`
	EventsListeners           []string `json:"eventsListeners"`
	EnabledEventTypes         []string `json:"enabledEventTypes"`
	AdminEventsEnabled        *bool    `json:"adminEventsEnabled,omitempty"`
	AdminEventsDetailsEnabled *bool    `json:"adminEventsDetailsEnabled,omitempty"`
}

func (h *Handler) getEventsConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, "view-events")
	if err != nil {
		return err
	}
	s := realm.Settings
	types := s.EnabledEventTypes
	if len(types) == 0 {
		types = service.DefaultEventTypes
	}
	rep := eventsConfigRep{EventsEnabled: ptr(s.EventsEnabled), EventsListeners: nonNil(s.EventsListeners),
		EnabledEventTypes: types, AdminEventsEnabled: ptr(s.AdminEventsEnabled), AdminEventsDetailsEnabled: ptr(s.AdminEventsDetailsEnabled)}
	if s.EventsExpiration > 0 {
		rep.EventsExpiration = ptr(s.EventsExpiration)
	}
	return ok(w, rep)
}

func (h *Handler) updateEventsConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, "manage-events")
	if err != nil {
		return err
	}
	var rep eventsConfigRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	s := &realm.Settings
	set(&s.EventsEnabled, rep.EventsEnabled)
	set(&s.EventsExpiration, rep.EventsExpiration)
	set(&s.AdminEventsEnabled, rep.AdminEventsEnabled)
	set(&s.AdminEventsDetailsEnabled, rep.AdminEventsDetailsEnabled)
	if rep.EventsListeners != nil {
		listeners := h.Svc.Listeners()
		for _, l := range rep.EventsListeners {
			if listeners[l] == nil {
				return badRequest("Event listener not found: " + l)
			}
		}
		s.EventsListeners = rep.EventsListeners
	}
	if rep.EnabledEventTypes != nil {
		s.EnabledEventTypes = rep.EnabledEventTypes
	}
	if err := h.Svc.Store.UpdateRealm(r.Context(), realm); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) listAdminEvents(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, "view-events")
	if err != nil {
		return err
	}
	q := r.URL.Query()
	aq := store.AdminEventQuery{OperationTypes: q["operationTypes"], ResourceTypes: q["resourceTypes"], ResourcePath: q.Get("resourcePath"),
		AuthRealm: q.Get("authRealm"), AuthClient: q.Get("authClient"), AuthUser: q.Get("authUser"), AuthIP: q.Get("authIpAddress"),
		From: dateParam(q.Get("dateFrom"), false), To: dateParam(q.Get("dateTo"), true),
		First: intParam(r, "first", 0), Max: intParam(r, "max", 100)}
	events, err := h.Svc.Store.ListAdminEvents(r.Context(), realm.ID, aq)
	if err != nil {
		return err
	}
	type authDetails struct {
		RealmID   string `json:"realmId"`
		ClientID  string `json:"clientId"`
		UserID    string `json:"userId"`
		IPAddress string `json:"ipAddress"`
	}
	type adminEventRep struct {
		Time           int64       `json:"time"`
		RealmID        string      `json:"realmId"`
		AuthDetails    authDetails `json:"authDetails"`
		OperationType  string      `json:"operationType"`
		ResourceType   string      `json:"resourceType"`
		ResourcePath   string      `json:"resourcePath"`
		Representation string      `json:"representation,omitempty"`
		Error          string      `json:"error,omitempty"`
	}
	out := []adminEventRep{}
	for _, e := range events {
		out = append(out, adminEventRep{e.Time, e.RealmID, authDetails{e.AuthRealmID, e.AuthClientID, e.AuthUserID, e.AuthIP},
			e.OperationType, e.ResourceType, e.ResourcePath, e.Representation, e.Error})
	}
	return ok(w, out)
}

func (h *Handler) deleteAdminEvents(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, "manage-events")
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteAdminEvents(r.Context(), realm.ID); err != nil {
		return err
	}
	return noContent(w)
}

// adminEventFor derives an admin event from a successful admin request.
// body is the request body; location the Location header of the response.
func adminEventFor(r *http.Request, p *principal, body []byte, location string) (realmName string, e *model.AdminEvent) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/realms")
	path = strings.TrimPrefix(path, "/")
	realmName, rest, _ := strings.Cut(path, "/")
	if r.Method == http.MethodPost && path == "" {
		// POST /admin/realms creates the realm named in the body
		var rep struct{ Realm string }
		json.Unmarshal(body, &rep)
		realmName, rest = rep.Realm, ""
	}
	if r.Method == http.MethodPost && location != "" {
		// a created resource is identified by its Location
		if u, err := url.Parse(location); err == nil {
			lp := strings.TrimPrefix(u.Path, "/admin/realms/")
			if _, after, ok := strings.Cut(lp, "/"); ok && strings.HasPrefix(lp, realmName+"/") {
				rest = after
			}
		}
	}
	op := map[string]string{http.MethodPost: "CREATE", http.MethodPut: "UPDATE", http.MethodDelete: "DELETE"}[r.Method]
	if actionPath.MatchString(rest) {
		op = "ACTION"
	}
	e = &model.AdminEvent{OperationType: op, ResourceType: resourceType(rest), ResourcePath: rest,
		AuthRealmID: p.realm.ID, AuthUserID: p.user.ID, AuthClientID: p.clientUUID, AuthIP: clientIP(r)}
	if op != "ACTION" && len(body) > 0 {
		e.Representation = scrub(body)
	}
	return realmName, e
}

var actionPath = regexp.MustCompile(`(reset-password|logout|logout-all|push-revocation|client-secret|send-verify-email|execute-actions-email|partial-export|partialImport|test)$`)

// resourceType maps an admin path (relative to the realm) to an admin
// event resource type.
func resourceType(path string) string {
	seg := strings.Split(path, "/")
	has := func(s string) bool {
		for _, x := range seg {
			if x == s {
				return true
			}
		}
		return false
	}
	switch {
	case path == "" || path == "events/config":
		return "REALM"
	case has("role-mappings") && has("realm"):
		return "REALM_ROLE_MAPPING"
	case has("role-mappings"):
		return "CLIENT_ROLE_MAPPING"
	case has("scope-mappings") && has("realm"):
		return "REALM_SCOPE_MAPPING"
	case has("scope-mappings"):
		return "CLIENT_SCOPE_MAPPING"
	case has("protocol-mappers"):
		return "PROTOCOL_MAPPER"
	case has("default-client-scopes") || has("optional-client-scopes"):
		return "CLIENT_SCOPE_CLIENT_MAPPING"
	case has("default-default-client-scopes") || has("default-optional-client-scopes"):
		return "REALM_SCOPE_MAPPING"
	case seg[0] == "identity-provider" && has("mappers"):
		return "IDENTITY_PROVIDER_MAPPER"
	case seg[0] == "identity-provider":
		return "IDENTITY_PROVIDER"
	case seg[0] == "users" && has("groups"):
		return "GROUP_MEMBERSHIP"
	case seg[0] == "attack-detection":
		return "USER_LOGIN_FAILURE"
	case seg[0] == "users":
		return "USER"
	case seg[0] == "clients" && has("roles"):
		return "CLIENT_ROLE"
	case seg[0] == "clients":
		return "CLIENT"
	case seg[0] == "client-scopes":
		return "CLIENT_SCOPE"
	case seg[0] == "roles" || seg[0] == "roles-by-id":
		return "REALM_ROLE"
	case seg[0] == "groups":
		return "GROUP"
	case seg[0] == "components":
		return "COMPONENT"
	}
	return "REALM"
}

var secretFields = map[string]bool{"clientSecret": true, "p8Key": true, "value": true, "secret": true, "password": true, "privateKey": true, "secretData": true, "credentials": true}

// scrub removes secrets from a JSON representation before it is stored.
func scrub(body []byte) string {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return ""
	}
	var walk func(any) any
	walk = func(x any) any {
		switch t := x.(type) {
		case map[string]any:
			for k, val := range t {
				if secretFields[k] {
					t[k] = "**********"
				} else {
					t[k] = walk(val)
				}
			}
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
		}
		return x
	}
	b, _ := json.Marshal(walk(v))
	return string(b)
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return strings.Trim(host, "[]")
}

// readBody reads and restores a request body (for admin events).
func readBody(r *http.Request) []byte {
	if r.Body == nil || r.Method == http.MethodGet {
		return nil
	}
	b, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 10<<20))
	if err != nil {
		return nil
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b
}

// ---------------------------------------------------------------- revocation

func (h *Handler) pushRevocation(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permManageRealm); err != nil {
		return err
	}
	// gocloak clients have no admin URL to push to.
	return ok(w, map[string]any{"successRequests": []string{}, "failedRequests": []string{}})
}

func (h *Handler) clientPushRevocation(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	if _, err := h.loadClient(r, realm); err != nil {
		return err
	}
	return ok(w, map[string]any{"successRequests": []string{}, "failedRequests": []string{}})
}

// ---------------------------------------------------------------- offline sessions

func (h *Handler) userOfflineSessions(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	c, err := h.Svc.Store.GetClient(r.Context(), realm.ID, r.PathValue("client"))
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Client")
	}
	if err != nil {
		return err
	}
	all, err := h.Svc.Store.ListOfflineSessions(r.Context(), u.ID)
	if err != nil {
		return err
	}
	var sessions []*model.UserSession
	for _, s := range all {
		if s.Clients[c.ID] {
			sessions = append(sessions, s)
		}
	}
	out, err := h.sessionsToRep(r, realm, sessions, map[string]*model.User{u.ID: u})
	if err != nil {
		return err
	}
	return ok(w, out)
}

// userConsents lists the consents and offline tokens of a user by client.
func (h *Handler) userConsents(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	grants, err := h.Svc.UserGrants(r.Context(), realm, u)
	if err != nil {
		return err
	}
	type grant struct {
		Client string `json:"client"`
		Key    string `json:"key"`
	}
	type consent struct {
		ClientID            string   `json:"clientId"`
		GrantedClientScopes []string `json:"grantedClientScopes"`
		CreatedDate         int64    `json:"createdDate"`
		LastUpdatedDate     int64    `json:"lastUpdatedDate"`
		AdditionalGrants    []grant  `json:"additionalGrants"`
	}
	out := []consent{}
	for _, g := range grants {
		c := consent{ClientID: g.Client.ClientID, GrantedClientScopes: []string{}, CreatedDate: g.Created,
			LastUpdatedDate: g.Updated, AdditionalGrants: []grant{}}
		for _, it := range g.Items {
			c.GrantedClientScopes = append(c.GrantedClientScopes, it.Name)
		}
		if g.Offline {
			c.AdditionalGrants = append(c.AdditionalGrants, grant{Client: g.Client.ID, Key: "Offline Token"})
		}
		out = append(out, c)
	}
	return ok(w, out)
}

// revokeConsent removes the consent and the offline tokens of a client.
func (h *Handler) revokeConsent(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	c, err := h.Svc.Store.GetClientByClientID(r.Context(), realm.ID, r.PathValue("client"))
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Client not found")
	}
	if err != nil {
		return err
	}
	found, err := h.Svc.RevokeGrant(r.Context(), u, c)
	if err != nil {
		return err
	}
	if !found {
		return errStatus(http.StatusNotFound, "Consent nor offline token not found")
	}
	return noContent(w)
}

// registrationPolicyProviders are the client registration policies gocloak applies.
var registrationPolicyProviders = map[string]bool{"trusted-hosts": true, "consent-required": true, "scope": true,
	"max-clients": true, "allowed-protocol-mappers": true, "allowed-client-templates": true}

// policyError renders a password policy violation as an HTTP error.
func policyError(err error) (*httpError, bool) {
	var pe *policy.Error
	if errors.As(err, &pe) {
		return &httpError{status: http.StatusBadRequest, msg: pe.Message, key: pe.Key}, true
	}
	return nil, false
}

func parseDay(v string) (time.Time, error) { return time.Parse("2006-01-02", v) }
