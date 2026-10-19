package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/oidc"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

const (
	permViewIdPs   = "view-identity-providers"
	permManageIdPs = "manage-identity-providers"
)

func init() {
	implied[permViewIdPs] = []string{permManageIdPs}
}

// IdentityProviderRep is Keycloak's IdentityProviderRepresentation.
type IdentityProviderRep struct {
	Alias                       *string           `json:"alias,omitempty"`
	DisplayName                 *string           `json:"displayName,omitempty"`
	InternalID                  *string           `json:"internalId,omitempty"`
	ProviderID                  *string           `json:"providerId,omitempty"`
	Enabled                     *bool             `json:"enabled,omitempty"`
	UpdateProfileFirstLoginMode *string           `json:"updateProfileFirstLoginMode,omitempty"`
	TrustEmail                  *bool             `json:"trustEmail,omitempty"`
	StoreToken                  *bool             `json:"storeToken,omitempty"`
	AddReadTokenRoleOnCreate    *bool             `json:"addReadTokenRoleOnCreate,omitempty"`
	AuthenticateByDefault       *bool             `json:"authenticateByDefault,omitempty"`
	LinkOnly                    *bool             `json:"linkOnly,omitempty"`
	HideOnLogin                 *bool             `json:"hideOnLogin,omitempty"`
	FirstBrokerLoginFlowAlias   *string           `json:"firstBrokerLoginFlowAlias,omitempty"`
	PostBrokerLoginFlowAlias    *string           `json:"postBrokerLoginFlowAlias,omitempty"`
	Config                      map[string]string `json:"config"`
}

// IdPMapperRep is Keycloak's IdentityProviderMapperRepresentation.
type IdPMapperRep struct {
	ID                     string            `json:"id,omitempty"`
	Name                   string            `json:"name"`
	IdentityProviderAlias  string            `json:"identityProviderAlias"`
	IdentityProviderMapper string            `json:"identityProviderMapper"`
	Config                 map[string]string `json:"config"`
}

// FederatedIdentityRep is Keycloak's FederatedIdentityRepresentation.
type FederatedIdentityRep struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId"`
	UserName         string `json:"userName"`
}

func idpToRep(p *model.IdentityProvider, withSecrets bool) IdentityProviderRep {
	cfg := map[string]string{}
	for k, v := range p.Config {
		if !withSecrets && (k == "clientSecret" || k == "p8Key") && v != "" && !strings.HasPrefix(v, "${vault.") {
			v = maskedSecret
		}
		cfg[k] = v
	}
	rep := IdentityProviderRep{Alias: &p.Alias, InternalID: &p.InternalID, ProviderID: &p.ProviderID, Enabled: &p.Enabled,
		UpdateProfileFirstLoginMode: ptr("on"), TrustEmail: &p.TrustEmail, StoreToken: &p.StoreToken,
		AddReadTokenRoleOnCreate: &p.AddReadTokenRoleOnCreate, AuthenticateByDefault: &p.AuthenticateByDefault,
		LinkOnly: &p.LinkOnly, HideOnLogin: &p.HideOnLogin, Config: cfg}
	if p.DisplayName != "" {
		rep.DisplayName = &p.DisplayName
	}
	if p.FirstBrokerLoginFlowAlias != "" {
		rep.FirstBrokerLoginFlowAlias = &p.FirstBrokerLoginFlowAlias
	}
	if p.PostBrokerLoginFlowAlias != "" {
		rep.PostBrokerLoginFlowAlias = &p.PostBrokerLoginFlowAlias
	}
	return rep
}

// applyIdPRep copies a representation onto a provider; absent fields keep
// their value, a masked secret keeps the stored one.
func applyIdPRep(p *model.IdentityProvider, rep *IdentityProviderRep) {
	set := func(dst *bool, v *bool) {
		if v != nil {
			*dst = *v
		}
	}
	if rep.DisplayName != nil {
		p.DisplayName = *rep.DisplayName
	}
	if rep.ProviderID != nil && p.ProviderID == "" {
		p.ProviderID = *rep.ProviderID
	}
	set(&p.Enabled, rep.Enabled)
	set(&p.TrustEmail, rep.TrustEmail)
	set(&p.StoreToken, rep.StoreToken)
	set(&p.AddReadTokenRoleOnCreate, rep.AddReadTokenRoleOnCreate)
	set(&p.AuthenticateByDefault, rep.AuthenticateByDefault)
	set(&p.LinkOnly, rep.LinkOnly)
	set(&p.HideOnLogin, rep.HideOnLogin)
	if rep.FirstBrokerLoginFlowAlias != nil {
		p.FirstBrokerLoginFlowAlias = *rep.FirstBrokerLoginFlowAlias
	}
	if rep.PostBrokerLoginFlowAlias != nil {
		p.PostBrokerLoginFlowAlias = *rep.PostBrokerLoginFlowAlias
	}
	if rep.Config != nil {
		old := p.Config
		p.Config = map[string]string{}
		for k, v := range rep.Config {
			if v == maskedSecret {
				v = old[k]
			}
			p.Config[k] = v
		}
		if v, ok := rep.Config["hideOnLoginPage"]; ok && rep.HideOnLogin == nil {
			p.HideOnLogin = v == "true" // before Keycloak 26 this was a config entry
		}
		p.GUIOrder = p.Config["guiOrder"]
	}
	if p.Config == nil {
		p.Config = map[string]string{}
	}
}

// presetDefaults are the config defaults Keycloak gives new providers.
func presetDefaults(p *model.IdentityProvider) {
	def := func(k, v string) {
		if _, ok := p.Config[k]; !ok {
			p.Config[k] = v
		}
	}
	def("syncMode", "LEGACY")
	if t := oidc.IdPTypes[p.ProviderID]; t != nil && t.OIDC && !t.Social {
		def("clientAuthMethod", "client_secret_post")
	}
}

// localHost reports whether a host is a loopback or private address, which
// sslRequired=external allows over plain http.
func localHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// validateIdP checks a provider as Keycloak does: known type, and https
// endpoints unless the realm allows otherwise.
func validateIdP(realm *model.Realm, p *model.IdentityProvider) error {
	if strings.TrimSpace(p.Alias) == "" {
		return badRequest("Missing alias")
	}
	if oidc.IdPTypes[p.ProviderID] == nil {
		return badRequest("Invalid identity provider id [" + p.ProviderID + "]")
	}
	for key, name := range map[string]string{"authorizationUrl": "authorization_url", "tokenUrl": "token_url",
		"userInfoUrl": "userinfo_url", "jwksUrl": "jwks_url", "logoutUrl": "logout_url"} {
		raw := p.Config[key]
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return badRequest("The url [" + name + "] is malformed")
		}
		ssl := realm.Settings.SSLRequired
		if u.Scheme == "http" && (ssl == "all" || (ssl != "none" && !localHost(u.Hostname()))) {
			return badRequest("The url [" + name + "] requires secure connections")
		}
	}
	return nil
}

func (h *Handler) loadIdP(r *http.Request, realm *model.Realm) (*model.IdentityProvider, error) {
	p, err := h.Svc.Store.GetIdentityProvider(r.Context(), realm.ID, r.PathValue("alias"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find identity provider")
	}
	return p, err
}

func (h *Handler) listIdPs(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewIdPs)
	if err != nil {
		return err
	}
	idps, err := h.Svc.Store.ListIdentityProviders(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	// as in Keycloak: "abc" matches a prefix, "*abc*" a substring
	search := strings.ToLower(r.URL.Query().Get("search"))
	infix := strings.HasPrefix(search, "*")
	search = strings.Trim(search, "*")
	brief := r.URL.Query().Get("briefRepresentation") == "true"
	out := []any{}
	for _, idp := range idps {
		alias := strings.ToLower(idp.Alias)
		if search != "" && !strings.HasPrefix(alias, search) && !(infix && strings.Contains(alias, search)) {
			continue
		}
		rep := idpToRep(idp, false)
		if brief {
			out = append(out, map[string]any{"alias": idp.Alias, "displayName": rep.DisplayName, "internalId": idp.InternalID,
				"providerId": idp.ProviderID, "enabled": idp.Enabled})
			continue
		}
		out = append(out, rep)
	}
	first, max := min(intParam(r, "first", 0), len(out)), intParam(r, "max", len(out))
	return ok(w, out[first:min(first+max, len(out))])
}

func (h *Handler) createIdP(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageIdPs)
	if err != nil {
		return err
	}
	var rep IdentityProviderRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	idp := &model.IdentityProvider{InternalID: service.NewID(), RealmID: realm.ID, Enabled: true, Config: map[string]string{}}
	if rep.Alias != nil {
		idp.Alias = *rep.Alias
	}
	applyIdPRep(idp, &rep)
	if rep.Config == nil || rep.Config["syncMode"] == "" {
		presetDefaults(idp)
	}
	if err := validateIdP(realm, idp); err != nil {
		return err
	}
	if err := h.Svc.Store.CreateIdentityProvider(r.Context(), idp); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("Identity Provider " + idp.Alias + " already exists")
		}
		return err
	}
	return created(w, r, url.PathEscape(idp.Alias))
}

func (h *Handler) getIdP(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	return ok(w, idpToRep(idp, false))
}

func (h *Handler) updateIdP(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	var rep IdentityProviderRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	oldAlias := idp.Alias
	applyIdPRep(idp, &rep)
	if err := validateIdP(realm, idp); err != nil {
		return err
	}
	if rep.Alias != nil && *rep.Alias != oldAlias {
		return badRequest("Changing the alias of an identity provider is not supported")
	}
	if err := h.Svc.Store.UpdateIdentityProvider(r.Context(), idp); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteIdP(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteIdentityProvider(r.Context(), realm.ID, idp.Alias); err != nil {
		return err
	}
	return noContent(w)
}

// getIdPProvider describes a provider type: /identity-provider/providers/{id}.
func (h *Handler) getIdPProvider(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permViewIdPs); err != nil {
		return err
	}
	t := oidc.IdPTypes[r.PathValue("provider")]
	if t == nil {
		return notFound("Could not find identity provider")
	}
	return ok(w, map[string]any{"id": t.ID, "name": t.Name})
}

// importIdPConfig reads an OpenID provider's discovery document:
// /identity-provider/import-config.
func (h *Handler) importIdPConfig(w http.ResponseWriter, r *http.Request, p *principal) error {
	if _, err := h.realmFor(r, p, permManageIdPs); err != nil {
		return err
	}
	var req map[string]string
	if err := decode(r, &req); err != nil {
		return err
	}
	from := req["fromUrl"]
	if from == "" {
		return badRequest("Missing fromUrl")
	}
	if t := oidc.IdPTypes[req["providerId"]]; t == nil || !t.OIDC {
		return badRequest("Import of the configuration is only supported for OpenID Connect providers")
	}
	ctx := r.Context()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, from, nil)
	if err != nil {
		return badRequest("Invalid fromUrl")
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(hreq)
	if err != nil {
		return badRequest("Could not fetch the configuration: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return badRequest(fmt.Sprintf("Could not fetch the configuration: HTTP %d", resp.StatusCode))
	}
	var d struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		UserInfo      string `json:"userinfo_endpoint"`
		EndSession    string `json:"end_session_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return badRequest("Invalid configuration document")
	}
	cfg := map[string]string{"issuer": d.Issuer, "authorizationUrl": d.Authorization, "tokenUrl": d.Token,
		"userInfoUrl": d.UserInfo, "logoutUrl": d.EndSession, "metadataDescriptorUrl": from}
	if d.JWKS != "" {
		cfg["jwksUrl"], cfg["useJwksUrl"], cfg["validateSignature"] = d.JWKS, "true", "true"
	}
	for k, v := range cfg {
		if v == "" {
			delete(cfg, k)
		}
	}
	return ok(w, cfg)
}

// ---------------------------------------------------------------- mappers

func idpMapperToRep(m *model.IdentityProviderMapper) IdPMapperRep {
	return IdPMapperRep{ID: m.ID, Name: m.Name, IdentityProviderAlias: m.IdPAlias, IdentityProviderMapper: m.Type, Config: m.Config}
}

func (h *Handler) validateIdPMapper(idp *model.IdentityProvider, rep *IdPMapperRep) error {
	if strings.TrimSpace(rep.Name) == "" {
		return badRequest("Missing name")
	}
	if oidc.MapperTypesFor(idp.ProviderID)[rep.IdentityProviderMapper] == nil {
		return badRequest("Invalid mapper type [" + rep.IdentityProviderMapper + "] for identity provider [" + idp.ProviderID + "]")
	}
	if rep.Config == nil {
		rep.Config = map[string]string{}
	}
	return nil
}

func (h *Handler) listIdPMappers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	ms, err := h.Svc.Store.ListIdPMappers(r.Context(), realm.ID, idp.Alias)
	if err != nil {
		return err
	}
	out := []IdPMapperRep{}
	for _, m := range ms {
		out = append(out, idpMapperToRep(m))
	}
	return ok(w, out)
}

func (h *Handler) createIdPMapper(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	var rep IdPMapperRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if err := h.validateIdPMapper(idp, &rep); err != nil {
		return err
	}
	m := &model.IdentityProviderMapper{ID: service.NewID(), RealmID: realm.ID, IdPAlias: idp.Alias, Name: rep.Name,
		Type: rep.IdentityProviderMapper, Config: rep.Config}
	if err := h.Svc.Store.CreateIdPMapper(r.Context(), m); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return conflict("IDP mapper name must be unique per IDP")
		}
		return err
	}
	return created(w, r, m.ID)
}

func (h *Handler) loadIdPMapper(r *http.Request, realm *model.Realm, idp *model.IdentityProvider) (*model.IdentityProviderMapper, error) {
	m, err := h.Svc.Store.GetIdPMapper(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && m.IdPAlias != idp.Alias) {
		return nil, notFound("Model not found")
	}
	return m, err
}

func (h *Handler) getIdPMapper(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	m, err := h.loadIdPMapper(r, realm, idp)
	if err != nil {
		return err
	}
	return ok(w, idpMapperToRep(m))
}

func (h *Handler) updateIdPMapper(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	m, err := h.loadIdPMapper(r, realm, idp)
	if err != nil {
		return err
	}
	var rep IdPMapperRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Name == "" {
		rep.Name = m.Name
	}
	if rep.IdentityProviderMapper == "" {
		rep.IdentityProviderMapper = m.Type
	}
	if err := h.validateIdPMapper(idp, &rep); err != nil {
		return err
	}
	m.Name, m.Type, m.Config = rep.Name, rep.IdentityProviderMapper, rep.Config
	if err := h.Svc.Store.UpdateIdPMapper(r.Context(), m); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteIdPMapper(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	m, err := h.loadIdPMapper(r, realm, idp)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteIdPMapper(r.Context(), realm.ID, m.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) idpMapperTypes(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewIdPs)
	if err != nil {
		return err
	}
	idp, err := h.loadIdP(r, realm)
	if err != nil {
		return err
	}
	return ok(w, oidc.MapperTypesFor(idp.ProviderID))
}

// ---------------------------------------------------------------- federated identities

func (h *Handler) listFederatedIdentities(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	links, err := h.Svc.Store.ListFederatedIdentities(r.Context(), u.ID)
	if err != nil {
		return err
	}
	out := []FederatedIdentityRep{}
	for _, l := range links {
		out = append(out, FederatedIdentityRep{IdentityProvider: l.IdentityProvider, UserID: l.FederatedUserID, UserName: l.FederatedUsername})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IdentityProvider < out[j].IdentityProvider })
	return ok(w, out)
}

func (h *Handler) addFederatedIdentity(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	alias := r.PathValue("provider")
	if _, err := h.Svc.Store.GetIdentityProvider(r.Context(), realm.ID, alias); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return badRequest("Could not find identity provider")
		}
		return err
	}
	var rep FederatedIdentityRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.UserID == "" {
		return badRequest("Missing userId")
	}
	if _, err := h.Svc.Store.GetFederatedIdentity(r.Context(), u.ID, alias); err == nil {
		return conflict("User is already linked with provider")
	}
	err = h.Svc.Store.CreateFederatedIdentity(r.Context(), &model.FederatedIdentity{UserID: u.ID, RealmID: realm.ID,
		IdentityProvider: alias, FederatedUserID: rep.UserID, FederatedUsername: rep.UserName})
	if errors.Is(err, store.ErrConflict) {
		return conflict("User is already linked with provider")
	}
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) removeFederatedIdentity(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	u, err := h.loadUser(r, realm)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteFederatedIdentity(r.Context(), u.ID, r.PathValue("provider")); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return notFound("Link not found")
		}
		return err
	}
	return noContent(w)
}

func (h *Handler) registerBrokeringRoutes(R string, add func(string, handlerFunc)) {
	const I = "/identity-provider/instances"
	add("GET "+R+I, h.listIdPs)
	add("POST "+R+I, h.createIdP)
	add("GET "+R+I+"/{alias}", h.getIdP)
	add("PUT "+R+I+"/{alias}", h.updateIdP)
	add("DELETE "+R+I+"/{alias}", h.deleteIdP)
	add("GET "+R+I+"/{alias}/mappers", h.listIdPMappers)
	add("POST "+R+I+"/{alias}/mappers", h.createIdPMapper)
	add("GET "+R+I+"/{alias}/mappers/{id}", h.getIdPMapper)
	add("PUT "+R+I+"/{alias}/mappers/{id}", h.updateIdPMapper)
	add("DELETE "+R+I+"/{alias}/mappers/{id}", h.deleteIdPMapper)
	add("GET "+R+I+"/{alias}/mapper-types", h.idpMapperTypes)
	add("GET "+R+"/identity-provider/providers/{provider}", h.getIdPProvider)
	add("POST "+R+"/identity-provider/import-config", h.importIdPConfig)
	add("GET "+R+"/users/{id}/federated-identity", h.listFederatedIdentities)
	add("POST "+R+"/users/{id}/federated-identity/{provider}", h.addFederatedIdentity)
	add("DELETE "+R+"/users/{id}/federated-identity/{provider}", h.removeFederatedIdentity)
}
