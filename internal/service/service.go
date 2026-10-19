// Package service contains the business logic shared by the OIDC endpoints
// and the admin REST API: realm provisioning, users, credentials, role
// resolution and signing keys.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/password"
	"github.com/ducnt114/gocloak/internal/policy"
	"github.com/ducnt114/gocloak/internal/store"
)

// Well known names, identical to Keycloak's.
const (
	MasterRealm           = "master"
	RealmManagementClient = "realm-management"
	AccountClient         = "account"
	AdminCLIClient        = "admin-cli"
	AdminRole             = "admin"
	CreateRealmRole       = "create-realm"
	RealmAdminRole        = "realm-admin"
	OfflineAccessRole     = "offline_access"
	UMAAuthorizationRole  = "uma_authorization"
	ServiceAccountPrefix  = "service-account-"
	ActionUpdatePassword  = "UPDATE_PASSWORD"
)

// realm-management client roles and the composites Keycloak builds from them.
var (
	managementRoles = []string{
		"view-realm", "manage-realm", "view-users", "manage-users", "query-users", "query-groups",
		"view-clients", "manage-clients", "query-clients", "query-realms", "create-client",
		"view-events", "manage-events", "view-identity-providers", "manage-identity-providers",
		"view-authorization", "manage-authorization", "impersonation",
	}
	managementComposites = map[string][]string{
		"view-users":   {"query-users", "query-groups"},
		"view-clients": {"query-clients"},
	}
	accountRoles      = []string{"manage-account", "view-profile", "manage-account-links", "view-applications", "view-consent", "manage-consent", "delete-account", "view-groups"}
	accountComposites = map[string][]string{
		"manage-account": {"manage-account-links"},
		"manage-consent": {"view-consent"},
	}
)

// ErrValidation wraps user input errors.
var ErrValidation = errors.New("validation error")

func validationf(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrValidation, fmt.Sprintf(format, a...))
}

// Service is safe for concurrent use.
type Service struct {
	Store  *store.Store
	Hasher password.Hasher
	Now    func() time.Time
	Log    *slog.Logger
	// ExtraListeners are event listeners available to realms besides
	// "jboss-logging", by id.
	ExtraListeners map[string]EventListener

	mu   sync.RWMutex
	keys map[string]*keySet // realm id -> keys
}

func New(st *store.Store) *Service {
	return &Service{Store: st, Hasher: password.Default, Now: time.Now, keys: map[string]*keySet{}}
}

func (s *Service) logger() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
}

// NewID returns a random UUID, the id format Keycloak uses.
func NewID() string { return uuid.NewString() }

// RandomToken returns n random bytes, base64url encoded.
func RandomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Service) nowMillis() int64 { return s.Now().UnixMilli() }

// ---------------------------------------------------------------- realms

// NewRealm returns a realm populated with Keycloak's default settings.
func NewRealm(name string) *model.Realm {
	return &model.Realm{
		ID:                    NewID(),
		Name:                  name,
		Enabled:               true,
		AccessTokenLifespan:   300,
		AccessCodeLifespan:    60,
		SSOSessionIdleTimeout: 1800,
		SSOSessionMaxLifespan: 36000,
		LoginWithEmailAllowed: true,
		Attributes:            map[string]string{},
		Settings:              model.DefaultRealmSettings(),
	}
}

// CreateRealm stores r and provisions everything Keycloak creates with a new
// realm: signing key, default roles and the built-in clients.
func (s *Service) CreateRealm(ctx context.Context, st *store.Store, r *model.Realm) error {
	if r.Name == "" || strings.ContainsAny(r.Name, "/ ") {
		return validationf("invalid realm name %q", r.Name)
	}
	if r.ID == "" {
		r.ID = NewID()
	}
	r.CreatedAt = s.Now()
	defaultRole := &model.Role{ID: NewID(), RealmID: r.ID, Name: "default-roles-" + strings.ToLower(r.Name),
		Description: "${role_default-roles}", Composite: true}
	r.DefaultRoleID = defaultRole.ID
	if err := st.CreateRealm(ctx, r); err != nil {
		return err
	}
	if err := s.CreateDefaultKeys(ctx, st, r); err != nil {
		return err
	}
	if err := st.CreateRole(ctx, defaultRole); err != nil {
		return err
	}
	for _, name := range []string{OfflineAccessRole, UMAAuthorizationRole} {
		role := &model.Role{ID: NewID(), RealmID: r.ID, Name: name, Description: "${role_" + name + "}"}
		if err := st.CreateRole(ctx, role); err != nil {
			return err
		}
		if err := st.AddComposite(ctx, defaultRole.ID, role.ID); err != nil {
			return err
		}
	}
	if r.Name == MasterRealm {
		for _, name := range []string{AdminRole, CreateRealmRole} {
			if err := st.CreateRole(ctx, &model.Role{ID: NewID(), RealmID: r.ID, Name: name, Description: "${role_" + name + "}"}); err != nil {
				return err
			}
		}
	}

	// account client: users get view-profile and manage-account by default.
	account := &model.Client{ID: NewID(), RealmID: r.ID, ClientID: AccountClient, Name: "${client_account}",
		Enabled: true, PublicClient: true, StandardFlowEnabled: true, FullScopeAllowed: false,
		Protocol: "openid-connect", RootURL: "${authBaseUrl}", BaseURL: "/realms/" + r.Name + "/account/",
		RedirectURIs: []string{"/realms/" + r.Name + "/account/*"}}
	if err := st.CreateClient(ctx, account); err != nil {
		return err
	}
	accRoles, err := s.createClientRoles(ctx, st, account, accountRoles, accountComposites)
	if err != nil {
		return err
	}
	for _, n := range []string{"view-profile", "manage-account"} {
		if err := st.AddComposite(ctx, defaultRole.ID, accRoles[n].ID); err != nil {
			return err
		}
	}

	adminCLI := &model.Client{ID: NewID(), RealmID: r.ID, ClientID: AdminCLIClient, Name: "${client_admin-cli}",
		Enabled: true, PublicClient: true, DirectAccessGrantsEnabled: true, FullScopeAllowed: true, Protocol: "openid-connect"}
	if err := st.CreateClient(ctx, adminCLI); err != nil {
		return err
	}

	mgmt := &model.Client{ID: NewID(), RealmID: r.ID, ClientID: RealmManagementClient, Name: "${client_realm-management}",
		Enabled: true, BearerOnly: true, FullScopeAllowed: false, Protocol: "openid-connect"}
	if err := st.CreateClient(ctx, mgmt); err != nil {
		return err
	}
	mroles, err := s.createClientRoles(ctx, st, mgmt, managementRoles, managementComposites)
	if err != nil {
		return err
	}
	realmAdmin := &model.Role{ID: NewID(), RealmID: r.ID, ClientID: mgmt.ID, Name: RealmAdminRole, Description: "${role_realm-admin}", Composite: true}
	if err := st.CreateRole(ctx, realmAdmin); err != nil {
		return err
	}
	for _, role := range mroles {
		if err := st.AddComposite(ctx, realmAdmin.ID, role.ID); err != nil {
			return err
		}
	}
	if err := s.ProvisionClientScopes(ctx, st, r); err != nil {
		return err
	}
	return s.ProvisionAuthentication(ctx, st, r)
}

func (s *Service) createClientRoles(ctx context.Context, st *store.Store, c *model.Client, names []string, composites map[string][]string) (map[string]*model.Role, error) {
	out := map[string]*model.Role{}
	for _, n := range names {
		role := &model.Role{ID: NewID(), RealmID: c.RealmID, ClientID: c.ID, Name: n, Description: "${role_" + n + "}"}
		if err := st.CreateRole(ctx, role); err != nil {
			return nil, err
		}
		out[n] = role
	}
	for parent, children := range composites {
		for _, ch := range children {
			if err := st.AddComposite(ctx, out[parent].ID, out[ch].ID); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// DeleteRealm deletes a realm and everything it owns.
func (s *Service) DeleteRealm(ctx context.Context, r *model.Realm) error {
	if r.Name == MasterRealm {
		return validationf("the master realm cannot be deleted")
	}
	if err := s.Store.DeleteRealm(ctx, r.ID); err != nil {
		return err
	}
	s.InvalidateKeys(r.ID)
	return nil
}

// ---------------------------------------------------------------- clients

// CreateClient stores a client, generating a secret for confidential clients
// and the service account user when service accounts are enabled.
func (s *Service) CreateClient(ctx context.Context, st *store.Store, c *model.Client) error {
	if c.ClientID == "" {
		return validationf("clientId is required")
	}
	if c.ID == "" {
		c.ID = NewID()
	}
	if c.Protocol == "" {
		c.Protocol = "openid-connect"
	}
	if !c.PublicClient && !c.BearerOnly && c.Secret == "" {
		c.Secret = RandomToken(24)
	}
	if err := st.CreateClient(ctx, c); err != nil {
		return err
	}
	if err := s.LinkDefaultScopes(ctx, st, c); err != nil {
		return err
	}
	return s.SyncServiceAccount(ctx, st, c)
}

// SyncServiceAccount makes sure a client with service accounts enabled has
// its service-account-<clientId> user.
func (s *Service) SyncServiceAccount(ctx context.Context, st *store.Store, c *model.Client) error {
	if !c.ServiceAccountsEnabled {
		return nil
	}
	if _, err := st.GetServiceAccountUser(ctx, c.ID); err == nil {
		return nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return err
	}
	u := &model.User{
		ID: NewID(), RealmID: c.RealmID, Username: ServiceAccountPrefix + c.ClientID,
		Enabled: true, ServiceAccountClientID: c.ID,
	}
	if err := s.CreateUser(ctx, st, u); err != nil {
		return err
	}
	return s.addServiceAccountMappers(ctx, st, c)
}

// ---------------------------------------------------------------- users

// CreateUser validates and stores a user and grants the realm's default roles.
func (s *Service) CreateUser(ctx context.Context, st *store.Store, u *model.User) error {
	u.Username = strings.ToLower(strings.TrimSpace(u.Username))
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	if u.Username == "" {
		return validationf("username is required")
	}
	realm, err := st.GetRealm(ctx, u.RealmID)
	if err != nil {
		return err
	}
	if err := s.checkEmail(ctx, st, realm, u); err != nil {
		return err
	}
	if u.ID == "" {
		u.ID = NewID()
	}
	if u.CreatedTimestamp == 0 {
		u.CreatedTimestamp = s.nowMillis()
	}
	if u.ServiceAccountClientID == "" {
		// required actions marked "default action" apply to every new user
		actions, err := st.ListRequiredActions(ctx, realm.ID)
		if err != nil {
			return err
		}
		for _, a := range actions {
			if a.DefaultAction && a.Enabled {
				u.RequiredActions, _ = addAction(u.RequiredActions, a.Alias)
			}
		}
	}
	if err := st.CreateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%w: User exists with same username", store.ErrConflict)
		}
		return err
	}
	if realm.DefaultRoleID != "" {
		return st.GrantUserRole(ctx, u.ID, realm.DefaultRoleID)
	}
	return nil
}

// UpdateUser validates and saves changes to a user.
func (s *Service) UpdateUser(ctx context.Context, st *store.Store, u *model.User) error {
	u.Username = strings.ToLower(strings.TrimSpace(u.Username))
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
	if u.Username == "" {
		return validationf("username is required")
	}
	realm, err := st.GetRealm(ctx, u.RealmID)
	if err != nil {
		return err
	}
	if err := s.checkEmail(ctx, st, realm, u); err != nil {
		return err
	}
	if err := st.UpdateUser(ctx, u); err != nil {
		if errors.Is(err, store.ErrConflict) {
			return fmt.Errorf("%w: User exists with same username", store.ErrConflict)
		}
		return err
	}
	return nil
}

func (s *Service) checkEmail(ctx context.Context, st *store.Store, realm *model.Realm, u *model.User) error {
	if u.Email == "" || realm.DuplicateEmailsAllowed {
		return nil
	}
	other, err := st.GetUserByEmail(ctx, realm.ID, u.Email)
	if err == nil && other.ID != u.ID {
		return fmt.Errorf("%w: User exists with same email", store.ErrConflict)
	}
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	return nil
}

// CredentialPasswordHistory is the credential type of previous passwords.
const CredentialPasswordHistory = "password-history"

// passwordPolicy parses the realm's password policy.
func passwordPolicy(realm *model.Realm) (*policy.Policy, error) {
	p, err := policy.Parse(realm.Settings.PasswordPolicy)
	if err != nil {
		return nil, validationf("%s", err.Error())
	}
	return p, nil
}

func (s *Service) hasherFor(p *policy.Policy) password.Hasher {
	if p.HashAlgorithm == "" {
		h := s.Hasher
		if p.HashIterations > 0 {
			h.Iterations = p.HashIterations
		}
		return h
	}
	return password.Hasher{Algorithm: p.HashAlgorithm, Iterations: p.HashIterations}
}

// SetPassword replaces the user's password after checking the realm's
// password policy (violations are *policy.Error). A temporary password
// forces the user to choose a new one on next login. With a
// passwordHistory policy the previous password is kept as history.
func (s *Service) SetPassword(ctx context.Context, st *store.Store, u *model.User, pw string, temporary bool) error {
	if pw == "" {
		return validationf("password must not be empty")
	}
	realm, err := st.GetRealm(ctx, u.RealmID)
	if err != nil {
		return err
	}
	pol, err := passwordPolicy(realm)
	if err != nil {
		return err
	}
	if perr := pol.Validate(pw, policy.Subject{Username: u.Username, Email: u.Email}); perr != nil {
		return perr
	}
	creds, err := st.ListCredentials(ctx, u.ID)
	if err != nil {
		return err
	}
	var current *model.Credential
	var history []*model.Credential
	for _, c := range creds {
		switch c.Type {
		case model.CredentialPassword:
			current = c
		case CredentialPasswordHistory:
			history = append(history, c)
		}
	}
	// newest history first
	sort.Slice(history, func(i, j int) bool { return history[i].CreatedDate > history[j].CreatedDate })
	if pol.History > 0 {
		recent := history
		if len(recent) > pol.History-1 {
			recent = recent[:pol.History-1]
		}
		if current != nil {
			recent = append([]*model.Credential{current}, recent...)
		}
		for _, c := range recent {
			if ok, _ := password.Verify(pw, c.SecretData, c.CredentialData); ok {
				return pol.HistoryError()
			}
		}
	}
	sd, cd, err := s.hasherFor(pol).Hash(pw)
	if err != nil {
		return err
	}
	if err := st.DeleteCredentialsOfType(ctx, u.ID, model.CredentialPassword); err != nil {
		return err
	}
	if err := st.DeleteCredentialsOfType(ctx, u.ID, CredentialPasswordHistory); err != nil {
		return err
	}
	if pol.History > 1 {
		keep := history
		if current != nil {
			old := *current
			old.ID, old.Type = NewID(), CredentialPasswordHistory
			keep = append([]*model.Credential{&old}, keep...)
		}
		if len(keep) > pol.History-1 {
			keep = keep[:pol.History-1]
		}
		for _, c := range keep {
			if err := st.CreateCredential(ctx, c); err != nil {
				return err
			}
		}
	}
	if err := st.CreateCredential(ctx, &model.Credential{ID: NewID(), UserID: u.ID, Type: model.CredentialPassword,
		SecretData: sd, CredentialData: cd, CreatedDate: s.nowMillis(), Priority: 10}); err != nil {
		return err
	}
	changed := false
	if temporary {
		u.RequiredActions, changed = addAction(u.RequiredActions, ActionUpdatePassword)
	} else {
		u.RequiredActions, changed = removeAction(u.RequiredActions, ActionUpdatePassword)
	}
	if changed {
		return st.UpdateUser(ctx, u)
	}
	return nil
}

// CheckPassword verifies pw against the user's stored password. A correct
// password stored with other hashing parameters than the realm's policy is
// re-hashed, as Keycloak does.
func (s *Service) CheckPassword(ctx context.Context, u *model.User, pw string) (bool, error) {
	creds, err := s.Store.ListCredentials(ctx, u.ID)
	if err != nil {
		return false, err
	}
	for _, c := range creds {
		if c.Type != model.CredentialPassword {
			continue
		}
		ok, err := password.Verify(pw, c.SecretData, c.CredentialData)
		if err != nil {
			return false, err
		}
		if ok {
			s.rehashIfNeeded(ctx, u, c, pw)
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) rehashIfNeeded(ctx context.Context, u *model.User, c *model.Credential, pw string) {
	realm, err := s.Store.GetRealm(ctx, u.RealmID)
	if err != nil {
		return
	}
	pol, err := passwordPolicy(realm)
	if err != nil || (pol.HashAlgorithm == "" && pol.HashIterations == 0) {
		return
	}
	h := s.hasherFor(pol)
	alg, iter := password.Params(c.CredentialData)
	if alg == h.Algorithm && (h.Iterations == 0 || iter == h.Iterations) {
		return
	}
	sd, cd, err := h.Hash(pw)
	if err != nil {
		return
	}
	if err := s.Store.UpdateCredentialSecret(ctx, c.ID, sd, cd); err != nil {
		s.logger().Warn("rehash password", "user", u.ID, "err", err)
	}
}

// PasswordExpired reports whether the forceExpiredPasswordChange policy
// requires the user to choose a new password.
func (s *Service) PasswordExpired(ctx context.Context, realm *model.Realm, u *model.User) (bool, error) {
	pol, err := passwordPolicy(realm)
	if err != nil || pol.ExpireDays == 0 {
		return false, err
	}
	creds, err := s.Store.ListCredentials(ctx, u.ID)
	if err != nil {
		return false, err
	}
	for _, c := range creds {
		if c.Type == model.CredentialPassword {
			age := s.Now().UnixMilli() - c.CreatedDate
			return age > int64(pol.ExpireDays)*24*3600*1000, nil
		}
	}
	return false, nil
}

// FindLoginUser resolves the identifier typed in a login form, which may be
// a username or (when the realm allows it) an email.
func (s *Service) FindLoginUser(ctx context.Context, realm *model.Realm, ident string) (*model.User, error) {
	u, err := s.Store.GetUserByUsername(ctx, realm.ID, ident)
	if errors.Is(err, store.ErrNotFound) && realm.LoginWithEmailAllowed && strings.Contains(ident, "@") {
		u, err = s.Store.GetUserByEmail(ctx, realm.ID, ident)
	}
	if err != nil {
		return nil, err
	}
	if u.ServiceAccountClientID != "" {
		return nil, store.ErrNotFound // service accounts cannot log in interactively
	}
	return u, nil
}

func addAction(actions []string, a string) ([]string, bool) {
	for _, x := range actions {
		if x == a {
			return actions, false
		}
	}
	return append(actions, a), true
}

func removeAction(actions []string, a string) ([]string, bool) {
	out := actions[:0:0]
	for _, x := range actions {
		if x != a {
			out = append(out, x)
		}
	}
	return out, len(out) != len(actions)
}

// RemoveRequiredAction removes a required action from a user and saves it.
func (s *Service) RemoveRequiredAction(ctx context.Context, u *model.User, a string) error {
	var changed bool
	if u.RequiredActions, changed = removeAction(u.RequiredActions, a); changed {
		return s.Store.UpdateUser(ctx, u)
	}
	return nil
}

// ---------------------------------------------------------------- roles

// EffectiveRoles returns all roles a user has: direct mappings, mappings of
// the user's groups and their ancestors, and everything reachable through
// composite roles.
func (s *Service) EffectiveRoles(ctx context.Context, realmID, userID string) ([]*model.Role, error) {
	st := s.Store
	direct, err := st.UserRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	seeds := map[string]bool{}
	for _, r := range direct {
		seeds[r.ID] = true
	}
	groups, err := st.UserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}
	all, err := st.ListAllGroups(ctx, realmID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.Group{}
	for _, g := range all {
		byID[g.ID] = g
	}
	visited := map[string]bool{}
	for _, g := range groups {
		for cur := g; cur != nil && !visited[cur.ID]; cur = byID[cur.ParentID] {
			visited[cur.ID] = true
			roles, err := st.GroupRoles(ctx, cur.ID)
			if err != nil {
				return nil, err
			}
			for _, r := range roles {
				seeds[r.ID] = true
			}
		}
	}
	return s.expandRoles(ctx, realmID, seeds)
}

// ExpandComposites returns the given roles plus everything they include.
func (s *Service) ExpandComposites(ctx context.Context, realmID string, roles []*model.Role) ([]*model.Role, error) {
	seeds := map[string]bool{}
	for _, r := range roles {
		seeds[r.ID] = true
	}
	return s.expandRoles(ctx, realmID, seeds)
}

func (s *Service) expandRoles(ctx context.Context, realmID string, seeds map[string]bool) ([]*model.Role, error) {
	if len(seeds) == 0 {
		return nil, nil
	}
	edges, err := s.Store.CompositeEdges(ctx, realmID)
	if err != nil {
		return nil, err
	}
	allRoles, err := s.Store.ListAllRoles(ctx, realmID)
	if err != nil {
		return nil, err
	}
	roleByID := map[string]*model.Role{}
	for _, r := range allRoles {
		roleByID[r.ID] = r
	}
	seen := map[string]bool{}
	var stack []string
	for id := range seeds {
		stack = append(stack, id)
	}
	var out []*model.Role
	for len(stack) > 0 {
		id := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[id] {
			continue
		}
		seen[id] = true
		if r := roleByID[id]; r != nil {
			out = append(out, r)
		}
		stack = append(stack, edges[id]...)
	}
	return out, nil
}

// ---------------------------------------------------------------- sessions

// SessionValid reports whether an SSO session is still within the realm's
// idle timeout and max lifespan.
func (s *Service) SessionValid(realm *model.Realm, us *model.UserSession) bool {
	now := s.Now()
	if us.Offline {
		idle := realm.Settings.OfflineSessionIdleTimeout
		if idle > 0 && now.After(us.LastRefresh.Add(time.Duration(idle)*time.Second)) {
			return false
		}
		if realm.Settings.OfflineSessionMaxLifespanEnabled {
			return !now.After(us.Started.Add(time.Duration(realm.Settings.OfflineSessionMaxLifespan) * time.Second))
		}
		return true
	}
	idle := realm.SSOSessionIdleTimeout
	if us.RememberMe && realm.Settings.SSOSessionIdleTimeoutRememberMe > 0 {
		idle = realm.Settings.SSOSessionIdleTimeoutRememberMe
	}
	if now.After(us.LastRefresh.Add(time.Duration(idle) * time.Second)) {
		return false
	}
	return !now.After(us.Started.Add(time.Duration(s.SessionMaxLifespan(realm, us)) * time.Second))
}

// SessionMaxLifespan is the max lifespan of an SSO session in seconds,
// which "remember me" sessions may extend.
func (s *Service) SessionMaxLifespan(realm *model.Realm, us *model.UserSession) int {
	if us.RememberMe && realm.Settings.SSOSessionMaxLifespanRememberMe > 0 {
		return realm.Settings.SSOSessionMaxLifespanRememberMe
	}
	return realm.SSOSessionMaxLifespan
}

// ---------------------------------------------------------------- bootstrap

// Bootstrap creates the master realm and the initial admin user on first start.
func (s *Service) Bootstrap(ctx context.Context, adminUser, adminPassword string) (created bool, err error) {
	if _, err := s.Store.GetRealmByName(ctx, MasterRealm); err == nil {
		return false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	err = s.Store.WithTx(ctx, func(tx *store.Store) error {
		master := NewRealm(MasterRealm)
		master.DisplayName = "Keycloak"
		if err := s.CreateRealm(ctx, tx, master); err != nil {
			return err
		}
		if adminUser == "" {
			return nil
		}
		return s.ensureAdmin(ctx, tx, master, adminUser, adminPassword)
	})
	return err == nil, err
}

// EnsureAdmin creates, or resets the password of, a master realm user with
// the admin and create-realm roles.
func (s *Service) EnsureAdmin(ctx context.Context, username, password string) error {
	master, err := s.Store.GetRealmByName(ctx, MasterRealm)
	if err != nil {
		return err
	}
	return s.Store.WithTx(ctx, func(tx *store.Store) error {
		return s.ensureAdmin(ctx, tx, master, username, password)
	})
}

func (s *Service) ensureAdmin(ctx context.Context, tx *store.Store, master *model.Realm, username, password string) error {
	u, err := tx.GetUserByUsername(ctx, master.ID, username)
	if errors.Is(err, store.ErrNotFound) {
		u = &model.User{RealmID: master.ID, Username: username, Enabled: true}
		err = s.CreateUser(ctx, tx, u)
	}
	if err != nil {
		return err
	}
	if err := s.SetPassword(ctx, tx, u, password, false); err != nil {
		return err
	}
	for _, name := range []string{AdminRole, CreateRealmRole} {
		role, err := tx.GetRoleByName(ctx, master.ID, "", name)
		if err != nil {
			return err
		}
		if err := tx.GrantUserRole(ctx, u.ID, role.ID); err != nil {
			return err
		}
	}
	return nil
}
