package federation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Manager implements service.UserFederation for the LDAP providers of all
// realms.
type Manager struct {
	Svc *service.Service
	Log *slog.Logger

	mu      sync.Mutex
	running map[string]bool // providers being synchronized
}

var _ service.UserFederation = (*Manager)(nil)

// provider is a loaded LDAP provider with its mappers.
type provider struct {
	cfg     *Config
	comp    *model.Component
	mappers []mapper
}

func (m *Manager) loadProvider(ctx context.Context, c *model.Component) (*provider, error) {
	comps, err := m.Svc.Store.ListComponents(ctx, c.RealmID, MapperType)
	if err != nil {
		return nil, err
	}
	p := &provider{cfg: ParseConfig(c), comp: c}
	for _, mc := range comps {
		if mc.ParentID == c.ID {
			p.mappers = append(p.mappers, mapper{mc})
		}
	}
	// the username mapper first: other mappers may depend on the username
	sort.SliceStable(p.mappers, func(i, j int) bool {
		return p.mappers[i].Get("user.model.attribute") == "username" && p.mappers[j].Get("user.model.attribute") != "username"
	})
	return p, nil
}

// providers lists the realm's enabled LDAP providers by priority.
func (m *Manager) providers(ctx context.Context, realmID string) ([]*provider, error) {
	comps, err := m.Svc.Store.ListComponents(ctx, realmID, ProviderType)
	if err != nil {
		return nil, err
	}
	var out []*provider
	for _, c := range comps {
		if c.ProviderID != ProviderLDAP || c.Get("enabled") == "false" {
			continue
		}
		p, err := m.loadProvider(ctx, c)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].cfg.Priority < out[j].cfg.Priority })
	return out, nil
}

// providerOf loads the provider an imported user is linked to.
func (m *Manager) providerOf(ctx context.Context, u *model.User) (*provider, error) {
	c, err := m.Svc.Store.GetComponent(ctx, u.RealmID, u.FederationLink)
	if err != nil {
		return nil, err
	}
	return m.loadProvider(ctx, c)
}

func (m *Manager) logger() *slog.Logger {
	if m.Log != nil {
		return m.Log
	}
	return slog.Default()
}

// ---------------------------------------------------------------- lookup and import

// LookupUser implements service.UserFederation.
func (m *Manager) LookupUser(ctx context.Context, realm *model.Realm, ident string) (*model.User, error) {
	ps, err := m.providers(ctx, realm.ID)
	if err != nil || len(ps) == 0 {
		return nil, err
	}
	for _, p := range ps {
		c, err := dial(p.cfg)
		if err != nil {
			m.logger().Warn("ldap connection", "provider", p.cfg.Name, "err", err)
			continue
		}
		attrs := ldapAttrs(p.cfg, p.mappers)
		entries, err := c.searchUsers(eq(p.cfg.UsernameAttr, ident), attrs)
		if err == nil && len(entries) == 0 && realm.LoginWithEmailAllowed && strings.Contains(ident, "@") {
			entries, err = c.searchUsers(eq(p.emailAttr(), ident), attrs)
		}
		if err != nil || len(entries) != 1 {
			c.Close()
			if err != nil {
				m.logger().Warn("ldap search", "provider", p.cfg.Name, "err", err)
			}
			continue
		}
		u, err := m.importUser(ctx, m.Svc.Store, realm, p, c, entries[0])
		c.Close()
		if errors.Is(err, errDuplicate) {
			return nil, nil
		}
		return u, err
	}
	return nil, nil
}

func (p *provider) emailAttr() string {
	for _, mp := range p.mappers {
		if mp.attrMapper() && mp.Get("user.model.attribute") == "email" {
			return mp.Get("ldap.attribute")
		}
	}
	return "mail"
}

var errDuplicate = errors.New("a local user with the same username or email exists")

// importUser creates the local user of an LDAP entry.
func (m *Manager) importUser(ctx context.Context, st *store.Store, realm *model.Realm, p *provider, c *conn, e *ldap.Entry) (*model.User, error) {
	username := strings.ToLower(e.GetEqualFoldAttributeValue(p.cfg.UsernameAttr))
	if username == "" {
		return nil, fmt.Errorf("ldap entry %s has no %s", e.DN, p.cfg.UsernameAttr)
	}
	if existing, err := st.GetUserByUsername(ctx, realm.ID, username); err == nil {
		m.logger().Warn("ldap user not imported: a user with the same username exists", "provider", p.cfg.Name, "username", username,
			"linked", existing.FederationLink)
		return nil, errDuplicate
	}
	u := &model.User{RealmID: realm.ID, Username: username, Enabled: true, FederationLink: p.cfg.ID,
		EmailVerified: p.cfg.TrustEmail, Attributes: map[string][]string{}}
	importEntry(p.cfg, u, e, p.mappers, false)
	if !p.cfg.ImportEnabled {
		u.ID = "f:" + p.cfg.ID + ":" + p.cfg.entryUUID(e)
	}
	err := st.WithTx(ctx, func(tx *store.Store) error {
		if err := m.Svc.CreateUser(ctx, tx, u); err != nil {
			return err
		}
		return m.applyMemberships(ctx, tx, realm, p, c, u, e, true)
	})
	if errors.Is(err, store.ErrConflict) {
		m.logger().Warn("ldap user not imported", "provider", p.cfg.Name, "username", username, "err", err)
		return nil, errDuplicate
	}
	return u, err
}

// ValidateUser implements service.UserFederation.
func (m *Manager) ValidateUser(ctx context.Context, realm *model.Realm, u *model.User) (*model.User, error) {
	p, err := m.providerOf(ctx, u)
	if errors.Is(err, store.ErrNotFound) {
		return u, nil // the provider is gone: a plain local user
	}
	if err != nil {
		return nil, err
	}
	if !p.cfg.Enabled {
		disabled := *u
		disabled.Enabled = false
		return &disabled, nil
	}
	c, err := dial(p.cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap provider %s: %w", p.cfg.Name, err)
	}
	defer c.Close()
	e, err := m.findEntry(c, p, u)
	if err != nil {
		return nil, err
	}
	if e == nil {
		// removed from LDAP: the imported user is removed too
		m.logger().Info("ldap user removed from the directory", "provider", p.cfg.Name, "username", u.Username)
		return nil, m.Svc.Store.DeleteUser(ctx, realm.ID, u.ID)
	}
	if !strings.EqualFold(e.GetEqualFoldAttributeValue(p.cfg.UsernameAttr), u.Username) {
		// renamed in LDAP: the imported user is stale
		return nil, m.Svc.Store.DeleteUser(ctx, realm.ID, u.ID)
	}
	changed := importEntry(p.cfg, u, e, p.mappers, true)
	err = m.Svc.Store.WithTx(ctx, func(tx *store.Store) error {
		if changed {
			if err := tx.UpdateUser(ctx, u); err != nil {
				return err
			}
		}
		return m.applyMemberships(ctx, tx, realm, p, c, u, e, false)
	})
	return u, err
}

// findEntry finds a user's entry by its LDAP_ID.
func (m *Manager) findEntry(c *conn, p *provider, u *model.User) (*ldap.Entry, error) {
	id := first(u.Attributes[AttrLDAPID])
	if id == "" {
		return nil, nil
	}
	entries, err := c.searchUsers(p.cfg.uuidFilter(id), ldapAttrs(p.cfg, p.mappers))
	if err != nil || len(entries) == 0 {
		return nil, err
	}
	return entries[0], nil
}

// ---------------------------------------------------------------- passwords

// CheckPassword implements service.UserFederation.
func (m *Manager) CheckPassword(ctx context.Context, realm *model.Realm, u *model.User, password string) (bool, error) {
	p, err := m.providerOf(ctx, u)
	if err != nil {
		return false, err
	}
	if !p.cfg.Enabled {
		return false, nil
	}
	dn := first(u.Attributes[AttrLDAPDN])
	if dn == "" {
		return false, nil
	}
	ok, err := checkPassword(p.cfg, dn, password)
	if err != nil {
		return false, fmt.Errorf("ldap provider %s: %w", p.cfg.Name, err)
	}
	return ok, nil
}

// PasswordMode implements service.UserFederation.
func (m *Manager) PasswordMode(ctx context.Context, realm *model.Realm, u *model.User) (service.PasswordMode, error) {
	p, err := m.providerOf(ctx, u)
	if errors.Is(err, store.ErrNotFound) {
		return service.PasswordMode{ValidatePolicy: true}, nil
	}
	if err != nil {
		return service.PasswordMode{}, err
	}
	switch p.cfg.EditMode {
	case Writable:
		return service.PasswordMode{Remote: true, ValidatePolicy: p.cfg.ValidatePasswordPolicy}, nil
	case ReadOnly:
		return service.PasswordMode{ReadOnly: true}, nil
	}
	return service.PasswordMode{ValidatePolicy: true}, nil // UNSYNCED: stored locally
}

// UpdatePassword implements service.UserFederation.
func (m *Manager) UpdatePassword(ctx context.Context, realm *model.Realm, u *model.User, password string) error {
	p, err := m.providerOf(ctx, u)
	if err != nil {
		return err
	}
	c, err := dial(p.cfg)
	if err != nil {
		return fmt.Errorf("ldap provider %s: %w", p.cfg.Name, err)
	}
	defer c.Close()
	return c.setPassword(first(u.Attributes[AttrLDAPDN]), password)
}

// ---------------------------------------------------------------- writes

// UserCreated implements service.UserFederation: with syncRegistrations,
// new users are created in the first writable provider.
func (m *Manager) UserCreated(ctx context.Context, st *store.Store, realm *model.Realm, u *model.User) error {
	ps, err := m.providers(ctx, realm.ID)
	if err != nil {
		return err
	}
	for _, p := range ps {
		if !p.cfg.SyncRegistrations || !p.cfg.Writable() {
			continue
		}
		c, err := dial(p.cfg)
		if err != nil {
			return fmt.Errorf("ldap provider %s: %w", p.cfg.Name, err)
		}
		defer c.Close()
		attrs := newEntry(p.cfg, u, p.mappers)
		dn := userDN(p.cfg, attrs)
		req := ldap.NewAddRequest(dn, nil)
		names := make([]string, 0, len(attrs))
		for k := range attrs {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			req.Attribute(k, attrs[k])
		}
		if err := c.Add(req); err != nil {
			return fmt.Errorf("ldap provider %s: create %s: %w", p.cfg.Name, dn, err)
		}
		e, err := c.entryByDN(dn, ldapAttrs(p.cfg, p.mappers))
		if err != nil || e == nil {
			return fmt.Errorf("ldap provider %s: read back %s: %v", p.cfg.Name, dn, err)
		}
		u.FederationLink = p.cfg.ID
		for _, mp := range p.mappers {
			if mp.attrMapper() && mp.bool("read.only") && mp.Get("user.model.attribute") != "username" {
				setModel(u, mp.Get("user.model.attribute"), values(e, mp.Get("ldap.attribute"), mp.bool("is.binary.attribute")))
			}
		}
		setModel(u, AttrLDAPID, []string{p.cfg.entryUUID(e)})
		setModel(u, AttrLDAPDN, []string{e.DN})
		return st.UpdateUser(ctx, u)
	}
	return nil
}

// UserUpdated implements service.UserFederation.
func (m *Manager) UserUpdated(ctx context.Context, realm *model.Realm, old, u *model.User) error {
	p, err := m.providerOf(ctx, u)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil || p.cfg.EditMode == Unsynced {
		return err
	}
	mods, errs := changes(p.cfg, old, u, p.mappers)
	if len(errs) > 0 {
		return errs
	}
	if len(mods) == 0 {
		return nil
	}
	c, err := dial(p.cfg)
	if err != nil {
		return fmt.Errorf("ldap provider %s: %w", p.cfg.Name, err)
	}
	defer c.Close()
	dn := first(u.Attributes[AttrLDAPDN])
	if v, ok := mods["userAccountControl"]; ok && v == nil {
		e, err := c.entryByDN(dn, []string{"userAccountControl"})
		if err != nil || e == nil {
			return fmt.Errorf("ldap provider %s: %v", p.cfg.Name, err)
		}
		uac, _ := strconv.Atoi(e.GetAttributeValue("userAccountControl"))
		if u.Enabled {
			uac &^= 2
		} else {
			uac |= 2
		}
		mods["userAccountControl"] = []string{strconv.Itoa(uac)}
	}
	// a new RDN value renames the entry
	if v, ok := mods[p.cfg.RDNAttr]; ok && len(v) > 0 {
		newRDN := ldap.EscapeDN(p.cfg.RDNAttr) + "=" + ldap.EscapeDN(v[0])
		if err := c.ModifyDN(ldap.NewModifyDNRequest(dn, newRDN, true, "")); err != nil {
			return fmt.Errorf("ldap provider %s: rename %s: %w", p.cfg.Name, dn, err)
		}
		_, parent, _ := strings.Cut(dn, ",")
		dn = newRDN + "," + parent
		u.Attributes[AttrLDAPDN] = []string{dn}
		delete(mods, p.cfg.RDNAttr)
	}
	if len(mods) == 0 {
		return nil
	}
	req := ldap.NewModifyRequest(dn, nil)
	names := make([]string, 0, len(mods))
	for k := range mods {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if len(mods[k]) == 0 {
			req.Replace(k, []string{})
		} else {
			req.Replace(k, mods[k])
		}
	}
	if err := c.Modify(req); err != nil {
		return fmt.Errorf("ldap provider %s: update %s: %w", p.cfg.Name, dn, err)
	}
	return nil
}

// UserDeleted implements service.UserFederation: the entry is removed from
// a writable provider; otherwise only the local user is deleted (and comes
// back on the next lookup).
func (m *Manager) UserDeleted(ctx context.Context, realm *model.Realm, u *model.User) error {
	p, err := m.providerOf(ctx, u)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil || !p.cfg.Writable() || !p.cfg.Enabled {
		return err
	}
	dn := first(u.Attributes[AttrLDAPDN])
	if dn == "" {
		return nil
	}
	c, err := dial(p.cfg)
	if err != nil {
		return fmt.Errorf("ldap provider %s: %w", p.cfg.Name, err)
	}
	defer c.Close()
	if err := c.Del(ldap.NewDelRequest(dn, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		return fmt.Errorf("ldap provider %s: delete %s: %w", p.cfg.Name, dn, err)
	}
	return nil
}

// ---------------------------------------------------------------- synchronization

// SyncResult is the synchronization result representation.
type SyncResult struct {
	Ignored bool   `json:"ignored"`
	Added   int    `json:"added"`
	Updated int    `json:"updated"`
	Removed int    `json:"removed"`
	Failed  int    `json:"failed"`
	Status  string `json:"status"`
}

func (r *SyncResult) finish() {
	r.Status = fmt.Sprintf("%d imported users, %d updated users", r.Added, r.Updated)
	if r.Removed > 0 {
		r.Status += fmt.Sprintf(", %d removed users", r.Removed)
	}
	if r.Failed > 0 {
		r.Status += fmt.Sprintf(", %d users failed sync! See server log for more details", r.Failed)
	}
}

// SyncUsers imports or updates the provider's users: all of them, or only
// those created or modified since the last synchronization.
func (m *Manager) SyncUsers(ctx context.Context, realm *model.Realm, comp *model.Component, changedOnly bool) (*SyncResult, error) {
	m.mu.Lock()
	if m.running == nil {
		m.running = map[string]bool{}
	}
	if m.running[comp.ID] {
		m.mu.Unlock()
		return &SyncResult{Ignored: true, Status: "Synchronization ignored as it's already in progress"}, nil
	}
	m.running[comp.ID] = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.running, comp.ID)
		m.mu.Unlock()
	}()

	p, err := m.loadProvider(ctx, comp)
	if err != nil {
		return nil, err
	}
	started := m.Svc.Now()
	c, err := dial(p.cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	extra := ""
	if changedOnly && p.cfg.LastSync > 0 {
		since := generalizedTime(time.Unix(p.cfg.LastSync, 0))
		created, modified := "createTimestamp", "modifyTimestamp"
		if p.cfg.ActiveDirectory() {
			created, modified = "whenCreated", "whenChanged"
		}
		extra = "(|(" + created + ">=" + since + ")(" + modified + ">=" + since + "))"
	}
	entries, err := c.searchUsers(extra, ldapAttrs(p.cfg, p.mappers))
	if err != nil {
		return nil, err
	}
	res := &SyncResult{}
	seen := map[string]bool{}
	for _, e := range entries {
		id := p.cfg.entryUUID(e)
		seen[id] = true
		local, err := m.Svc.Store.FindUserByAttribute(ctx, realm.ID, AttrLDAPID, id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if local != nil && local.FederationLink == p.cfg.ID {
			importEntry(p.cfg, local, e, p.mappers, false)
			err := m.Svc.Store.WithTx(ctx, func(tx *store.Store) error {
				if err := tx.UpdateUser(ctx, local); err != nil {
					return err
				}
				return m.applyMemberships(ctx, tx, realm, p, c, local, e, false)
			})
			if err != nil {
				m.logger().Warn("ldap sync: update user", "provider", p.cfg.Name, "username", local.Username, "err", err)
				res.Failed++
				continue
			}
			res.Updated++
			continue
		}
		if _, err := m.importUser(ctx, m.Svc.Store, realm, p, c, e); err != nil {
			m.logger().Warn("ldap sync: import user", "provider", p.cfg.Name, "dn", e.DN, "err", err)
			res.Failed++
			continue
		}
		res.Added++
	}
	if !changedOnly && p.cfg.RemoveInvalidUsers {
		users, err := m.Svc.Store.ListFederatedUsers(ctx, realm.ID, p.cfg.ID)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if !seen[first(u.Attributes[AttrLDAPID])] {
				if err := m.Svc.Store.DeleteUser(ctx, realm.ID, u.ID); err == nil {
					res.Removed++
				}
			}
		}
	}
	comp.Set("lastSync", strconv.FormatInt(started.Unix(), 10))
	if err := m.Svc.Store.UpdateComponent(ctx, comp); err != nil {
		return nil, err
	}
	res.finish()
	return res, nil
}

// RemoveImportedUsers deletes the local users imported from a provider.
func (m *Manager) RemoveImportedUsers(ctx context.Context, realm *model.Realm, comp *model.Component) error {
	users, err := m.Svc.Store.ListFederatedUsers(ctx, realm.ID, comp.ID)
	if err != nil {
		return err
	}
	for _, u := range users {
		if err := m.Svc.Store.DeleteUser(ctx, realm.ID, u.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return nil
}

// UnlinkUsers turns the users imported from a provider into local users.
func (m *Manager) UnlinkUsers(ctx context.Context, realm *model.Realm, comp *model.Component) error {
	users, err := m.Svc.Store.ListFederatedUsers(ctx, realm.ID, comp.ID)
	if err != nil {
		return err
	}
	for _, u := range users {
		u.FederationLink = ""
		if err := m.Svc.Store.UpdateUser(ctx, u); err != nil {
			return err
		}
	}
	return nil
}

// RunPeriodicSync synchronizes providers with fullSyncPeriod or
// changedSyncPeriod until ctx ends.
func (m *Manager) RunPeriodicSync(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.periodicSync(ctx)
		}
	}
}

func (m *Manager) periodicSync(ctx context.Context) {
	// one node of a cluster synchronizes at a time
	unlock, ok, err := m.Svc.Store.TryLock(ctx, "federation-sync")
	if err != nil || !ok {
		return
	}
	defer unlock()
	realms, err := m.Svc.Store.ListRealms(ctx)
	if err != nil {
		return
	}
	now := m.Svc.Now().Unix()
	for _, realm := range realms {
		comps, err := m.Svc.Store.ListComponents(ctx, realm.ID, ProviderType)
		if err != nil {
			continue
		}
		for _, c := range comps {
			cfg := ParseConfig(c)
			if c.ProviderID != ProviderLDAP || !cfg.Enabled {
				continue
			}
			var changedOnly bool
			switch {
			case cfg.FullSyncPeriod > 0 && now-cfg.LastSync >= int64(cfg.FullSyncPeriod):
			case cfg.ChangedSyncPeriod > 0 && now-cfg.LastSync >= int64(cfg.ChangedSyncPeriod):
				changedOnly = true
			default:
				continue
			}
			res, err := m.SyncUsers(ctx, realm, c, changedOnly)
			if err != nil {
				m.logger().Warn("periodic ldap sync", "realm", realm.Name, "provider", cfg.Name, "err", err)
				continue
			}
			m.logger().Info("periodic ldap sync", "realm", realm.Name, "provider", cfg.Name, "status", res.Status)
		}
	}
}

// ---------------------------------------------------------------- connection test

// TestConnection checks a connection URL (and the bind credentials when
// authenticate is set), returning the console's error keys.
func TestConnection(cfg *Config, authenticate bool) error {
	c, err := dialOnly(cfg, cfg.ConnectionURL)
	if err != nil {
		return errors.New("SocketReset")
	}
	defer c.Close()
	if authenticate && cfg.AuthType == "simple" {
		if err := c.Bind(cfg.BindDN, cfg.BindCredential); err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return errors.New("AuthenticationFailure")
			}
			return errors.New("LDAP test error")
		}
	}
	return nil
}
