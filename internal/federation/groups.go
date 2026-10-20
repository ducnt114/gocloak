package federation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

// Group and role mappers map LDAP groups (groupOfNames entries with member
// attributes) to groups or roles.

// groupMapping is the configuration of a group-ldap-mapper or
// role-ldap-mapper.
type groupMapping struct {
	m             mapper
	roles         bool
	dn            string
	nameAttr      string
	objectClasses []string
	filter        string
	memberAttr    string
	memberType    string // DN or UID
	memberUser    string // user attribute for UID memberships
	mode          string // READ_ONLY, LDAP_ONLY, IMPORT
	inheritance   bool
	path          string // parent group path (groups)
	realmRoles    bool
	clientID      string
	dropMissing   bool
}

const emptyMember = "cn=empty-membership-placeholder"

func cfgOr(m mapper, key, def string) string {
	if v := strings.TrimSpace(m.Get(key)); v != "" {
		return v
	}
	return def
}

func mappingOf(m mapper, p *provider) *groupMapping {
	g := &groupMapping{m: m, roles: m.ProviderID == "role-ldap-mapper"}
	prefix := "group"
	if g.roles {
		prefix = "role"
		g.dn = m.Get("roles.dn")
		g.filter = m.Get("roles.ldap.filter")
		g.realmRoles = m.Get("use.realm.roles.mapping") == "true"
		g.clientID = m.Get("client.id")
	} else {
		g.dn = m.Get("groups.dn")
		g.filter = m.Get("groups.ldap.filter")
		g.inheritance = cfgOr(m, "preserve.group.inheritance", "true") == "true"
		g.path = cfgOr(m, "groups.path", "/")
		g.dropMissing = m.Get("drop.non.existing.groups.during.sync") == "true"
	}
	g.nameAttr = cfgOr(m, prefix+".name.ldap.attribute", "cn")
	for _, oc := range strings.Split(cfgOr(m, prefix+".object.classes", "groupOfNames"), ",") {
		if oc = strings.TrimSpace(oc); oc != "" {
			g.objectClasses = append(g.objectClasses, oc)
		}
	}
	g.memberAttr = cfgOr(m, "membership.ldap.attribute", "member")
	g.memberType = cfgOr(m, "membership.attribute.type", "DN")
	g.memberUser = cfgOr(m, "membership.user.ldap.attribute", p.cfg.UsernameAttr)
	g.mode = cfgOr(m, "mode", "READ_ONLY")
	return g
}

func (g *groupMapping) groupFilter(extra string) string {
	var b strings.Builder
	b.WriteString("(&")
	for _, oc := range g.objectClasses {
		b.WriteString("(objectclass=" + ldap.EscapeFilter(oc) + ")")
	}
	if f := strings.TrimSpace(g.filter); f != "" {
		b.WriteString(f)
	}
	b.WriteString(extra)
	b.WriteString(")")
	return b.String()
}

// ldapGroup is a group entry with its parent (inheritance) in the tree.
type ldapGroup struct {
	name    string
	dn      string
	members []string
	parent  *ldapGroup
}

// path is the group path below the mapper's parent path.
func (lg *ldapGroup) path() []string {
	if lg.parent == nil {
		return []string{lg.name}
	}
	return append(lg.parent.path(), lg.name)
}

// loadGroups reads all groups of a mapper, linking parents through the
// membership attribute when inheritance is preserved.
func (g *groupMapping) loadGroups(c *conn) ([]*ldapGroup, error) {
	entries, err := c.search(g.dn, ldap.ScopeSingleLevel, g.groupFilter(""), []string{g.nameAttr, g.memberAttr})
	if err != nil {
		return nil, err
	}
	byDN := map[string]*ldapGroup{}
	var out []*ldapGroup
	for _, e := range entries {
		lg := &ldapGroup{name: e.GetEqualFoldAttributeValue(g.nameAttr), dn: e.DN, members: e.GetEqualFoldAttributeValues(g.memberAttr)}
		if lg.name == "" {
			continue
		}
		byDN[normDN(e.DN)] = lg
		out = append(out, lg)
	}
	if g.inheritance && !g.roles {
		for _, lg := range out {
			for _, mdn := range lg.members {
				if child := byDN[normDN(mdn)]; child != nil && child != lg && child.parent == nil {
					child.parent = lg
				}
			}
		}
		// break cycles
		for _, lg := range out {
			seen := map[*ldapGroup]bool{}
			for p := lg; p != nil; p = p.parent {
				if seen[p] {
					lg.parent = nil
					break
				}
				seen[p] = true
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return len(out[i].path()) < len(out[j].path()) || (len(out[i].path()) == len(out[j].path()) && out[i].name < out[j].name)
	})
	return out, nil
}

func normDN(dn string) string {
	parts := strings.Split(dn, ",")
	for i, p := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(p))
	}
	return strings.Join(parts, ",")
}

// memberValue is how a user appears in the membership attribute.
func (g *groupMapping) memberValue(u *model.User, e *ldap.Entry) string {
	if strings.EqualFold(g.memberType, "UID") {
		if e != nil {
			return e.GetEqualFoldAttributeValue(g.memberUser)
		}
		return u.Username
	}
	if e != nil {
		return e.DN
	}
	return first(u.Attributes[AttrLDAPDN])
}

func (g *groupMapping) isMember(lg *ldapGroup, value string) bool {
	for _, m := range lg.members {
		if strings.EqualFold(g.memberType, "UID") && strings.EqualFold(m, value) || normDN(m) == normDN(value) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- local groups and roles

// parentGroup finds or creates the group of a path (e.g. "/ldap").
func ensureGroupPath(ctx context.Context, st *store.Store, realmID string, names []string) (*model.Group, bool, error) {
	all, err := st.ListAllGroups(ctx, realmID)
	if err != nil {
		return nil, false, err
	}
	parent := ""
	var g *model.Group
	created := false
	for _, n := range names {
		g = nil
		for _, x := range all {
			if x.ParentID == parent && x.Name == n {
				g = x
				break
			}
		}
		if g == nil {
			g = &model.Group{ID: service.NewID(), RealmID: realmID, Name: n, ParentID: parent, Attributes: map[string][]string{}}
			if err := st.CreateGroup(ctx, g); err != nil {
				return nil, false, err
			}
			all = append(all, g)
			created = true
		}
		parent = g.ID
	}
	return g, created, nil
}

func splitPath(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' })
}

func (g *groupMapping) groupNames(lg *ldapGroup) []string {
	return append(splitPath(g.path), lg.path()...)
}

// localRole finds or creates the role of an LDAP group.
func (g *groupMapping) localRole(ctx context.Context, st *store.Store, realm *model.Realm, name string, create bool) (*model.Role, bool, error) {
	clientUUID := ""
	if !g.realmRoles {
		c, err := st.GetClientByClientID(ctx, realm.ID, g.clientID)
		if err != nil {
			return nil, false, fmt.Errorf("role mapper client %q: %w", g.clientID, err)
		}
		clientUUID = c.ID
	}
	r, err := st.GetRoleByName(ctx, realm.ID, clientUUID, name)
	if err == nil || !errors.Is(err, store.ErrNotFound) || !create {
		return r, false, err
	}
	r = &model.Role{ID: service.NewID(), RealmID: realm.ID, ClientID: clientUUID, Name: name, Attributes: map[string][]string{}}
	return r, true, st.CreateRole(ctx, r)
}

// applyMemberships sets the groups and roles mappers give a user: on import,
// and at every login or sync for mappers not in IMPORT mode.
func (m *Manager) applyMemberships(ctx context.Context, st *store.Store, realm *model.Realm, p *provider, c *conn, u *model.User, e *ldap.Entry, imported bool) error {
	for _, mp := range p.mappers {
		switch mp.ProviderID {
		case "hardcoded-ldap-role-mapper":
			role, err := findRoleRef(ctx, st, realm, mp.Get("role"))
			if err != nil {
				m.logger().Warn("hardcoded ldap role mapper", "mapper", mp.Name, "err", err)
				continue
			}
			if err := st.GrantUserRole(ctx, u.ID, role.ID); err != nil {
				return err
			}
		case "hardcoded-ldap-group-mapper":
			names := splitPath(mp.Get("group"))
			if len(names) == 0 {
				continue
			}
			grp, _, err := ensureGroupPath(ctx, st, realm.ID, names)
			if err != nil {
				return err
			}
			if err := st.AddUserToGroup(ctx, u.ID, grp.ID); err != nil {
				return err
			}
		case "group-ldap-mapper", "role-ldap-mapper":
			g := mappingOf(mp, p)
			if g.mode == "IMPORT" && !imported {
				continue
			}
			if err := m.syncUserMemberships(ctx, st, realm, g, c, u, e); err != nil {
				m.logger().Warn("ldap group mapper", "mapper", mp.Name, "user", u.Username, "err", err)
			}
		}
	}
	return nil
}

func (m *Manager) syncUserMemberships(ctx context.Context, st *store.Store, realm *model.Realm, g *groupMapping, c *conn, u *model.User, e *ldap.Entry) error {
	groups, err := g.loadGroups(c)
	if err != nil {
		return err
	}
	value := g.memberValue(u, e)
	if g.roles {
		current, err := st.UserRoles(ctx, u.ID)
		if err != nil {
			return err
		}
		has := map[string]bool{}
		for _, r := range current {
			has[r.ID] = true
		}
		for _, lg := range groups {
			member := g.isMember(lg, value)
			role, _, err := g.localRole(ctx, st, realm, lg.name, member)
			if err != nil || role == nil {
				continue
			}
			switch {
			case member && !has[role.ID]:
				err = st.GrantUserRole(ctx, u.ID, role.ID)
			case !member && has[role.ID] && g.mode != "IMPORT":
				err = st.RevokeUserRole(ctx, u.ID, role.ID)
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	current, err := st.UserGroups(ctx, u.ID)
	if err != nil {
		return err
	}
	has := map[string]bool{}
	for _, cg := range current {
		has[cg.ID] = true
	}
	for _, lg := range groups {
		member := g.isMember(lg, value)
		if !member && g.mode == "IMPORT" {
			continue
		}
		grp, _, err := ensureGroupPath(ctx, st, realm.ID, g.groupNames(lg))
		if err != nil {
			return err
		}
		switch {
		case member && !has[grp.ID]:
			err = st.AddUserToGroup(ctx, u.ID, grp.ID)
		case !member && has[grp.ID]:
			err = st.RemoveUserFromGroup(ctx, u.ID, grp.ID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// findRoleRef resolves "role" or "clientId.role".
func findRoleRef(ctx context.Context, st *store.Store, realm *model.Realm, ref string) (*model.Role, error) {
	if i := strings.LastIndex(ref, "."); i > 0 {
		for j := i; j > 0; j = strings.LastIndex(ref[:j], ".") {
			if c, err := st.GetClientByClientID(ctx, realm.ID, ref[:j]); err == nil {
				if r, err := st.GetRoleByName(ctx, realm.ID, c.ID, ref[j+1:]); err == nil {
					return r, nil
				}
			}
		}
	}
	return st.GetRoleByName(ctx, realm.ID, "", ref)
}

// ---------------------------------------------------------------- membership changes

// GroupMembership implements service.UserFederation: in LDAP_ONLY mode the
// membership is written to LDAP, in READ_ONLY mode it cannot change.
func (m *Manager) GroupMembership(ctx context.Context, realm *model.Realm, u *model.User, grp *model.Group, join bool) error {
	if u.FederationLink == "" {
		return nil
	}
	p, err := m.providerOf(ctx, u)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil || !p.cfg.Enabled {
		return err
	}
	path, err := groupPathOf(ctx, m.Svc.Store, realm.ID, grp)
	if err != nil {
		return err
	}
	for _, mp := range p.mappers {
		if mp.ProviderID != "group-ldap-mapper" {
			continue
		}
		g := mappingOf(mp, p)
		parent := splitPath(g.path)
		if len(path) <= len(parent) || strings.Join(path[:len(parent)], "/") != strings.Join(parent, "/") || g.mode == "IMPORT" {
			continue
		}
		if g.mode != "LDAP_ONLY" {
			continue // READ_ONLY: a local change, overwritten from LDAP at the next login or sync
		}
		c, err := dial(p.cfg)
		if err != nil {
			return err
		}
		defer c.Close()
		groups, err := g.loadGroups(c)
		if err != nil {
			return err
		}
		for _, lg := range groups {
			if strings.Join(g.groupNames(lg), "/") != strings.Join(path, "/") {
				continue
			}
			value := g.memberValue(u, nil)
			req := ldap.NewModifyRequest(lg.dn, nil)
			if join {
				if g.isMember(lg, value) {
					return nil
				}
				req.Add(g.memberAttr, []string{value})
			} else {
				if !g.isMember(lg, value) {
					return nil
				}
				if len(lg.members) == 1 && strings.EqualFold(g.memberAttr, "member") {
					req.Replace(g.memberAttr, []string{emptyMember}) // groupOfNames needs a member
				} else {
					req.Delete(g.memberAttr, []string{value})
				}
			}
			return c.Modify(req)
		}
	}
	return nil
}

func groupPathOf(ctx context.Context, st *store.Store, realmID string, g *model.Group) ([]string, error) {
	all, err := st.ListAllGroups(ctx, realmID)
	if err != nil {
		return nil, err
	}
	byID := map[string]*model.Group{}
	for _, x := range all {
		byID[x.ID] = x
	}
	var names []string
	for x := g; x != nil; x = byID[x.ParentID] {
		names = append([]string{x.Name}, names...)
		if x.ParentID == "" {
			break
		}
	}
	return names, nil
}

// ---------------------------------------------------------------- mapper sync

// SyncMapper synchronizes the groups or roles of a group / role mapper:
// fedToGocloak imports them, gocloakToFed writes local ones to LDAP.
func (m *Manager) SyncMapper(ctx context.Context, realm *model.Realm, providerComp, mapperComp *model.Component, direction string) (*SyncResult, error) {
	p, err := m.loadProvider(ctx, providerComp)
	if err != nil {
		return nil, err
	}
	if mapperComp.ProviderID != "group-ldap-mapper" && mapperComp.ProviderID != "role-ldap-mapper" {
		return &SyncResult{Ignored: true, Status: "Ignored as the mapper does not support synchronization"}, nil
	}
	g := mappingOf(mapper{mapperComp}, p)
	c, err := dial(p.cfg)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	groups, err := g.loadGroups(c)
	if err != nil {
		return nil, err
	}
	kind := "groups"
	if g.roles {
		kind = "roles"
	}
	res := &SyncResult{}
	st := m.Svc.Store
	if direction == "gocloakToFed" {
		if err := m.syncToLDAP(ctx, realm, g, c, groups, res); err != nil {
			return nil, err
		}
		res.Status = fmt.Sprintf("%d %s imported to LDAP, %d %s updated to LDAP, %d %s removed from LDAP", res.Added, kind, res.Updated, kind, res.Removed, kind)
		return res, nil
	}
	err = st.WithTx(ctx, func(tx *store.Store) error {
		seen := map[string]bool{}
		for _, lg := range groups {
			if g.roles {
				_, created, err := g.localRole(ctx, tx, realm, lg.name, true)
				if err != nil {
					return err
				}
				seen[lg.name] = true
				if created {
					res.Added++
				} else {
					res.Updated++
				}
				continue
			}
			grp, created, err := ensureGroupPath(ctx, tx, realm.ID, g.groupNames(lg))
			if err != nil {
				return err
			}
			seen[grp.ID] = true
			if created {
				res.Added++
			} else {
				res.Updated++
			}
		}
		if g.dropMissing && !g.roles {
			all, err := tx.ListAllGroups(ctx, realm.ID)
			if err != nil {
				return err
			}
			parent, _, err := ensureGroupPath(ctx, tx, realm.ID, splitPath(g.path))
			if err != nil && len(splitPath(g.path)) > 0 {
				return err
			}
			parentID := ""
			if parent != nil {
				parentID = parent.ID
			}
			for _, x := range all {
				if x.ParentID == parentID && !seen[x.ID] {
					if err := tx.DeleteGroup(ctx, x.ID); err == nil {
						res.Removed++
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if g.roles {
		res.Status = fmt.Sprintf("%d imported roles, %d roles already exists in gocloak", res.Added, res.Updated)
	} else {
		res.Status = fmt.Sprintf("%d imported groups, %d updated groups, %d removed groups", res.Added, res.Updated, res.Removed)
	}
	// memberships are read from LDAP; imported users get them now
	users, err := st.ListFederatedUsers(ctx, realm.ID, p.cfg.ID)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		e, err := m.findEntry(c, p, u)
		if err != nil || e == nil {
			continue
		}
		if err := m.syncUserMemberships(ctx, st, realm, g, c, u, e); err != nil {
			m.logger().Warn("ldap mapper sync: memberships", "user", u.Username, "err", err)
		}
	}
	return res, nil
}

// findGroup resolves a group path.
func findGroup(ctx context.Context, st *store.Store, realmID string, names []string) (*model.Group, error) {
	all, err := st.ListAllGroups(ctx, realmID)
	if err != nil {
		return nil, err
	}
	parent := ""
	var g *model.Group
	for _, n := range names {
		g = nil
		for _, x := range all {
			if x.ParentID == parent && x.Name == n {
				g = x
				break
			}
		}
		if g == nil {
			return nil, store.ErrNotFound
		}
		parent = g.ID
	}
	return g, nil
}

// syncToLDAP creates LDAP groups for the local groups (or roles) of a
// mapper, with the memberships of LDAP users.
func (m *Manager) syncToLDAP(ctx context.Context, realm *model.Realm, g *groupMapping, c *conn, existing []*ldapGroup, res *SyncResult) error {
	st := m.Svc.Store
	have := map[string]bool{}
	for _, lg := range existing {
		have[strings.ToLower(lg.name)] = true
	}
	type local struct {
		name    string
		members []string
	}
	var locals []local
	memberOf := func(users []*model.User) []string {
		var out []string
		for _, u := range users {
			if v := g.memberValue(u, nil); v != "" && u.FederationLink != "" {
				out = append(out, v)
			}
		}
		return out
	}
	if g.roles {
		clientUUID := ""
		if !g.realmRoles {
			cl, err := st.GetClientByClientID(ctx, realm.ID, g.clientID)
			if err != nil {
				return err
			}
			clientUUID = cl.ID
		}
		roles, err := st.ListRoles(ctx, realm.ID, clientUUID, "", 0, 1<<30)
		if err != nil {
			return err
		}
		for _, r := range roles {
			if !g.realmRoles || (!strings.HasPrefix(r.Name, "default-roles-") && r.Name != "offline_access" && r.Name != "uma_authorization") {
				users, err := st.UsersWithRole(ctx, r.ID, 0, 1<<30)
				if err != nil {
					return err
				}
				locals = append(locals, local{r.Name, memberOf(users)})
			}
		}
	} else {
		parent, _, err := ensureGroupPath(ctx, st, realm.ID, splitPath(g.path))
		if err != nil && len(splitPath(g.path)) > 0 {
			return err
		}
		parentID := ""
		if parent != nil {
			parentID = parent.ID
		}
		all, err := st.ListAllGroups(ctx, realm.ID)
		if err != nil {
			return err
		}
		for _, x := range all {
			if x.ParentID != parentID {
				continue
			}
			users, err := st.GroupMembers(ctx, x.ID, 0, 1<<30)
			if err != nil {
				return err
			}
			locals = append(locals, local{x.Name, memberOf(users)})
		}
	}
	for _, l := range locals {
		if have[strings.ToLower(l.name)] {
			res.Updated++
			continue
		}
		dn := ldap.EscapeDN(g.nameAttr) + "=" + ldap.EscapeDN(l.name) + "," + g.dn
		req := ldap.NewAddRequest(dn, nil)
		req.Attribute("objectclass", g.objectClasses)
		req.Attribute(g.nameAttr, []string{l.name})
		members := l.members
		if len(members) == 0 && strings.EqualFold(g.memberAttr, "member") {
			members = []string{emptyMember}
		}
		if len(members) > 0 {
			req.Attribute(g.memberAttr, members)
		}
		if err := c.Add(req); err != nil {
			m.logger().Warn("ldap group sync", "group", l.name, "err", err)
			res.Failed++
			continue
		}
		res.Added++
	}
	return nil
}
