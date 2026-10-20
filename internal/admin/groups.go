package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

func (h *Handler) loadGroup(r *http.Request, realm *model.Realm) (*model.Group, error) {
	g, err := h.Svc.Store.GetGroup(r.Context(), realm.ID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		return nil, notFound("Could not find group by id")
	}
	return g, err
}

// groupTree holds every group of a realm for path and subgroup lookups.
type groupTree struct {
	paths    map[string]string
	children map[string][]*model.Group
}

func (h *Handler) groupTree(ctx context.Context, realmID string) (*groupTree, error) {
	all, err := h.Svc.Store.ListAllGroups(ctx, realmID)
	if err != nil {
		return nil, err
	}
	t := &groupTree{paths: groupPaths(all), children: map[string][]*model.Group{}}
	for _, g := range all {
		t.children[g.ParentID] = append(t.children[g.ParentID], g)
	}
	return t, nil
}

// rep builds a group representation; depth > 0 includes that many levels
// of subgroups.
func (t *groupTree) rep(g *model.Group, depth int) GroupRep {
	rep := groupToRep(g, t.paths[g.ID], len(t.children[g.ID]))
	if depth > 0 {
		for _, c := range t.children[g.ID] {
			rep.SubGroups = append(rep.SubGroups, t.rep(c, depth-1))
		}
	}
	return rep
}

func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryGroups)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	search := q.Get("search")
	if search == "" {
		search = q.Get("q")
	}
	groups, err := h.Svc.Store.ListGroups(r.Context(), realm.ID, "", search, intParam(r, "first", 0), intParam(r, "max", -1))
	if err != nil {
		return err
	}
	t, err := h.groupTree(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	depth := 100 // the full tree, unless briefRepresentation paging is used
	if q.Get("briefRepresentation") == "true" || q.Has("first") || q.Has("max") {
		depth = 0
	}
	out := []GroupRep{}
	for _, g := range groups {
		out = append(out, t.rep(g, depth))
	}
	return ok(w, out)
}

func (h *Handler) countGroups(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryGroups)
	if err != nil {
		return err
	}
	n, err := h.Svc.Store.CountGroups(r.Context(), realm.ID, r.URL.Query().Get("top") == "true")
	if err != nil {
		return err
	}
	return ok(w, map[string]int{"count": n})
}

func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryGroups)
	if err != nil {
		return err
	}
	g, err := h.loadGroup(r, realm)
	if err != nil {
		return err
	}
	t, err := h.groupTree(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	return ok(w, t.rep(g, 100))
}

func (h *Handler) groupByPath(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryGroups)
	if err != nil {
		return err
	}
	t, err := h.groupTree(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	g := t.find(splitPath(r.PathValue("path")))
	if g == nil {
		return notFound("Group path does not exist")
	}
	return ok(w, t.rep(g, 100))
}

func (t *groupTree) find(names []string) *model.Group {
	parent := ""
	var found *model.Group
	for _, n := range names {
		found = nil
		for _, g := range t.children[parent] {
			if g.Name == n {
				found = g
				break
			}
		}
		if found == nil {
			return nil
		}
		parent = found.ID
	}
	return found
}

func (h *Handler) createGroupUnder(w http.ResponseWriter, r *http.Request, realm *model.Realm, parentID string) error {
	var rep GroupRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Name == nil || *rep.Name == "" {
		return badRequest("Group name is missing")
	}
	ctx := r.Context()
	// Posting an existing group's id moves that group.
	if rep.ID != nil && *rep.ID != "" {
		g, err := h.Svc.Store.GetGroup(ctx, realm.ID, *rep.ID)
		if err == nil {
			if g.ID == parentID {
				return badRequest("Cannot move group to itself")
			}
			g.ParentID = parentID
			if err := h.Svc.Store.UpdateGroup(ctx, g); err != nil {
				return groupConflict(err)
			}
			return noContent(w)
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	g := &model.Group{ID: service.NewID(), RealmID: realm.ID, ParentID: parentID, Name: *rep.Name, Attributes: rep.Attributes}
	if err := h.Svc.Store.CreateGroup(ctx, g); err != nil {
		return groupConflict(err)
	}
	if parentID != "" {
		t, err := h.groupTree(ctx, realm.ID)
		if err != nil {
			return err
		}
		u := requestURL(r)
		w.Header().Set("Location", u[:strings.LastIndex(u, "/groups/")]+"/groups/"+g.ID)
		writeJSON(w, http.StatusCreated, t.rep(g, 0))
		return nil
	}
	return created(w, r, g.ID)
}

func groupConflict(err error) error {
	if errors.Is(err, store.ErrConflict) {
		return conflict("Sibling group named already exists.")
	}
	return err
}

func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	return h.createGroupUnder(w, r, realm, "")
}

func (h *Handler) createChildGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	parent, err := h.loadGroup(r, realm)
	if err != nil {
		return err
	}
	return h.createGroupUnder(w, r, realm, parent.ID)
}

func (h *Handler) groupChildren(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permQueryGroups)
	if err != nil {
		return err
	}
	g, err := h.loadGroup(r, realm)
	if err != nil {
		return err
	}
	children, err := h.Svc.Store.ListGroups(r.Context(), realm.ID, g.ID, "", intParam(r, "first", 0), intParam(r, "max", -1))
	if err != nil {
		return err
	}
	t, err := h.groupTree(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	out := []GroupRep{}
	for _, c := range children {
		out = append(out, t.rep(c, 0))
	}
	return ok(w, out)
}

func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	g, err := h.loadGroup(r, realm)
	if err != nil {
		return err
	}
	var rep GroupRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	set(&g.Name, rep.Name)
	if rep.Attributes != nil {
		g.Attributes = rep.Attributes
	}
	if err := h.Svc.Store.UpdateGroup(r.Context(), g); err != nil {
		return groupConflict(err)
	}
	return noContent(w)
}

func (h *Handler) deleteGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	g, err := h.loadGroup(r, realm)
	if err != nil {
		return err
	}
	if err := h.Svc.Store.DeleteGroup(r.Context(), g.ID); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) groupMembers(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewUsers)
	if err != nil {
		return err
	}
	g, err := h.loadGroup(r, realm)
	if err != nil {
		return err
	}
	users, err := h.Svc.Store.GroupMembers(r.Context(), g.ID, intParam(r, "first", 0), intParam(r, "max", 100))
	if err != nil {
		return err
	}
	return ok(w, usersToRep(users))
}

// ---------------------------------------------------------------- default groups

func (h *Handler) listDefaultGroups(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	groups, err := h.Svc.Store.ListDefaultGroups(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	t, err := h.groupTree(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	out := []GroupRep{}
	for _, g := range groups {
		rep := t.rep(g, 0)
		rep.SubGroups = nil
		out = append(out, rep)
	}
	return ok(w, out)
}

func (h *Handler) defaultGroup(w http.ResponseWriter, r *http.Request, p *principal, add bool) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	g, err := h.Svc.Store.GetGroup(r.Context(), realm.ID, r.PathValue("groupId"))
	if errors.Is(err, store.ErrNotFound) {
		return notFound("Group not found")
	}
	if err != nil {
		return err
	}
	if add {
		err = h.Svc.Store.AddDefaultGroup(r.Context(), realm.ID, g.ID)
	} else {
		err = h.Svc.Store.RemoveDefaultGroup(r.Context(), realm.ID, g.ID)
	}
	if err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) addDefaultGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.defaultGroup(w, r, p, true)
}

func (h *Handler) removeDefaultGroup(w http.ResponseWriter, r *http.Request, p *principal) error {
	return h.defaultGroup(w, r, p, false)
}
