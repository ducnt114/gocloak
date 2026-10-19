package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/policy"
	"github.com/ducnt114/gocloak/internal/service"
	"github.com/ducnt114/gocloak/internal/store"
)

func (h *Handler) realmRep(r *http.Request, realm *model.Realm) (RealmRep, error) {
	var dr *model.Role
	if realm.DefaultRoleID != "" {
		var err error
		if dr, err = h.Svc.Store.GetRole(r.Context(), realm.ID, realm.DefaultRoleID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return RealmRep{}, err
		}
	}
	return realmToRep(realm, dr), nil
}

func (h *Handler) listRealms(w http.ResponseWriter, r *http.Request, p *principal) error {
	realms, err := h.Svc.Store.ListRealms(r.Context())
	if err != nil {
		return err
	}
	out := []RealmRep{}
	for _, realm := range realms {
		if !p.can(realm, permViewRealm) {
			continue
		}
		rep, err := h.realmRep(r, realm)
		if err != nil {
			return err
		}
		out = append(out, rep)
	}
	return ok(w, out)
}

func (h *Handler) createRealm(w http.ResponseWriter, r *http.Request, p *principal) error {
	if !p.superAdmin && !p.createRealm {
		return forbidden()
	}
	rep := NewRealmRep()
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Realm == nil || *rep.Realm == "" {
		return badRequest("Realm name cannot be empty")
	}
	if _, err := policy.Parse(rep.PasswordPolicy); err != nil {
		return badRequest(err.Error())
	}
	if _, err := h.Svc.Store.GetRealmByName(r.Context(), *rep.Realm); err == nil {
		return conflict("Conflict detected. See logs for details")
	}
	realm, err := Import(r.Context(), h.Svc, &rep)
	if err != nil {
		return err
	}
	h.Log.Info("realm created", "realm", realm.Name)
	w.Header().Set("Location", requestURL(r)+"/"+realm.Name)
	w.WriteHeader(http.StatusCreated)
	return nil
}

func (h *Handler) getRealm(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	rep, err := h.realmRep(r, realm)
	if err != nil {
		return err
	}
	return ok(w, rep)
}

func (h *Handler) updateRealm(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 10<<20))
	if err != nil {
		return badRequest("Invalid body")
	}
	var rep RealmRep
	if err := json.Unmarshal(body, &rep); err != nil {
		return badRequest("Invalid JSON: " + err.Error())
	}
	if err := json.Unmarshal(body, &realm.Settings); err != nil {
		return badRequest("Invalid JSON: " + err.Error())
	}
	if rep.Realm != nil && *rep.Realm != realm.Name && realm.Name == service.MasterRealm {
		return badRequest("Can't rename master realm")
	}
	applyRealmRep(realm, &rep)
	if realm.Name == "" {
		return badRequest("Realm name cannot be empty")
	}
	if _, err := policy.Parse(realm.Settings.PasswordPolicy); err != nil {
		return badRequest(err.Error())
	}
	if err := h.Svc.Store.UpdateRealm(r.Context(), realm); err != nil {
		return err
	}
	return noContent(w)
}

func (h *Handler) deleteRealm(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageRealm)
	if err != nil {
		return err
	}
	if err := h.Svc.DeleteRealm(r.Context(), realm); err != nil {
		return err
	}
	h.Log.Info("realm deleted", "realm", realm.Name)
	return noContent(w)
}

func (h *Handler) logoutAll(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	sessions, err := h.Svc.Store.ListRealmSessions(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	h.Svc.BackchannelLogout(r.Context(), h.URLs.Base(r), realm, sessions...)
	if err := h.Svc.Store.DeleteUserSessionsOfRealm(r.Context(), realm.ID); err != nil {
		return err
	}
	return ok(w, map[string]any{})
}

// deleteSession ends one user session (DELETE /sessions/{session}).
func (h *Handler) deleteSession(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageUsers)
	if err != nil {
		return err
	}
	offline := r.URL.Query().Get("isOffline") == "true"
	s, err := h.Svc.Store.GetSession(r.Context(), r.PathValue("session"), offline)
	if err != nil || s.RealmID != realm.ID {
		return notFound("Session not found")
	}
	if !offline {
		h.Svc.BackchannelLogout(r.Context(), h.URLs.Base(r), realm, s)
	}
	if err := h.Svc.Store.DeleteSession(r.Context(), s); err != nil {
		return err
	}
	return noContent(w)
}
