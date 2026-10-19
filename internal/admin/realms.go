package admin

import (
	"errors"
	"net/http"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
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
	var rep RealmRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Realm == nil || *rep.Realm == "" {
		return badRequest("Realm name cannot be empty")
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
	var rep RealmRep
	if err := decode(r, &rep); err != nil {
		return err
	}
	if rep.Realm != nil && *rep.Realm != realm.Name && realm.Name == service.MasterRealm {
		return badRequest("Can't rename master realm")
	}
	applyRealmRep(realm, &rep)
	if realm.Name == "" {
		return badRequest("Realm name cannot be empty")
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
	if err := h.Svc.Store.DeleteUserSessionsOfRealm(r.Context(), realm.ID); err != nil {
		return err
	}
	return ok(w, map[string]any{})
}

func (h *Handler) getKeys(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewRealm)
	if err != nil {
		return err
	}
	keys, err := h.Svc.Store.ListRealmKeys(r.Context(), realm.ID)
	if err != nil {
		return err
	}
	type keyRep struct {
		Kid       string `json:"kid"`
		Type      string `json:"type"`
		Algorithm string `json:"algorithm"`
		Use       string `json:"use"`
		Status    string `json:"status"`
		Priority  int    `json:"priority"`
		PublicKey string `json:"publicKey"`
	}
	out := []keyRep{}
	active := map[string]string{}
	activeSet := false
	for _, k := range keys {
		pk, err := jwt.ParsePrivateKey(k.PrivatePEM)
		if err != nil {
			return err
		}
		status := "PASSIVE"
		if k.Active && !activeSet {
			status, activeSet = "ACTIVE", true
			active[k.Algorithm] = k.ID
		}
		out = append(out, keyRep{Kid: k.ID, Type: "RSA", Algorithm: k.Algorithm, Use: "SIG", Status: status,
			Priority: k.Priority, PublicKey: jwt.PublicKeyBase64(&pk.PublicKey)})
	}
	return ok(w, map[string]any{"active": active, "keys": out})
}
