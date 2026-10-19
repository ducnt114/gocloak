package service

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// ConsentItem is something a user consents to: a client scope, or the
// client itself when it has a consent text of its own (display.on.consent.screen).
type ConsentItem struct {
	ID   string // client scope id, or the client UUID
	Name string // client scope name, or the client id
	Text string // consent text: "${key}" message reference or literal text
}

// ConsentItems returns what the user is asked to consent to for a client
// and its applied client scopes, in Keycloak's terms.
func ConsentItems(c *model.Client, scopes []*model.ClientScope) []ConsentItem {
	var out []ConsentItem
	for _, s := range scopes {
		if s.Attributes["display.on.consent.screen"] == "false" {
			continue
		}
		text := s.Attributes["consent.screen.text"]
		if text == "" {
			text = s.Name
		}
		out = append(out, ConsentItem{ID: s.ID, Name: s.Name, Text: text})
	}
	if c.Attributes["display.on.consent.screen"] == "true" {
		text := c.Attributes["consent.screen.text"]
		if text == "" {
			text = c.ClientID
		}
		out = append(out, ConsentItem{ID: c.ID, Name: c.ClientID, Text: text})
	}
	return out
}

// GrantConsent records that the user granted the items, keeping what was
// granted before.
func (s *Service) GrantConsent(ctx context.Context, st *store.Store, realmID, userID string, c *model.Client, items []ConsentItem) error {
	now := s.Now().UnixMilli()
	consent, err := st.GetConsent(ctx, userID, c.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		consent = &model.UserConsent{UserID: userID, ClientID: c.ID, Created: now}
	case err != nil:
		return err
	}
	for _, it := range items {
		if !contains(consent.Scopes, it.ID) {
			consent.Scopes = append(consent.Scopes, it.ID)
		}
	}
	consent.Updated = now
	return st.SaveConsent(ctx, realmID, consent)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ClientGrant is what a user gave a client: a stored consent and/or
// offline tokens.
type ClientGrant struct {
	Client  *model.Client
	Consent *model.UserConsent // nil without a stored consent
	Items   []ConsentItem      // the granted items that still exist
	Offline bool
	Created int64 // millis
	Updated int64
}

// UserGrants lists the consents and offline tokens of a user, by client.
func (s *Service) UserGrants(ctx context.Context, realm *model.Realm, user *model.User) ([]*ClientGrant, error) {
	st := s.Store
	byClient := map[string]*ClientGrant{}
	var order []string
	get := func(clientID string) *ClientGrant {
		if g := byClient[clientID]; g != nil {
			return g
		}
		c, err := st.GetClient(ctx, realm.ID, clientID)
		if err != nil {
			return nil
		}
		g := &ClientGrant{Client: c}
		byClient[clientID] = g
		order = append(order, clientID)
		return g
	}
	consents, err := st.ListConsents(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if len(consents) > 0 {
		scopes, err := st.ListClientScopes(ctx, realm.ID)
		if err != nil {
			return nil, err
		}
		byID := map[string]*model.ClientScope{}
		for _, sc := range scopes {
			byID[sc.ID] = sc
		}
		for _, cn := range consents {
			g := get(cn.ClientID)
			if g == nil {
				continue
			}
			g.Consent, g.Created, g.Updated = cn, cn.Created, cn.Updated
			var granted []*model.ClientScope
			own := false
			for _, id := range cn.Scopes {
				if id == g.Client.ID {
					own = true
				} else if sc := byID[id]; sc != nil {
					granted = append(granted, sc)
				}
			}
			for _, it := range ConsentItems(g.Client, granted) {
				if it.ID != g.Client.ID {
					g.Items = append(g.Items, it)
				}
			}
			if own {
				text := g.Client.Attributes["consent.screen.text"]
				if text == "" {
					text = g.Client.ClientID
				}
				g.Items = append(g.Items, ConsentItem{ID: g.Client.ID, Name: g.Client.ClientID, Text: text})
			}
		}
	}
	offline, err := st.ListOfflineSessions(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	for _, us := range offline {
		ids := make([]string, 0, len(us.Clients))
		for id := range us.Clients {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			g := get(id)
			if g == nil {
				continue
			}
			if !g.Offline && g.Consent == nil {
				g.Created, g.Updated = us.Started.UnixMilli(), us.LastRefresh.UnixMilli()
			}
			g.Offline = true
		}
	}
	out := make([]*ClientGrant, 0, len(order))
	for _, id := range order {
		out = append(out, byClient[id])
	}
	return out, nil
}

// RevokeGrant removes the consent and the offline tokens a user gave a
// client; it reports whether there was anything to revoke.
func (s *Service) RevokeGrant(ctx context.Context, user *model.User, c *model.Client) (bool, error) {
	st := s.Store
	found := false
	if err := st.DeleteConsent(ctx, user.ID, c.ID); err == nil {
		found = true
	} else if !errors.Is(err, store.ErrNotFound) {
		return false, err
	}
	sessions, err := st.ListOfflineSessions(ctx, user.ID)
	if err != nil {
		return false, err
	}
	for _, us := range sessions {
		if !us.Clients[c.ID] {
			continue
		}
		found = true
		delete(us.Clients, c.ID)
		if len(us.Clients) == 0 {
			err = st.DeleteSession(ctx, us)
		} else {
			err = st.UpdateUserSession(ctx, us)
		}
		if err != nil {
			return false, err
		}
	}
	return found, nil
}

// MessageRef returns the message key of a "${key}" text, or "".
func MessageRef(text string) string {
	if strings.HasPrefix(text, "${") && strings.HasSuffix(text, "}") {
		return text[2 : len(text)-1]
	}
	return ""
}
