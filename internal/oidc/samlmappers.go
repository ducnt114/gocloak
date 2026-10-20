package oidc

import (
	"context"
	"sort"

	"github.com/ducnt114/gocloak/internal/saml"
	"github.com/ducnt114/gocloak/internal/service"
)

// samlNameFormats maps the attribute.nameformat values of SAML mappers.
var samlNameFormats = map[string]string{
	"Basic": saml.AttrNameFormatBasic, "URI Reference": saml.AttrNameFormatURI, "Unspecified": saml.AttrNameFormatUnspecified,
}

// samlAttributes runs the SAML protocol mappers: it returns the attribute
// statement of the assertion and the extra audiences.
func (tc *tokenContext) samlAttributes(ctx context.Context) ([]saml.Attribute, []string, error) {
	var attrs []saml.Attribute
	var audiences []string
	add := func(cfg map[string]string, values []string, aggregate bool) {
		if len(values) == 0 || cfg["attribute.name"] == "" {
			return
		}
		format := samlNameFormats[cfg["attribute.nameformat"]]
		if format == "" {
			format = saml.AttrNameFormatBasic
		}
		if aggregate {
			for i := range attrs {
				if attrs[i].Name == cfg["attribute.name"] && attrs[i].NameFormat == format {
					attrs[i].Values = append(attrs[i].Values, values...)
					return
				}
			}
		}
		attrs = append(attrs, saml.Attribute{Name: cfg["attribute.name"], NameFormat: format,
			FriendlyName: cfg["friendly.name"], Values: values})
	}
	// single: all values in one attribute (true), or one attribute per value
	addList := func(cfg map[string]string, values []string, single bool) {
		if single {
			add(cfg, values, false)
			return
		}
		for _, v := range values {
			add(cfg, []string{v}, false)
		}
	}
	u := tc.user
	// only one role list mapper applies: the client's own
	// (its mappers come first) over the one of the role_list scope
	roleList := ""
	for _, m := range tc.mappers {
		if m.Type == service.SAMLMapperRoleList {
			roleList = m.ID
			break
		}
	}
	for _, m := range tc.mappers {
		cfg := m.Config
		switch m.Type {
		case service.SAMLMapperUserProperty:
			if v, ok := userProperty(u, cfg["user.attribute"]); ok && v != "" {
				add(cfg, []string{v}, false)
			}
		case service.SAMLMapperUserAttribute:
			add(cfg, u.Attributes[cfg["user.attribute"]], cfg["aggregate.attrs"] == "true")
		case service.SAMLMapperHardcodedAttr:
			if v := cfg["attribute.value"]; v != "" {
				add(cfg, []string{v}, false)
			}
		case service.SAMLMapperSessionNote:
			if v := tc.notes[cfg["note"]]; v != "" {
				add(cfg, []string{v}, false)
			}
		case service.SAMLMapperRoleList:
			if m.ID != roleList {
				continue
			}
			seen := map[string]bool{}
			var roles []string
			for _, r := range tc.realmRoles {
				if !seen[r] {
					seen[r] = true
					roles = append(roles, r)
				}
			}
			clients := make([]string, 0, len(tc.clientRoles))
			for c := range tc.clientRoles {
				clients = append(clients, c)
			}
			sort.Strings(clients)
			for _, c := range clients {
				for _, r := range tc.clientRoles[c] {
					if !seen[r] {
						seen[r] = true
						roles = append(roles, r)
					}
				}
			}
			addList(cfg, roles, cfg["single"] == "true")
		case service.SAMLMapperGroups:
			if err := tc.loadGroups(ctx); err != nil {
				return nil, nil, err
			}
			var groups []string
			for _, g := range tc.groups {
				if cfg["full.path"] == "false" {
					groups = append(groups, g.Name)
				} else {
					groups = append(groups, tc.groupPaths[g.ID])
				}
			}
			sort.Strings(groups)
			addList(cfg, groups, cfg["single"] != "false")
		case service.SAMLMapperAudience:
			for _, k := range []string{"included.client.audience", "included.custom.audience"} {
				if v := cfg[k]; v != "" {
					audiences = append(audiences, v)
				}
			}
		case service.SAMLMapperAudienceResolv:
			// the SAML clients the user has roles of
			clients := make([]string, 0, len(tc.clientRoles))
			for c := range tc.clientRoles {
				if c == tc.client.ClientID {
					continue
				}
				other, err := tc.svc.Store.GetClientByClientID(ctx, tc.realm.ID, c)
				if err == nil && other.Protocol == service.ProtocolSAML {
					clients = append(clients, c)
				}
			}
			sort.Strings(clients)
			audiences = append(audiences, clients...)
		}
	}
	return attrs, dedupe(audiences, tc.client.ClientID), nil
}

// dedupe drops duplicates and the excluded value, keeping the order.
func dedupe(values []string, exclude string) []string {
	seen := map[string]bool{exclude: true}
	var out []string
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
