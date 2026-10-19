package store

import (
	"context"

	"github.com/google/uuid"
)

// addRegistrationPolicies gives existing realms Keycloak's default client
// registration policies (explicit columns, see addSAMLRoleListScope).
func addRegistrationPolicies(ctx context.Context, tx *Store) error {
	const typ = "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
	realms, err := queryList(ctx, tx, func(sc scanner) (string, error) {
		var id string
		err := sc.Scan(&id)
		return id, err
	}, `SELECT r.id FROM realms r WHERE NOT EXISTS (SELECT 1 FROM components c WHERE c.realm_id=r.id AND c.provider_type=?)`, typ)
	if err != nil {
		return err
	}
	mappers := `["oidc-usermodel-attribute-mapper","oidc-usermodel-property-mapper","oidc-full-name-mapper","saml-user-property-mapper",` +
		`"oidc-sha256-pairwise-sub-mapper","saml-role-list-mapper","oidc-address-mapper","saml-user-attribute-mapper"]`
	policies := []struct{ sub, name, provider, config string }{
		{"anonymous", "Trusted Hosts", "trusted-hosts", `{"client-uris-must-match":["true"],"host-sending-registration-request-must-match":["true"]}`},
		{"anonymous", "Consent Required", "consent-required", `{}`},
		{"anonymous", "Full Scope Disabled", "scope", `{}`},
		{"anonymous", "Max Clients Limit", "max-clients", `{"max-clients":["200"]}`},
		{"anonymous", "Allowed Protocol Mapper Types", "allowed-protocol-mappers", `{"allowed-protocol-mapper-types":` + mappers + `}`},
		{"anonymous", "Allowed Client Scopes", "allowed-client-templates", `{"allow-default-scopes":["true"]}`},
		{"authenticated", "Allowed Protocol Mapper Types", "allowed-protocol-mappers", `{"allowed-protocol-mapper-types":` + mappers + `}`},
		{"authenticated", "Allowed Client Scopes", "allowed-client-templates", `{"allow-default-scopes":["true"]}`},
	}
	for _, realmID := range realms {
		for _, p := range policies {
			if err := tx.exec(ctx, `INSERT INTO components (id, realm_id, name, provider_id, provider_type, parent_id, sub_type, config)
				VALUES (?,?,?,?,?,?,?,?)`, uuid.NewString(), realmID, p.name, p.provider, typ, realmID, p.sub, p.config); err != nil {
				return err
			}
		}
	}
	return nil
}
