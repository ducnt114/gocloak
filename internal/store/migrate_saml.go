package store

import (
	"context"

	"github.com/google/uuid"
)

// addSAMLRoleListScope gives realms created before SAML support the
// "role_list" client scope created for SAML clients. It uses
// explicit columns so that later schema changes do not break it.
func addSAMLRoleListScope(ctx context.Context, tx *Store) error {
	realms, err := queryList(ctx, tx, func(sc scanner) (string, error) {
		var id string
		err := sc.Scan(&id)
		return id, err
	}, `SELECT r.id FROM realms r WHERE EXISTS (SELECT 1 FROM client_scopes s WHERE s.realm_id=r.id)
		AND NOT EXISTS (SELECT 1 FROM client_scopes s WHERE s.realm_id=r.id AND s.name='role_list')`)
	if err != nil {
		return err
	}
	for _, realmID := range realms {
		scopeID := uuid.NewString()
		if err := tx.exec(ctx, `INSERT INTO client_scopes (id, realm_id, name, description, protocol, attributes) VALUES (?,?,?,?,?,?)`,
			scopeID, realmID, "role_list", "SAML role list", "saml",
			`{"consent.screen.text":"${samlRoleListScopeConsentText}","display.on.consent.screen":"true"}`); err != nil {
			return err
		}
		if err := tx.exec(ctx, `INSERT INTO protocol_mappers (id, realm_id, owner_id, name, protocol, mapper_type, config) VALUES (?,?,?,?,?,?,?)`,
			uuid.NewString(), realmID, scopeID, "role list", "saml", "saml-role-list-mapper",
			`{"attribute.name":"Role","attribute.nameformat":"Basic","single":"false"}`); err != nil {
			return err
		}
		if err := tx.exec(ctx, `INSERT INTO realm_default_scopes (realm_id, scope_id, is_default) VALUES (?,?,?)`, realmID, scopeID, true); err != nil {
			return err
		}
	}
	return nil
}
