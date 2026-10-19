package store

import (
	"context"
	"encoding/json"
)

// enableLightweightTokens turns on lightweight access tokens for the
// admin-cli and security-admin-console clients of existing realms, as
// Keycloak 26 creates them, unless the attribute was set already.
func enableLightweightTokens(ctx context.Context, tx *Store) error {
	type row struct{ id, attrs string }
	rows, err := queryList(ctx, tx, func(sc scanner) (row, error) {
		var r row
		err := sc.Scan(&r.id, &r.attrs)
		return r, err
	}, `SELECT id, attributes FROM clients WHERE client_id IN ('admin-cli', 'security-admin-console')`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		attrs := map[string]string{}
		_ = json.Unmarshal([]byte(r.attrs), &attrs)
		if _, ok := attrs["client.use.lightweight.access.token.enabled"]; ok {
			continue
		}
		attrs["client.use.lightweight.access.token.enabled"] = "true"
		if err := tx.exec(ctx, `UPDATE clients SET attributes=? WHERE id=?`, toJSON(attrs), r.id); err != nil {
			return err
		}
	}
	return nil
}
