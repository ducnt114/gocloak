package store

import (
	"context"
	"encoding/json"
)

// renameUpstreamNames renames the identifiers databases created before
// version 25 hold under the upstream project's name: component types
// (org.keycloak.* to org.gocloak.*), the keycloak-oidc identity provider
// type, the built-in theme names, the WebAuthn relying party name and the
// master realm's display name. The old names below are data to match, not
// names gocloak uses.
func renameUpstreamNames(ctx context.Context, tx *Store) error {
	const oldPrefix, newPrefix = "org.keycloak.", "org.gocloak."
	stmts := []struct {
		q    string
		args []any
	}{
		{`UPDATE components SET provider_type = ? || substr(provider_type, ?) WHERE provider_type LIKE ?`,
			[]any{newPrefix, len(oldPrefix) + 1, oldPrefix + "%"}},
		{`UPDATE identity_providers SET provider_id=? WHERE provider_id=?`, []any{"gocloak-oidc", "keycloak-oidc"}},
		{`UPDATE realms SET display_name=? WHERE name=? AND display_name=?`, []any{"gocloak", "master", "Keycloak"}},
	}
	for _, st := range stmts {
		if err := tx.exec(ctx, st.q, st.args...); err != nil {
			return err
		}
	}
	type row struct{ id, settings string }
	rows, err := queryList(ctx, tx, func(sc scanner) (row, error) {
		var r row
		err := sc.Scan(&r.id, &r.settings)
		return r, err
	}, `SELECT id, settings FROM realms`)
	if err != nil {
		return err
	}
	renamed := map[string]string{"keycloak": "gocloak", "keycloak.v2": "gocloak.v2"}
	fields := []string{"loginTheme", "accountTheme", "emailTheme", "adminTheme",
		"webAuthnPolicyRpEntityName", "webAuthnPolicyPasswordlessRpEntityName"}
	for _, r := range rows {
		var settings map[string]any
		if err := json.Unmarshal([]byte(r.settings), &settings); err != nil {
			return err
		}
		changed := false
		for _, f := range fields {
			if v, ok := settings[f].(string); ok && renamed[v] != "" {
				settings[f] = renamed[v]
				changed = true
			}
		}
		if !changed {
			continue
		}
		b, err := json.Marshal(settings)
		if err != nil {
			return err
		}
		if err := tx.exec(ctx, `UPDATE realms SET settings=? WHERE id=?`, string(b), r.id); err != nil {
			return err
		}
	}
	return nil
}
