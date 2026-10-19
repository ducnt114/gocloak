package store

import (
	"context"
	"encoding/json"
)

// realmAttributeDefaults mirrors service.RealmAttributeDefaults at the time
// of the migration.
var realmAttributeDefaults = map[string]string{
	"cibaBackchannelTokenDeliveryMode": "poll", "cibaExpiresIn": "120", "cibaAuthRequestedUserHint": "login_hint",
	"cibaInterval": "5", "oauth2DeviceCodeLifespan": "600", "oauth2DevicePollingInterval": "5",
	"parRequestUriLifespan": "60", "realmReusableOtpCode": "false",
}

// addRealmAttributeDefaults gives existing realms the device flow, CIBA and
// PAR attributes Keycloak creates realms with.
func addRealmAttributeDefaults(ctx context.Context, tx *Store) error {
	type row struct{ id, attrs string }
	rows, err := queryList(ctx, tx, func(sc scanner) (row, error) {
		var r row
		err := sc.Scan(&r.id, &r.attrs)
		return r, err
	}, `SELECT id, attributes FROM realms`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		attrs := map[string]string{}
		_ = json.Unmarshal([]byte(r.attrs), &attrs)
		changed := false
		for k, v := range realmAttributeDefaults {
			if _, ok := attrs[k]; !ok {
				attrs[k] = v
				changed = true
			}
		}
		if changed {
			if err := tx.exec(ctx, `UPDATE realms SET attributes=? WHERE id=?`, toJSON(attrs), r.id); err != nil {
				return err
			}
		}
	}
	return nil
}
