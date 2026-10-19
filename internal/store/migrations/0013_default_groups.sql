-- Default groups of a realm: new users join them.
CREATE TABLE IF NOT EXISTS realm_default_groups (
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES realm_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (realm_id, group_id)
);
