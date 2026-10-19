-- Client scopes, protocol mappers and role scope mappings (milestone M1).

CREATE TABLE IF NOT EXISTS client_scopes (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    protocol    TEXT NOT NULL DEFAULT 'openid-connect',
    attributes  TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, name)
);

-- owner_id is a client id or a client scope id.
CREATE TABLE IF NOT EXISTS protocol_mappers (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    owner_id    TEXT NOT NULL,
    name        TEXT NOT NULL,
    protocol    TEXT NOT NULL DEFAULT 'openid-connect',
    mapper_type TEXT NOT NULL,
    config      TEXT NOT NULL DEFAULT '{}',
    UNIQUE (owner_id, name)
);
CREATE INDEX IF NOT EXISTS idx_protocol_mappers_owner ON protocol_mappers (owner_id);

-- Realm level default (is_default) and optional client scopes for new clients.
CREATE TABLE IF NOT EXISTS realm_default_scopes (
    realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    scope_id   TEXT NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    is_default BOOLEAN NOT NULL,
    PRIMARY KEY (realm_id, scope_id)
);

CREATE TABLE IF NOT EXISTS client_scope_links (
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope_id   TEXT NOT NULL REFERENCES client_scopes(id) ON DELETE CASCADE,
    is_default BOOLEAN NOT NULL,
    PRIMARY KEY (client_id, scope_id)
);

-- Roles a client or client scope may put in tokens when the client does
-- not have full scope allowed. owner_id is a client id or a client scope id.
CREATE TABLE IF NOT EXISTS scope_mappings (
    owner_id TEXT NOT NULL,
    role_id  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (owner_id, role_id)
);

-- Searchable copy of users.attributes, maintained by the store.
CREATE TABLE IF NOT EXISTS user_attributes (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name    TEXT NOT NULL,
    value   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_user_attributes_value ON user_attributes (name, value);
CREATE INDEX IF NOT EXISTS idx_user_attributes_user ON user_attributes (user_id);
