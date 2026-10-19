-- Security hardening (milestone M2): events, brute force detection,
-- offline sessions, components (key providers), JWT client authentication.

CREATE TABLE IF NOT EXISTS events (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    type       TEXT NOT NULL,
    time       BIGINT NOT NULL,
    client_id  TEXT NOT NULL DEFAULT '',
    user_id    TEXT NOT NULL DEFAULT '',
    session_id TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT '',
    error      TEXT NOT NULL DEFAULT '',
    details    TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_realm_time ON events (realm_id, time);

CREATE TABLE IF NOT EXISTS admin_events (
    id             TEXT PRIMARY KEY,
    realm_id       TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    time           BIGINT NOT NULL,
    operation_type TEXT NOT NULL,
    resource_type  TEXT NOT NULL,
    resource_path  TEXT NOT NULL,
    representation TEXT NOT NULL DEFAULT '',
    auth_realm_id  TEXT NOT NULL DEFAULT '',
    auth_client_id TEXT NOT NULL DEFAULT '',
    auth_user_id   TEXT NOT NULL DEFAULT '',
    auth_ip        TEXT NOT NULL DEFAULT '',
    error          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_admin_events_realm_time ON admin_events (realm_id, time);

CREATE TABLE IF NOT EXISTS login_failures (
    realm_id                TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id                 TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    num_failures            BIGINT NOT NULL DEFAULT 0,
    num_temporary_lockouts  BIGINT NOT NULL DEFAULT 0,
    last_failure            BIGINT NOT NULL DEFAULT 0,
    last_ip                 TEXT NOT NULL DEFAULT '',
    failed_login_not_before BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (realm_id, user_id)
);

-- Offline sessions mirror user_sessions; they survive SSO logout.
CREATE TABLE IF NOT EXISTS offline_sessions (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address   TEXT NOT NULL DEFAULT '',
    started      BIGINT NOT NULL,
    last_refresh BIGINT NOT NULL,
    remember_me  BOOLEAN NOT NULL DEFAULT FALSE,
    clients      TEXT NOT NULL DEFAULT '{}',
    notes        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_offline_sessions_user ON offline_sessions (user_id);

-- Keycloak components (key providers now, user storage later). config is a
-- multivalued map, as in Keycloak: {"priority": ["100"], ...}.
CREATE TABLE IF NOT EXISTS components (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    provider_id   TEXT NOT NULL,
    provider_type TEXT NOT NULL,
    parent_id     TEXT NOT NULL DEFAULT '',
    sub_type      TEXT NOT NULL DEFAULT '',
    config        TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_components_realm ON components (realm_id, provider_type);

ALTER TABLE clients ADD COLUMN client_authenticator_type TEXT NOT NULL DEFAULT 'client-secret';
ALTER TABLE clients ADD COLUMN not_before BIGINT NOT NULL DEFAULT 0;
