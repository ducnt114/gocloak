CREATE TABLE IF NOT EXISTS realms (
    id                       TEXT PRIMARY KEY,
    name                     TEXT NOT NULL UNIQUE,
    display_name             TEXT NOT NULL DEFAULT '',
    enabled                  BOOLEAN NOT NULL DEFAULT 1,
    access_token_lifespan    INTEGER NOT NULL,
    access_code_lifespan     INTEGER NOT NULL,
    sso_session_idle_timeout INTEGER NOT NULL,
    sso_session_max_lifespan INTEGER NOT NULL,
    login_with_email_allowed BOOLEAN NOT NULL DEFAULT 1,
    duplicate_emails_allowed BOOLEAN NOT NULL DEFAULT 0,
    registration_allowed     BOOLEAN NOT NULL DEFAULT 0,
    default_role_id          TEXT NOT NULL DEFAULT '',
    attributes               TEXT NOT NULL DEFAULT '{}',
    created_at               INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id                           TEXT PRIMARY KEY,
    realm_id                     TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id                    TEXT NOT NULL,
    name                         TEXT NOT NULL DEFAULT '',
    description                  TEXT NOT NULL DEFAULT '',
    enabled                      BOOLEAN NOT NULL DEFAULT 1,
    public_client                BOOLEAN NOT NULL DEFAULT 0,
    bearer_only                  BOOLEAN NOT NULL DEFAULT 0,
    secret                       TEXT NOT NULL DEFAULT '',
    root_url                     TEXT NOT NULL DEFAULT '',
    base_url                     TEXT NOT NULL DEFAULT '',
    redirect_uris                TEXT NOT NULL DEFAULT '[]',
    web_origins                  TEXT NOT NULL DEFAULT '[]',
    standard_flow_enabled        BOOLEAN NOT NULL DEFAULT 1,
    direct_access_grants_enabled BOOLEAN NOT NULL DEFAULT 0,
    service_accounts_enabled     BOOLEAN NOT NULL DEFAULT 0,
    full_scope_allowed           BOOLEAN NOT NULL DEFAULT 1,
    protocol                     TEXT NOT NULL DEFAULT 'openid-connect',
    attributes                   TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, client_id)
);

CREATE TABLE IF NOT EXISTS users (
    id                        TEXT PRIMARY KEY,
    realm_id                  TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    username                  TEXT NOT NULL,
    email                     TEXT NOT NULL DEFAULT '',
    email_verified            BOOLEAN NOT NULL DEFAULT 0,
    first_name                TEXT NOT NULL DEFAULT '',
    last_name                 TEXT NOT NULL DEFAULT '',
    enabled                   BOOLEAN NOT NULL DEFAULT 1,
    created_timestamp         INTEGER NOT NULL,
    attributes                TEXT NOT NULL DEFAULT '{}',
    required_actions          TEXT NOT NULL DEFAULT '[]',
    service_account_client_id TEXT NOT NULL DEFAULT '',
    not_before                INTEGER NOT NULL DEFAULT 0,
    UNIQUE (realm_id, username)
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users (realm_id, email);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    user_label      TEXT NOT NULL DEFAULT '',
    secret_data     TEXT NOT NULL,
    credential_data TEXT NOT NULL,
    created_date    INTEGER NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 10
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials (user_id);

-- client_id is '' for realm roles so that the UNIQUE constraint also covers them.
CREATE TABLE IF NOT EXISTS roles (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    composite   BOOLEAN NOT NULL DEFAULT 0,
    attributes  TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, client_id, name)
);

CREATE TABLE IF NOT EXISTS composite_roles (
    parent_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    child_id  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (parent_id, child_id)
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- parent_id is '' for top-level groups.
CREATE TABLE IF NOT EXISTS realm_groups (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    parent_id  TEXT NOT NULL DEFAULT '',
    name       TEXT NOT NULL,
    attributes TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, parent_id, name)
);

CREATE TABLE IF NOT EXISTS group_roles (
    group_id TEXT NOT NULL REFERENCES realm_groups(id) ON DELETE CASCADE,
    role_id  TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, role_id)
);

CREATE TABLE IF NOT EXISTS user_groups (
    user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES realm_groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address   TEXT NOT NULL DEFAULT '',
    started      INTEGER NOT NULL,
    last_refresh INTEGER NOT NULL,
    remember_me  BOOLEAN NOT NULL DEFAULT 0,
    clients      TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions (user_id);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    params     TEXT NOT NULL,
    user_id    TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT PRIMARY KEY,
    realm_id              TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id             TEXT NOT NULL,
    user_id               TEXT NOT NULL,
    session_id            TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL,
    nonce                 TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    expires_at            INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS realm_keys (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    algorithm   TEXT NOT NULL,
    private_pem TEXT NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT 1,
    priority    INTEGER NOT NULL DEFAULT 100,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);
