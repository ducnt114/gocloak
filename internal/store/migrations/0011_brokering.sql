-- Identity brokering (milestone M5).

CREATE TABLE IF NOT EXISTS identity_providers (
    internal_id                     TEXT PRIMARY KEY,
    realm_id                        TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias                           TEXT NOT NULL,
    display_name                    TEXT NOT NULL DEFAULT '',
    provider_id                     TEXT NOT NULL,
    enabled                         BOOLEAN NOT NULL DEFAULT TRUE,
    trust_email                     BOOLEAN NOT NULL DEFAULT FALSE,
    store_token                     BOOLEAN NOT NULL DEFAULT FALSE,
    add_read_token_role_on_create   BOOLEAN NOT NULL DEFAULT FALSE,
    link_only                       BOOLEAN NOT NULL DEFAULT FALSE,
    hide_on_login                   BOOLEAN NOT NULL DEFAULT FALSE,
    authenticate_by_default         BOOLEAN NOT NULL DEFAULT FALSE,
    first_broker_login_flow_alias   TEXT NOT NULL DEFAULT '',
    post_broker_login_flow_alias    TEXT NOT NULL DEFAULT '',
    gui_order                       TEXT NOT NULL DEFAULT '',
    config                          TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, alias)
);

CREATE TABLE IF NOT EXISTS idp_mappers (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    idp_alias   TEXT NOT NULL,
    name        TEXT NOT NULL,
    mapper_type TEXT NOT NULL,
    config      TEXT NOT NULL DEFAULT '{}',
    UNIQUE (realm_id, idp_alias, name)
);

CREATE TABLE IF NOT EXISTS federated_identities (
    user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    realm_id           TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    identity_provider  TEXT NOT NULL,
    federated_user_id  TEXT NOT NULL,
    federated_username TEXT NOT NULL DEFAULT '',
    token              TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, identity_provider),
    UNIQUE (realm_id, identity_provider, federated_user_id)
);
