-- Authorization services (milestone M8): resource servers on clients, with
-- their resources, scopes, policies and UMA permission tickets.

CREATE TABLE IF NOT EXISTS resource_servers (
    client_id                        TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    realm_id                         TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    policy_enforcement_mode          TEXT NOT NULL DEFAULT 'ENFORCING',
    decision_strategy                TEXT NOT NULL DEFAULT 'UNANIMOUS',
    allow_remote_resource_management BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS authz_scopes (
    id                 TEXT PRIMARY KEY,
    resource_server_id TEXT NOT NULL REFERENCES resource_servers(client_id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    display_name       TEXT NOT NULL DEFAULT '',
    icon_uri           TEXT NOT NULL DEFAULT '',
    UNIQUE (resource_server_id, name)
);

CREATE TABLE IF NOT EXISTS authz_resources (
    id                   TEXT PRIMARY KEY,
    resource_server_id   TEXT NOT NULL REFERENCES resource_servers(client_id) ON DELETE CASCADE,
    name                 TEXT NOT NULL,
    display_name         TEXT NOT NULL DEFAULT '',
    type                 TEXT NOT NULL DEFAULT '',
    owner                TEXT NOT NULL,
    owner_managed_access BOOLEAN NOT NULL DEFAULT FALSE,
    icon_uri             TEXT NOT NULL DEFAULT '',
    uris                 TEXT NOT NULL DEFAULT '[]',
    attributes           TEXT NOT NULL DEFAULT '{}',
    UNIQUE (resource_server_id, name, owner)
);

CREATE TABLE IF NOT EXISTS authz_resource_scopes (
    resource_id TEXT NOT NULL REFERENCES authz_resources(id) ON DELETE CASCADE,
    scope_id    TEXT NOT NULL REFERENCES authz_scopes(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (resource_id, scope_id)
);

CREATE TABLE IF NOT EXISTS authz_policies (
    id                 TEXT PRIMARY KEY,
    resource_server_id TEXT NOT NULL REFERENCES resource_servers(client_id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    description        TEXT NOT NULL DEFAULT '',
    type               TEXT NOT NULL,
    logic              TEXT NOT NULL DEFAULT 'POSITIVE',
    decision_strategy  TEXT NOT NULL DEFAULT 'UNANIMOUS',
    owner              TEXT NOT NULL DEFAULT '',
    config             TEXT NOT NULL DEFAULT '{}',
    UNIQUE (resource_server_id, name)
);

CREATE TABLE IF NOT EXISTS authz_policy_resources (
    policy_id   TEXT NOT NULL REFERENCES authz_policies(id) ON DELETE CASCADE,
    resource_id TEXT NOT NULL REFERENCES authz_resources(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, resource_id)
);

CREATE TABLE IF NOT EXISTS authz_policy_scopes (
    policy_id TEXT NOT NULL REFERENCES authz_policies(id) ON DELETE CASCADE,
    scope_id  TEXT NOT NULL REFERENCES authz_scopes(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, scope_id)
);

CREATE TABLE IF NOT EXISTS authz_associated_policies (
    policy_id     TEXT NOT NULL REFERENCES authz_policies(id) ON DELETE CASCADE,
    associated_id TEXT NOT NULL REFERENCES authz_policies(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, associated_id)
);

CREATE TABLE IF NOT EXISTS authz_permission_tickets (
    id                 TEXT PRIMARY KEY,
    resource_server_id TEXT NOT NULL REFERENCES resource_servers(client_id) ON DELETE CASCADE,
    resource_id        TEXT NOT NULL REFERENCES authz_resources(id) ON DELETE CASCADE,
    scope_id           TEXT NOT NULL DEFAULT '',
    owner              TEXT NOT NULL,
    requester          TEXT NOT NULL,
    created_timestamp  BIGINT NOT NULL,
    granted_timestamp  BIGINT NOT NULL DEFAULT 0
);
