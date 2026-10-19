-- Authentication flows and required actions (milestone M3).

CREATE TABLE IF NOT EXISTS auth_flows (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias       TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    provider_id TEXT NOT NULL DEFAULT 'basic-flow',
    top_level   BOOLEAN NOT NULL DEFAULT TRUE,
    built_in    BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (realm_id, alias)
);

-- An execution runs an authenticator, or a sub flow (sub_flow_id); form
-- flows run both (the form authenticator and its form actions).
CREATE TABLE IF NOT EXISTS auth_executions (
    id            TEXT PRIMARY KEY,
    realm_id      TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    flow_id       TEXT NOT NULL REFERENCES auth_flows(id) ON DELETE CASCADE,
    authenticator TEXT NOT NULL DEFAULT '',
    sub_flow_id   TEXT NOT NULL DEFAULT '',
    requirement   TEXT NOT NULL,
    priority      BIGINT NOT NULL,
    config_id     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_auth_executions_flow ON auth_executions (flow_id);

CREATE TABLE IF NOT EXISTS authenticator_configs (
    id       TEXT PRIMARY KEY,
    realm_id TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias    TEXT NOT NULL,
    config   TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS required_actions (
    realm_id       TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    alias          TEXT NOT NULL,
    name           TEXT NOT NULL,
    provider_id    TEXT NOT NULL,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE,
    default_action BOOLEAN NOT NULL DEFAULT FALSE,
    priority       BIGINT NOT NULL DEFAULT 0,
    config         TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (realm_id, alias)
);

ALTER TABLE clients ADD COLUMN flow_overrides TEXT NOT NULL DEFAULT '{}';
