-- Dynamic client registration (milestone M10): initial access tokens and
-- the current registration access token of registered clients.

CREATE TABLE IF NOT EXISTS client_initial_access (
    id         TEXT PRIMARY KEY,
    realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    created_at BIGINT NOT NULL,
    expiration INTEGER NOT NULL,
    total      INTEGER NOT NULL,
    remaining  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS client_registration_tokens (
    client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
    token_id  TEXT NOT NULL
);
