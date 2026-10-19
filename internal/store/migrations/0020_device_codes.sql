-- OAuth 2.0 Device Authorization Grant (milestone M10).
CREATE TABLE IF NOT EXISTS device_codes (
    device_code TEXT PRIMARY KEY,
    user_code   TEXT NOT NULL,
    realm_id    TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope       TEXT NOT NULL DEFAULT '',
    nonce       TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    user_id     TEXT NOT NULL DEFAULT '',
    session_id  TEXT NOT NULL DEFAULT '',
    poll_interval INTEGER NOT NULL DEFAULT 5,
    last_poll   BIGINT NOT NULL DEFAULT 0,
    expires_at  BIGINT NOT NULL,
    UNIQUE (realm_id, user_code)
);
