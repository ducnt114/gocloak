-- OpenID Connect Client-Initiated Backchannel Authentication (milestone M10).
CREATE TABLE IF NOT EXISTS ciba_requests (
    id                  TEXT PRIMARY KEY,
    realm_id            TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope               TEXT NOT NULL DEFAULT '',
    callback_id         TEXT NOT NULL,
    notification_token  TEXT NOT NULL DEFAULT '',
    status              TEXT NOT NULL DEFAULT 'pending',
    session_id          TEXT NOT NULL DEFAULT '',
    poll_interval       INTEGER NOT NULL DEFAULT 5,
    last_poll           BIGINT NOT NULL DEFAULT 0,
    expires_at          BIGINT NOT NULL
);
