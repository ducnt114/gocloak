-- Authorization codes already exchanged, until they would have expired: a
-- second exchange of a code ends the session it created (RFC 6749 4.1.2).
CREATE TABLE IF NOT EXISTS used_auth_codes (
    code       TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    expires_at BIGINT NOT NULL
);
