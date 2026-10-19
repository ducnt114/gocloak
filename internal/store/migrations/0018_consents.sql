-- Consents (milestone M10): clients that require the user's consent, and
-- the client scopes users granted them.

ALTER TABLE clients ADD COLUMN consent_required BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS user_consents (
    realm_id   TEXT NOT NULL REFERENCES realms(id) ON DELETE CASCADE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL DEFAULT '[]',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, client_id)
);
