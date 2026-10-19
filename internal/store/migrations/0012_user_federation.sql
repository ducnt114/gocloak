-- User federation (milestone M6): users imported from a user storage
-- provider (LDAP) link to its component.

ALTER TABLE users ADD COLUMN federation_link TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS users_federation_link ON users (realm_id, federation_link);
