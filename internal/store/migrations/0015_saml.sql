-- SAML 2.0 (milestone M9): front-channel logout and the admin URL ("Master
-- SAML processing URL") of clients.

ALTER TABLE clients ADD COLUMN frontchannel_logout BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE clients ADD COLUMN admin_url TEXT NOT NULL DEFAULT '';
