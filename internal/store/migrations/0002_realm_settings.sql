-- Typed realm settings (password policy, brute force, SMTP, OTP, themes,
-- events...) stored as one JSON document, see model.RealmSettings.
ALTER TABLE realms ADD COLUMN settings TEXT NOT NULL DEFAULT '{}';
