-- User session notes (AUTH_TIME, ...) used by session note mappers.
ALTER TABLE user_sessions ADD COLUMN notes TEXT NOT NULL DEFAULT '{}';
