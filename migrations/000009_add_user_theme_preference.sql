ALTER TABLE users
    ADD COLUMN IF NOT EXISTS theme_preference VARCHAR(10) NOT NULL DEFAULT 'system';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_theme_preference_check;
ALTER TABLE users ADD CONSTRAINT users_theme_preference_check
    CHECK (theme_preference IN ('system', 'light', 'dark'));
