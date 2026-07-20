ALTER TABLE secret_deliveries
    ADD COLUMN IF NOT EXISTS payload_type VARCHAR(20) NOT NULL DEFAULT 'json' CHECK (payload_type IN ('structured', 'text', 'json')),
    ADD COLUMN IF NOT EXISTS payload_field_count INTEGER NOT NULL DEFAULT 0 CHECK (payload_field_count >= 0),
    ADD COLUMN IF NOT EXISTS payload_contains_sensitive BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_secret_deliveries_payload_type
    ON secret_deliveries (payload_type, created_at DESC);
