CREATE TABLE installations (
    installation_id TEXT PRIMARY KEY,
    credential_digest BYTEA,
    consent_version SMALLINT,
    facts JSONB,
    initial_event_id TEXT,
    initial_digest BYTEA,
    first_reported_at TIMESTAMPTZ,
    last_reported_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CHECK (credential_digest IS NULL OR octet_length(credential_digest) = 32),
    CHECK (initial_digest IS NULL OR octet_length(initial_digest) = 32),
    CHECK (
        (deleted_at IS NULL
            AND credential_digest IS NOT NULL
            AND consent_version IS NOT NULL
            AND facts IS NOT NULL
            AND initial_event_id IS NOT NULL
            AND initial_digest IS NOT NULL
            AND first_reported_at IS NOT NULL
            AND last_reported_at IS NOT NULL
            AND expires_at IS NOT NULL)
        OR
        (deleted_at IS NOT NULL
            AND credential_digest IS NULL
            AND consent_version IS NULL
            AND facts IS NULL
            AND initial_event_id IS NULL
            AND initial_digest IS NULL
            AND first_reported_at IS NULL
            AND last_reported_at IS NULL
            AND expires_at IS NULL)
    )
);

CREATE TABLE report_receipts (
    installation_id TEXT NOT NULL REFERENCES installations (installation_id),
    event_id TEXT NOT NULL,
    digest BYTEA NOT NULL CHECK (octet_length(digest) = 32),
    received_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (installation_id, event_id)
);

CREATE INDEX report_receipts_received_at_idx ON report_receipts (received_at);
CREATE INDEX installations_expiry_idx ON installations (expires_at) WHERE deleted_at IS NULL;

CREATE TABLE reporting_retention_aggregates (
    report_month DATE PRIMARY KEY,
    expired_installation_count BIGINT NOT NULL CHECK (expired_installation_count >= 0)
);
