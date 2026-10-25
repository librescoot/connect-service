ALTER TABLE installations ALTER COLUMN created_at DROP NOT NULL;

UPDATE installations SET created_at = NULL WHERE deleted_at IS NOT NULL;

ALTER TABLE installations
    ADD CONSTRAINT installations_created_at_state_check
    CHECK ((deleted_at IS NULL AND created_at IS NOT NULL) OR (deleted_at IS NOT NULL AND created_at IS NULL));
