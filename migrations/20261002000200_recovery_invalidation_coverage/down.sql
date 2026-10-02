ALTER TABLE recovery_invalidations
    DROP CONSTRAINT ck_recovery_invalidations_coverage,
    DROP COLUMN coverage_version;
