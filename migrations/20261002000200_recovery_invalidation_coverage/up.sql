-- Historical receipts and old writers retain partial coverage (0).
-- Never relabel or rescan a completed operation.
ALTER TABLE recovery_invalidations
    ADD COLUMN coverage_version SMALLINT NOT NULL DEFAULT 0,
    ADD CONSTRAINT ck_recovery_invalidations_coverage CHECK (coverage_version IN (0, 1));
