ALTER TABLE nazo_avatar_objects ADD COLUMN storage TEXT NOT NULL DEFAULT 'd1'
    CHECK(storage IN ('d1','r2_pending','r2_ready','r2_retired'));

CREATE INDEX nazo_avatar_objects_r2_cleanup
    ON nazo_avatar_objects(tenant_id,storage,created_at)
    WHERE storage<>'d1';
