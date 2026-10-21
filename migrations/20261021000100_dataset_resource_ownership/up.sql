-- One physical dataset has one active controller resource owner. Existing aliases
-- must be reconciled explicitly before upgrade; selecting an owner silently would
-- change the signed resource manifest.
CREATE UNIQUE INDEX uq_tenant_dataset_owner
ON tenant_resource_bindings (tenant_id, locator)
WHERE active AND resource_kind = 'openid4vc-dataset';
