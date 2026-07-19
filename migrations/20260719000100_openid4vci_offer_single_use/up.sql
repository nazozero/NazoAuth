DROP TABLE openid4vci_pre_authorized_code_consumptions;

COMMENT ON COLUMN openid4vci_offers.consumed_at IS
    'Single-use consumption timestamp shared by authorization-code and pre-authorized-code grants.';
