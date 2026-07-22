impl UserinfoHandles {
    pub(crate) fn from_test_infrastructure(state: &super::TestInfrastructure) -> Self {
        Self::new(
            nazo_valkey::ReplayStore::new(&state.valkey_connection()),
            state.keyset.clone(),
            UserinfoConfig::from(state.settings.as_ref()),
        )
    }
}
