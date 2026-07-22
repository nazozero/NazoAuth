pub(super) fn algorithm_name(alg: Algorithm) -> Option<&'static str> {
    supported_algorithm(alg).map(|(name, _)| name)
}
