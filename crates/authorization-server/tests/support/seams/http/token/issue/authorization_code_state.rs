pub(super) fn consumed_authorization_code_transition_result(result: &str) -> anyhow::Result<()> {
    if result == "ok" {
        Ok(())
    } else {
        anyhow::bail!("authorization code state is {result}, expected consuming")
    }
}
