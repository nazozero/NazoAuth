#[cfg(not(target_arch = "wasm32"))]
fn main() -> anyhow::Result<()> {
    use std::io::{Read, Write};
    let path = std::env::args_os().nth(1).ok_or_else(|| {
        anyhow::anyhow!("usage: nazo-worker-provision NEW_SQLITE_FILE < provisioning.json")
    })?;
    let mut input = zeroize::Zeroizing::new(String::new());
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_string(&mut input)?;
    anyhow::ensure!(
        input.len() <= 1024 * 1024,
        "provisioning input exceeds 1 MiB"
    );
    let input: nazo_server_worker::provisioning::ProvisioningInput = serde_json::from_str(&input)?;
    let result = futures_executor::block_on(nazo_server_worker::provisioning::provision(
        std::path::Path::new(&path),
        input,
    ))?;
    serde_json::to_writer(std::io::stdout().lock(), &result)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn main() {}
