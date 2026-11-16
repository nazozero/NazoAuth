use std::{sync::Arc, time::Duration};

use super::*;

#[cfg(windows)]
fn sleep_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        "$null=[Console]::In.ReadToEnd(); Start-Sleep -Seconds 2".to_owned(),
    ])
}

#[cfg(windows)]
fn error_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "pwsh".to_owned(),
        "-NoLogo".to_owned(),
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        "$null=[Console]::In.ReadToEnd(); [Console]::Error.Write('secret'); exit 7".to_owned(),
    ])
}

#[cfg(unix)]
fn error_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "cat >/dev/null; printf secret >&2; exit 7".to_owned(),
    ])
}

#[cfg(unix)]
fn sleep_command() -> Arc<Vec<String>> {
    Arc::new(vec![
        "sh".to_owned(),
        "-c".to_owned(),
        "cat >/dev/null; sleep 2".to_owned(),
    ])
}

#[tokio::test]
async fn external_signer_timeout_fails_closed() {
    let key =
        CommandExternalKeySigner::new(sleep_command().as_ref().clone(), Duration::from_millis(25));
    let error = sign_external_jwt_input(
        &key,
        "external",
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        "kms://test/key",
    )
    .await
    .expect_err("timeout must fail closed");
    assert!(format!("{error}").contains("timed out"));
}

#[tokio::test]
async fn external_signer_process_fault_fails_closed_without_stderr_disclosure() {
    let key =
        CommandExternalKeySigner::new(error_command().as_ref().clone(), Duration::from_secs(5));
    let error = sign_external_jwt_input(
        &key,
        "external",
        jsonwebtoken::Algorithm::EdDSA,
        "header.claims",
        "kms://test/key",
    )
    .await
    .expect_err("process fault must fail closed");
    let message = format!("{error}");
    assert!(message.contains("exited with status"));
    assert!(!message.contains("secret"));
}

#[path = "external_signer/process.rs"]
mod process;
