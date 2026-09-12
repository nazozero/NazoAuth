use std::{
    fs::{self, File, OpenOptions},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, bail};
use flate2::read::GzDecoder;
use fs2::FileExt as _;
use futures_util::StreamExt as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;
use url::Url;

use crate::config::{ConfigSource, DEFAULT_DATA_DIR};

const RELEASE_API: &str = "https://api.github.com/repos/nazozero/NazoAuthWeb/releases/latest";
const ARTIFACT_NAME: &str = "nazoauth-web.tar.gz";
const MAX_METADATA_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    size: u64,
    digest: String,
}

// Download metadata is used once at installation; it is never a constraint on
// the installed files or on subsequent frontend replacements.
struct FrontendDownload {
    version: String,
    sha256: String,
    size: u64,
}

pub(super) async fn resolve(config: &ConfigSource) -> anyhow::Result<Option<PathBuf>> {
    if !config.bool("UI_ENABLED", true)? {
        return Ok(None);
    }
    if config.optional_string("UI_STATIC_DIR").is_some() {
        let path = config.persistent_path("UI_STATIC_DIR", None)?;
        return Ok(Some(validate_static_directory(&path)?));
    }
    let root = config
        .persistent_path("DATA_DIR", Some(DEFAULT_DATA_DIR))?
        .join("ui")
        .join("current");
    if !root.join("index.html").is_file()
        && let Err(error) = install_default(&root).await
    {
        // UI availability must not prevent the API from starting. Keep the
        // static root available so an operator can supply files in place.
        tracing::warn!(%error, "default UI is unavailable; API startup continues");
        fs::create_dir_all(&root)?;
    }
    Ok(Some(fs::canonicalize(root)?))
}

fn validate_static_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let path = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve UI_STATIC_DIR {}", path.display()))?;
    if !path.join("index.html").is_file() {
        bail!("UI_STATIC_DIR must contain index.html: {}", path.display());
    }
    Ok(path)
}

impl GithubRelease {
    fn download(self) -> anyhow::Result<FrontendDownload> {
        if self.draft || self.prerelease || !semantic_tag(&self.tag_name) {
            bail!("default frontend must be a published stable release");
        }
        let mut assets = self
            .assets
            .into_iter()
            .filter(|asset| asset.name == ARTIFACT_NAME);
        let asset = assets
            .next()
            .context("frontend release has no UI archive")?;
        if assets.next().is_some() || asset.size == 0 || asset.size > MAX_ARCHIVE_BYTES {
            bail!("frontend release must contain one bounded UI archive");
        }
        let sha256 = asset
            .digest
            .strip_prefix("sha256:")
            .filter(|digest| lower_hex(digest, 64))
            .context("GitHub frontend asset digest must be SHA-256")?
            .to_owned();
        Ok(FrontendDownload {
            version: self.tag_name,
            sha256,
            size: asset.size,
        })
    }
}

async fn install_default(root: &Path) -> anyhow::Result<()> {
    let parent = root.parent().context("UI directory must have a parent")?;
    fs::create_dir_all(parent)?;
    let lock_path = parent.join(".ui-install.lock");
    let _lock = tokio::task::spawn_blocking(move || -> anyhow::Result<File> {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        lock.lock_exclusive()?;
        Ok(lock)
    })
    .await
    .context("UI installation lock task failed")??;
    if root.join("index.html").is_file() {
        return Ok(());
    }
    if root.exists() && fs::read_dir(root)?.next().is_some() {
        bail!("UI directory contains custom or incomplete files; refusing to overwrite them");
    }
    let client = reqwest::Client::builder()
        .user_agent(concat!("NazoAuth/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !allowed_download_url(attempt.url()) {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()?;
    let response = client
        .get(RELEASE_API)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await?
        .error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut metadata = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if metadata.len() + chunk.len() > MAX_METADATA_BYTES {
            bail!("frontend release metadata exceeds the size limit");
        }
        metadata.extend_from_slice(&chunk);
    }
    let descriptor = serde_json::from_slice::<GithubRelease>(&metadata)?.download()?;
    let work = parent.join(format!(".ui-install-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&work)?;
    let result = async {
        let archive = work.join(ARTIFACT_NAME);
        download(&client, &descriptor, &archive).await?;
        let staged = work.join("ui");
        fs::create_dir(&staged)?;
        extract(&archive, &staged)?;
        if root.exists() {
            fs::remove_dir(root)?; // Only an empty directory may be replaced.
        }
        fs::rename(staged, root)?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = fs::remove_dir_all(work);
    result
}

async fn download(
    client: &reqwest::Client,
    descriptor: &FrontendDownload,
    target: &Path,
) -> anyhow::Result<()> {
    let url = format!(
        "https://github.com/nazozero/NazoAuthWeb/releases/download/{}/{}",
        descriptor.version, ARTIFACT_NAME
    );
    let response = client.get(url).send().await?.error_for_status()?;
    if !allowed_download_url(response.url()) {
        bail!("frontend download left the approved HTTPS origin set");
    }
    let mut stream = response.bytes_stream();
    let mut file = tokio::fs::File::create(target).await?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size = size
            .checked_add(chunk.len() as u64)
            .context("frontend archive size overflow")?;
        if size > descriptor.size {
            bail!("frontend archive exceeds its release size");
        }
        digest.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    file.sync_all().await?;
    if size != descriptor.size || hex(&digest.finalize()) != descriptor.sha256 {
        bail!("frontend archive does not match the GitHub asset digest and size");
    }
    Ok(())
}

fn allowed_download_url(url: &Url) -> bool {
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || url.fragment().is_some()
    {
        return false;
    }
    matches!(
        url.host_str(),
        Some("github.com")
            | Some("api.github.com")
            | Some("objects.githubusercontent.com")
            | Some("release-assets.githubusercontent.com")
    )
}

fn extract(archive: &Path, target: &Path) -> anyhow::Result<()> {
    let source = File::open(archive)?;
    let mut archive = tar::Archive::new(GzDecoder::new(source));
    let mut entries = 0_usize;
    let mut expanded = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > MAX_ENTRIES {
            bail!("frontend archive contains too many entries");
        }
        let path = entry.path()?.into_owned();
        if !safe_relative(&path) {
            bail!("frontend archive contains an unsafe path");
        }
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            bail!("frontend archive contains a non-file entry");
        }
        expanded = expanded
            .checked_add(entry.header().size()?)
            .context("frontend expanded size overflow")?;
        if expanded > MAX_EXPANDED_BYTES {
            bail!("frontend archive expands beyond the safety limit");
        }
        entry.unpack_in(target)?;
    }
    if !target.join("index.html").is_file() {
        bail!("frontend archive has no index.html");
    }
    Ok(())
}

fn safe_relative(path: &Path) -> bool {
    let rendered = path.to_string_lossy();
    !path.as_os_str().is_empty()
        && !rendered.contains(['\\', ':'])
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn semantic_tag(value: &str) -> bool {
    let Some(version) = value.strip_prefix('v') else {
        return false;
    };
    semver::Version::parse(version).is_ok_and(|parsed| parsed.to_string() == version)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
#[path = "../../tests/unit/ui_release.rs"]
mod tests;
