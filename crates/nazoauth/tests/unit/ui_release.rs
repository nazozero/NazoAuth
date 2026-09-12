use super::*;

#[test]
fn archive_paths_reject_parent_absolute_and_platform_prefixes() {
    assert!(safe_relative(Path::new("./assets/app.js")));
    assert!(!safe_relative(Path::new("../index.html")));
    assert!(!safe_relative(Path::new("/index.html")));
    assert!(!safe_relative(Path::new("C:\\index.html")));
}

#[test]
fn frontend_downloads_stay_on_explicit_github_https_origins() {
    for accepted in [
        "https://github.com/nazozero/NazoAuthWeb/releases/download/v0.2.2/nazoauth-web.tar.gz",
        "https://objects.githubusercontent.com/object",
        "https://release-assets.githubusercontent.com/object?token=opaque",
    ] {
        assert!(allowed_download_url(&Url::parse(accepted).unwrap()));
    }
    for rejected in [
        "http://github.com/object",
        "https://user@github.com/object",
        "https://github.com:444/object",
        "https://github.com.evil.example/object",
        "https://127.0.0.1/object",
        "https://release-assets.githubusercontent.com/object#fragment",
    ] {
        assert!(!allowed_download_url(&Url::parse(rejected).unwrap()));
    }
}

#[test]
fn bounded_regular_archive_extracts_without_external_ui_source() {
    use flate2::{Compression, write::GzEncoder};
    use tar::{Builder, Header};

    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&root).unwrap();
    let archive_path = root.join("ui.tar.gz");
    let output = root.join("output");
    fs::create_dir(&output).unwrap();
    let archive = File::create(&archive_path).unwrap();
    let mut builder = Builder::new(GzEncoder::new(archive, Compression::default()));
    let mut header = Header::new_gnu();
    header.set_size(7);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, "index.html", &b"fixture"[..])
        .unwrap();
    builder.into_inner().unwrap().finish().unwrap();

    extract(&archive_path, &output).unwrap();
    assert_eq!(fs::read(output.join("index.html")).unwrap(), b"fixture");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn release_metadata_selects_the_frontend_independently_of_the_server_version() {
    let release = |version: &str| GithubRelease {
        tag_name: version.to_owned(),
        draft: false,
        prerelease: false,
        assets: vec![GithubAsset {
            name: ARTIFACT_NAME.to_owned(),
            size: 123,
            digest: format!("sha256:{}", "a".repeat(64)),
        }],
    };
    assert_eq!(release("v9.8.7").download().unwrap().version, "v9.8.7");
    let mut invalid = release("v9.8.7");
    invalid.assets[0].digest = "sha256:invalid".to_owned();
    assert!(invalid.download().is_err());
    let mut invalid = release("v9.8.7");
    invalid.prerelease = true;
    assert!(invalid.download().is_err());
    let mut invalid = release("v9.8.7");
    invalid.assets[0].size = MAX_ARCHIVE_BYTES + 1;
    assert!(invalid.download().is_err());
}

#[actix_web::test]
async fn an_existing_ui_is_used_without_a_release_pin_or_reinstallation() {
    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    let ui = root.join("ui").join("current");
    fs::create_dir_all(&ui).unwrap();
    fs::write(ui.join("index.html"), b"custom UI").unwrap();
    let config = ConfigSource::from_owned_pairs_for_test([(
        "DATA_DIR".to_owned(),
        root.display().to_string(),
    )]);
    assert_eq!(
        resolve(&config).await.unwrap(),
        Some(fs::canonicalize(&ui).unwrap())
    );
    fs::write(ui.join("index.html"), b"replacement UI").unwrap();
    assert_eq!(
        resolve(&config).await.unwrap(),
        Some(fs::canonicalize(&ui).unwrap())
    );
    assert_eq!(fs::read(ui.join("index.html")).unwrap(), b"replacement UI");
    assert!(!root.join("ui").join(".ui-install.lock").exists());
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn disabled_ui_does_not_access_a_static_directory() {
    let config = ConfigSource::from_pairs_for_test([
        ("UI_ENABLED", "false"),
        ("UI_STATIC_DIR", "missing-ui"),
    ]);
    assert!(resolve(&config).await.unwrap().is_none());
}

#[actix_web::test]
async fn an_incomplete_custom_ui_never_blocks_api_startup_or_gets_overwritten() {
    let root = std::env::temp_dir().join(format!("nazoauth-ui-{}", uuid::Uuid::now_v7()));
    let ui = root.join("ui").join("current");
    fs::create_dir_all(&ui).unwrap();
    fs::write(ui.join("custom.js"), b"custom asset").unwrap();
    let config = ConfigSource::from_owned_pairs_for_test([(
        "DATA_DIR".to_owned(),
        root.display().to_string(),
    )]);
    assert_eq!(
        resolve(&config).await.unwrap(),
        Some(fs::canonicalize(&ui).unwrap())
    );
    assert_eq!(fs::read(ui.join("custom.js")).unwrap(), b"custom asset");
    assert!(!ui.join("index.html").exists());
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
#[ignore = "downloads the current official UI from GitHub"]
async fn official_ui_initialization_keeps_later_local_replacements() {
    let root = std::env::temp_dir().join(format!("nazoauth-live-ui-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(root.join("ui")).unwrap();
    let config = ConfigSource::from_owned_pairs_for_test([(
        "DATA_DIR".to_owned(),
        root.display().to_string(),
    )]);
    let ui = resolve(&config).await.unwrap().unwrap();
    assert!(
        ui.join("index.html").is_file(),
        "official UI initialization failed"
    );
    assert!(ui.join("assets").is_dir());
    fs::write(ui.join("index.html"), "independent frontend replacement").unwrap();
    assert_eq!(resolve(&config).await.unwrap().unwrap(), ui);
    assert_eq!(
        fs::read_to_string(ui.join("index.html")).unwrap(),
        "independent frontend replacement"
    );
    fs::remove_dir_all(root).unwrap();
}
