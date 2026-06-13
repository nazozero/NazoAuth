use super::*;

#[tokio::test]
async fn avatar_promotion_can_restore_previous_files() {
    let dir = temp_avatar_dir("rollback");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"new-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"new-meta");

    rollback_avatar_promotion(&promotion).await;
    assert_eq!(tokio::fs::read(&avatar).await.unwrap(), b"old-avatar");
    assert_eq!(tokio::fs::read(&meta).await.unwrap(), b"old-meta");
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn avatar_promotion_finish_removes_backup_files() {
    let dir = temp_avatar_dir("finish");
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let avatar = dir.join("avatar.bin");
    let meta = dir.join("meta.json");
    let avatar_tmp = dir.join("avatar-new.tmp");
    let meta_tmp = dir.join("meta-new.tmp");
    tokio::fs::write(&avatar, b"old-avatar").await.unwrap();
    tokio::fs::write(&meta, b"old-meta").await.unwrap();
    tokio::fs::write(&avatar_tmp, b"new-avatar").await.unwrap();
    tokio::fs::write(&meta_tmp, b"new-meta").await.unwrap();

    let promotion =
        promote_avatar_files(&avatar_tmp, &meta_tmp, avatar.clone(), meta.clone(), "v1")
            .await
            .unwrap();
    finish_avatar_promotion(&promotion).await;
    let avatar_backup_exists = tokio::fs::try_exists(&promotion.avatar_backup_path)
        .await
        .unwrap();
    let meta_backup_exists = tokio::fs::try_exists(&promotion.avatar_meta_backup_path)
        .await
        .unwrap();
    let _ = tokio::fs::remove_dir_all(&dir).await;

    assert!(!avatar_backup_exists);
    assert!(!meta_backup_exists);
}

fn temp_avatar_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "nazo_avatar_{label}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
