use super::*;
use std::{future::poll_fn, task::Poll, time::Duration};

use nazo_identity::{AvatarService, DeleteAvatarError, UploadAvatarError, ports::RepositoryError};
use crate::test_support::local_avatar::{
    CasOutcome, CasRepository, LocalFixture, NoGrants, object, png,
};

async fn seed(fixture: &mut LocalFixture) -> String {
    let version = Uuid::now_v7().to_string();
    let mutation = fixture.storage
        .begin_replace(fixture.account.user_id(), None, object(&version)).await.unwrap();
    fixture.storage.commit(&mutation).await.unwrap();
    fixture.account.profile.avatar_url = Some(format!("/auth/me/avatar?v={version}"));
    version
}

async fn version_count(fixture: &LocalFixture) -> usize {
    let mut entries = fs::read_dir(fixture.storage.user_dir(fixture.account.user_id())
        .join(VERSIONS_DIRECTORY)).await.unwrap();
    let mut count = 0;
    while entries.next_entry().await.unwrap().is_some() {
        count += 1;
    }
    count
}

#[tokio::test]
async fn two_candidates_leave_the_selected_version_readable_and_cas_loser_removes_only_itself() {
    let mut fixture = LocalFixture::new();
    let old = seed(&mut fixture).await;
    let user = fixture.account.user_id();
    let winner = Uuid::now_v7().to_string();
    let loser = Uuid::now_v7().to_string();
    let first = fixture.storage.begin_replace(user, Some(&old), object(&winner)).await.unwrap();
    // This must complete while the first mutation is alive: no active stripe
    // lock survives preparation into the database await.
    let second = tokio::time::timeout(Duration::from_secs(2),
        fixture.storage.begin_replace(user, Some(&old), object(&loser))).await.unwrap().unwrap();
    assert_eq!(fixture.storage.read(user, &old).await.unwrap().bytes, png());
    fixture.storage.rollback(&second).await.unwrap();
    assert_eq!(fixture.storage.read(user, &winner).await.unwrap().version, winner);
    assert_eq!(fixture.storage.read(user, &old).await.unwrap().version, old);
    fixture.storage.commit(&first).await.unwrap();
    assert_eq!(version_count(&fixture).await, 1);
    assert_eq!(fixture.storage.read(user, &winner).await.unwrap().version, winner);
    assert!(fixture.storage.read(user, &loser).await.is_err());
    assert!(fixture.storage.read(user, &old).await.is_err());
}

#[tokio::test]
async fn service_cas_miss_cleans_the_unique_candidate_but_all_repository_errors_retain_it() {
    for outcome in [CasOutcome::Success, CasOutcome::Miss,
        CasOutcome::ErrorBeforeCommit, CasOutcome::ErrorAfterCommit] {
        let mut fixture = LocalFixture::new();
        let old = seed(&mut fixture).await;
        let repository = CasRepository::new(fixture.account.clone(), outcome);
        let service = AvatarService::new(repository.clone(), NoGrants, fixture.storage.clone(), 4096);
        let result = service.upload(&fixture.account, png()).await;
        let current = repository.account.lock().unwrap().clone();
        let selected = service.read(&current).await.unwrap();
        match outcome {
            CasOutcome::Success => {
                result.unwrap();
                assert_ne!(selected.version, old);
                assert_eq!(version_count(&fixture).await, 1);
            }
            CasOutcome::Miss => {
                assert!(matches!(result, Err(UploadAvatarError::ConcurrentChange)));
                assert_eq!(selected.version, old);
                assert_eq!(version_count(&fixture).await, 1);
            }
            CasOutcome::ErrorBeforeCommit | CasOutcome::ErrorAfterCommit => {
                assert!(matches!(result, Err(UploadAvatarError::Repository(RepositoryError::Unavailable))));
                assert_eq!(version_count(&fixture).await, 2);
                assert_eq!(fixture.storage.read(current.user_id(), &old).await.unwrap().version, old);
                assert_eq!(selected.version == old, matches!(outcome, CasOutcome::ErrorBeforeCommit));
            }
            _ => unreachable!(),
        }
    }
}

#[tokio::test]
async fn cancellation_before_or_after_database_commit_never_invalidates_the_database_reference() {
    for outcome in [CasOutcome::PauseBeforeCommit, CasOutcome::PauseAfterCommit] {
        for deleting in [false, true] {
            let mut fixture = LocalFixture::new();
            let old = seed(&mut fixture).await;
            let repository = CasRepository::new(fixture.account.clone(), outcome);
            let service = AvatarService::new(repository.clone(), NoGrants, fixture.storage.clone(), 4096);
            if deleting {
                let mut operation = Box::pin(service.delete(&fixture.account));
                tokio::select! {
                    _ = repository.entered.notified() => {}
                    result = &mut operation => panic!("expected paused CAS: {result:?}"),
                }
                drop(operation);
            } else {
                let mut operation = Box::pin(service.upload(&fixture.account, png()));
                tokio::select! {
                    _ = repository.entered.notified() => {}
                    result = &mut operation => panic!("expected paused CAS: {result:?}"),
                }
                drop(operation);
            }
            let current = repository.account.lock().unwrap().clone();
            if current.profile.avatar_url.is_some() {
                service.read(&current).await.unwrap();
            } else {
                assert!(deleting && matches!(outcome, CasOutcome::PauseAfterCommit));
            }
            assert_eq!(fixture.storage.read(current.user_id(), &old).await.unwrap().version, old);
            assert_eq!(version_count(&fixture).await, if deleting { 1 } else { 2 });
        }
    }
}

#[tokio::test]
async fn cancellation_at_each_observed_publication_suspend_leaves_the_old_version_untouched() {
    let mut fixture = LocalFixture::new();
    let old = seed(&mut fixture).await;
    let user = fixture.account.user_id();
    let mut saw_completion = false;
    // Poll the real I/O future, dropping it at each successive suspension.
    // No production failpoint, Drop worker, or rollback journal is introduced.
    for cutoff in 0..256 {
        let version = Uuid::now_v7().to_string();
        let mut operation = fixture.storage.begin_replace(user, Some(&old), object(&version));
        let mut suspensions = 0;
        let complete = poll_fn(|cx| match operation.as_mut().poll(cx) {
            Poll::Pending if suspensions == cutoff => Poll::Ready(false),
            Poll::Pending => {
                suspensions += 1;
                Poll::Pending
            }
            Poll::Ready(result) => {
                result.unwrap();
                Poll::Ready(true)
            }
        }).await;
        drop(operation);
        assert_eq!(fixture.storage.read(user, &old).await.unwrap().bytes, png());
        if complete {
            saw_completion = true;
            break;
        }
    }
    assert!(saw_completion, "publication did not finish within the suspension sweep");
}

#[tokio::test]
async fn delete_preparation_and_unknown_outcomes_retain_files_until_affirmative_cas() {
    let mut fixture = LocalFixture::new();
    let old = seed(&mut fixture).await;
    let user = fixture.account.user_id();
    let mutation = fixture.storage.begin_delete(user, Some(&old), "../unused-revision").await.unwrap();
    assert_eq!(fixture.storage.read(user, &old).await.unwrap().bytes, png());
    fixture.storage.rollback(&mutation).await.unwrap();
    assert_eq!(fixture.storage.read(user, &old).await.unwrap().bytes, png());
    for outcome in [CasOutcome::Miss, CasOutcome::ErrorBeforeCommit, CasOutcome::ErrorAfterCommit] {
        let repository = CasRepository::new(fixture.account.clone(), outcome);
        let service = AvatarService::new(repository, NoGrants, fixture.storage.clone(), 4096);
        let result = service.delete(&fixture.account).await;
        assert!(matches!(result, Err(DeleteAvatarError::ConcurrentChange)
            | Err(DeleteAvatarError::Repository(RepositoryError::Unavailable))));
        assert_eq!(fixture.storage.read(user, &old).await.unwrap().bytes, png());
    }
    fixture.storage.commit(&mutation).await.unwrap();
    assert!(fixture.storage.read(user, &old).await.is_err());
}

#[tokio::test]
async fn restart_reads_legacy_active_and_matching_backup_without_using_version_text_as_a_path() {
    let fixture = LocalFixture::new();
    let user = fixture.account.user_id();
    let user_dir = fixture.storage.user_dir(user);
    fs::create_dir_all(&user_dir).await.unwrap();
    let historical = r"legacy\..\outside%historical";
    fs::write(user_dir.join(AVATAR_FILE_NAME), png()).await.unwrap();
    fs::write(user_dir.join(METADATA_FILE_NAME),
        serde_json::to_vec(&AvatarMetadata { content_type: "text/plain".to_owned(), version: historical.to_owned() }).unwrap())
        .await.unwrap();
    let restarted = LocalAvatarStorage::new(fixture.root.clone());
    assert_eq!(restarted.read(user, historical).await.unwrap().bytes, png());
    fs::rename(user_dir.join(AVATAR_FILE_NAME), user_dir.join("avatar-r1.bak")).await.unwrap();
    fs::rename(user_dir.join(METADATA_FILE_NAME), user_dir.join("meta-r1.bak")).await.unwrap();
    fs::write(user_dir.join(AVATAR_FILE_NAME), png()).await.unwrap();
    fs::write(user_dir.join(METADATA_FILE_NAME),
        br#"{"content_type":"image/png","version":"another-active-version"}"#).await.unwrap();
    assert_eq!(restarted.read(user, historical).await.unwrap().bytes, png());
    fs::copy(user_dir.join("avatar-r1.bak"), user_dir.join("avatar-r2.bak")).await.unwrap();
    fs::copy(user_dir.join("meta-r1.bak"), user_dir.join("meta-r2.bak")).await.unwrap();
    assert_eq!(restarted.read(user, historical).await, Err(AvatarStorageError::InvalidState));
    fs::remove_file(user_dir.join("avatar-r2.bak")).await.unwrap();
    fs::remove_file(user_dir.join("meta-r2.bak")).await.unwrap();
    fs::write(user_dir.join("avatar-other.bak"), png()).await.unwrap();
    fs::write(user_dir.join("meta-other.bak"),
        br#"{"content_type":"image/png","version":"another-backup-version"}"#).await.unwrap();
    let retired = restarted.begin_delete(user, Some(historical), "unused").await.unwrap();
    restarted.commit(&retired).await.unwrap();
    assert!(!user_dir.join("meta-r1.bak").exists());
    assert_eq!(restarted.read(user, "another-active-version").await.unwrap().bytes, png());
    assert_eq!(restarted.read(user, "another-backup-version").await.unwrap().bytes, png());
}

#[tokio::test]
async fn candidate_versions_are_exclusive_and_partial_or_mismatched_versions_fail_closed() {
    let fixture = LocalFixture::new();
    let user = fixture.account.user_id();
    for version in ["", "..", "../outside", r"..\outside", "not-a-uuid", "00112233-4455-6677-8899-AABBCCDDEEFF"] {
        assert!(matches!(fixture.storage.begin_replace(user, None, object(version)).await,
            Err(AvatarStorageError::InvalidState)));
    }
    assert!(!fixture.root.exists());
    let version = Uuid::now_v7().to_string();
    let directory = fixture.storage.user_dir(user).join(VERSIONS_DIRECTORY).join(&version);
    fs::create_dir_all(&directory).await.unwrap();
    fs::write(directory.join(AVATAR_FILE_NAME), png()).await.unwrap();
    assert_eq!(fixture.storage.read(user, &version).await, Err(AvatarStorageError::Missing));
    assert!(matches!(fixture.storage.begin_replace(user, None, object(&version)).await,
        Err(AvatarStorageError::Conflict)));
    assert!(directory.join(AVATAR_FILE_NAME).exists());
    fs::write(directory.join(METADATA_FILE_NAME),
        br#"{"content_type":"image/png","version":"wrong"}"#).await.unwrap();
    assert_eq!(fixture.storage.read(user, &version).await, Err(AvatarStorageError::InvalidState));
    fs::write(directory.join(METADATA_FILE_NAME),
        serde_json::to_vec(&AvatarMetadata { content_type: "image/png".to_owned(), version: version.clone() }).unwrap()).await.unwrap();
    let restarted = LocalAvatarStorage::new(fixture.root.clone());
    assert_eq!(restarted.read(user, &version).await.unwrap().bytes, png());
    assert!(matches!(fixture.storage.begin_replace(user, Some(&version), object(&version)).await,
        Err(AvatarStorageError::InvalidState)));
}

#[tokio::test]
async fn tenant_and_user_roots_are_isolated_and_mutations_cannot_cross_storage_bindings() {
    let first = LocalFixture::new();
    let second = LocalFixture::new();
    let user = first.account.user_id();
    let version = Uuid::now_v7().to_string();
    let mutation = first.storage.begin_replace(user, None, object(&version)).await.unwrap();
    let other = second.storage.begin_replace(user, None, object(&version)).await.unwrap();
    assert_eq!(second.storage.rollback(&mutation).await, Err(AvatarStorageError::InvalidState));
    assert_eq!(second.storage.read(user, &version).await.unwrap().bytes, png());
    assert_eq!(first.storage.read(second.account.user_id(), &version).await, Err(AvatarStorageError::Missing));
    first.storage.rollback(&mutation).await.unwrap();
    assert_eq!(second.storage.read(user, &version).await.unwrap().bytes, png());
    second.storage.rollback(&other).await.unwrap();
}

#[tokio::test]
async fn cleanup_failure_after_success_is_only_an_orphan_and_never_hides_the_new_version() {
    let mut fixture = LocalFixture::new();
    let old = seed(&mut fixture).await;
    let user = fixture.account.user_id();
    let old_directory = fixture.storage.user_dir(user).join(VERSIONS_DIRECTORY).join(&old);
    fs::create_dir(old_directory.join("unexpected-entry")).await.unwrap();
    let repository = CasRepository::new(fixture.account.clone(), CasOutcome::Success);
    let service = AvatarService::new(repository.clone(), NoGrants, fixture.storage.clone(), 4096);
    let updated = service.upload(&fixture.account, png()).await.unwrap();
    service.read(&updated.account).await.unwrap();
    assert!(old_directory.exists());
    let current = repository.account.lock().unwrap().clone();
    assert_eq!(current.profile.avatar_url, updated.account.profile.avatar_url);
}

#[cfg(unix)]
#[tokio::test]
async fn symlinked_directory_components_and_nonregular_files_are_never_followed() {
    use std::os::unix::fs::symlink;
    let mut fixture = LocalFixture::new();
    let old = seed(&mut fixture).await;
    let user = fixture.account.user_id();
    let user_dir = fixture.storage.user_dir(user);
    let outside = fixture.root.join("outside");
    fs::create_dir(&outside).await.unwrap();
    fs::write(outside.join("sentinel"), b"outside").await.unwrap();
    let linked_version = Uuid::now_v7().to_string();
    symlink(&outside, user_dir.join(VERSIONS_DIRECTORY).join(&linked_version)).unwrap();
    assert_eq!(fixture.storage.read(user, &linked_version).await, Err(AvatarStorageError::InvalidState));
    assert!(matches!(fixture.storage.begin_replace(user, None, object(&linked_version)).await,
        Err(AvatarStorageError::Conflict)));
    let old_file = user_dir.join(VERSIONS_DIRECTORY).join(&old).join(AVATAR_FILE_NAME);
    fs::remove_file(&old_file).await.unwrap();
    symlink(outside.join("sentinel"), &old_file).unwrap();
    assert_eq!(fixture.storage.read(user, &old).await, Err(AvatarStorageError::InvalidState));
    fs::remove_file(&old_file).await.unwrap();
    fs::write(&old_file, png()).await.unwrap();
    let metadata_file = old_file.with_file_name(METADATA_FILE_NAME);
    fs::remove_file(&metadata_file).await.unwrap();
    symlink(outside.join("sentinel"), &metadata_file).unwrap();
    assert_eq!(fixture.storage.read(user, &old).await, Err(AvatarStorageError::InvalidState));
    let linked_user = UserId::new(Uuid::now_v7()).unwrap();
    symlink(&outside, fixture.storage.user_dir(linked_user)).unwrap();
    assert!(fixture.storage.begin_replace(linked_user, None, object(&Uuid::now_v7().to_string())).await.is_err());
    assert_eq!(fixture.storage.read(linked_user, &old).await, Err(AvatarStorageError::InvalidState));
    let versions = user_dir.join(VERSIONS_DIRECTORY);
    fs::rename(&versions, user_dir.join("retained-versions")).await.unwrap();
    symlink(&outside, &versions).unwrap();
    assert_eq!(fixture.storage.read(user, &old).await, Err(AvatarStorageError::InvalidState));
    assert!(fixture.storage.begin_replace(user, None, object(&Uuid::now_v7().to_string())).await.is_err());
    let linked_root = fixture.root.join("linked-root");
    symlink(&outside, &linked_root).unwrap();
    let storage_with_symlink_root = LocalAvatarStorage::new(linked_root);
    assert_eq!(storage_with_symlink_root.read(user, &old).await, Err(AvatarStorageError::InvalidState));
    assert!(storage_with_symlink_root.begin_replace(user, None, object(&Uuid::now_v7().to_string())).await.is_err());
    assert_eq!(fs::read(outside.join("sentinel")).await.unwrap(), b"outside");
}

#[tokio::test]
async fn concurrent_instances_choose_one_winner_through_database_cas_and_keep_it_readable() {
    let mut fixture = LocalFixture::new();
    seed(&mut fixture).await;
    let repository = CasRepository::new(fixture.account.clone(), CasOutcome::Success);
    let first = AvatarService::new(repository.clone(), NoGrants, fixture.storage.clone(), 4096);
    let second = AvatarService::new(repository.clone(), NoGrants,
        LocalAvatarStorage::new(fixture.root.clone()), 4096);
    let (first_result, second_result) = tokio::join!(
        first.upload(&fixture.account, png()),
        second.upload(&fixture.account, png()),
    );
    assert!(matches!((&first_result, &second_result),
        (Ok(_), Err(UploadAvatarError::ConcurrentChange))
        | (Err(UploadAvatarError::ConcurrentChange), Ok(_))));
    let current = repository.account.lock().unwrap().clone();
    first.read(&current).await.unwrap();
    assert_eq!(version_count(&fixture).await, 1);
}
