use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use nazo_identity::{
    AvatarContentType, AvatarObject, UserId,
    ports::{AvatarStorageError, AvatarStorageFuture, AvatarStoragePort},
};
use serde::{Deserialize, Serialize};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use uuid::Uuid;

const AVATAR_FILE_NAME: &str = "avatar.bin";
const METADATA_FILE_NAME: &str = "meta.json";
const VERSIONS_DIRECTORY: &str = "versions";
const LOCK_STRIPES: usize = 256;

#[derive(Clone)]
pub(crate) struct LocalAvatarStorage {
    root: Arc<PathBuf>,
    // Only legacy reads and retirement need serialization. Immutable candidates
    // never hold this lock while awaiting the database.
    locks: Arc<Vec<Arc<Mutex<()>>>>,
}

pub(crate) struct LocalAvatarMutation {
    root: Arc<PathBuf>,
    user_id: UserId,
    candidate_version: Option<String>,
    previous_version: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct AvatarMetadata {
    content_type: String,
    version: String,
}

impl LocalAvatarStorage {
    pub(crate) fn new(root: PathBuf) -> Self {
        Self {
            root: Arc::new(root),
            locks: Arc::new(
                (0..LOCK_STRIPES)
                    .map(|_| Arc::new(Mutex::new(())))
                    .collect(),
            ),
        }
    }

    fn user_dir(&self, user_id: UserId) -> PathBuf {
        self.root.join(user_id.as_uuid().to_string())
    }

    fn lock(&self, user_id: UserId) -> Arc<Mutex<()>> {
        let raw_user_id = user_id.as_uuid();
        let index = raw_user_id.as_bytes().iter().fold(0usize, |value, byte| {
            value.wrapping_mul(31) ^ usize::from(*byte)
        }) % self.locks.len();
        self.locks[index].clone()
    }

    fn mutation(
        &self,
        user_id: UserId,
        candidate_version: Option<String>,
        previous_version: Option<&str>,
    ) -> LocalAvatarMutation {
        LocalAvatarMutation {
            root: Arc::clone(&self.root),
            user_id,
            candidate_version,
            previous_version: previous_version.map(str::to_owned),
        }
    }

    fn check_mutation(&self, mutation: &LocalAvatarMutation) -> Result<(), AvatarStorageError> {
        if self.root != mutation.root {
            return Err(AvatarStorageError::InvalidState);
        }
        Ok(())
    }

    async fn check_user_dir(&self, user_id: UserId) -> Result<PathBuf, AvatarStorageError> {
        check_directory_path(&self.root).await?;
        let user_dir = self.user_dir(user_id);
        check_directory_path(&user_dir).await?;
        Ok(user_dir)
    }

    async fn read_object(
        &self,
        avatar_path: &Path,
        metadata_path: &Path,
        expected_version: &str,
    ) -> Result<AvatarObject, AvatarStorageError> {
        let metadata = read_metadata(metadata_path)
            .await?
            .ok_or(AvatarStorageError::Missing)?;
        if metadata.version != expected_version {
            return Err(AvatarStorageError::InvalidState);
        }
        let bytes = read_regular_file(avatar_path).await?;
        let detected = AvatarContentType::detect(&bytes).ok_or(AvatarStorageError::InvalidState)?;
        // Historical metadata sometimes had an unrecognized MIME. Preserve
        // decoding that legacy image, but reject a supported MIME mismatch.
        if let Some(declared) = AvatarContentType::parse(&metadata.content_type)
            && declared != detected
        {
            return Err(AvatarStorageError::InvalidState);
        }
        Ok(AvatarObject {
            bytes,
            content_type: detected,
            version: metadata.version,
        })
    }

    async fn read_legacy(
        &self,
        user_dir: &Path,
        expected_version: &str,
    ) -> Result<AvatarObject, AvatarStorageError> {
        let primary = match self
            .read_object(
                &user_dir.join(AVATAR_FILE_NAME),
                &user_dir.join(METADATA_FILE_NAME),
                expected_version,
            )
            .await
        {
            Ok(avatar) => return Ok(avatar),
            Err(error @ (AvatarStorageError::Missing | AvatarStorageError::InvalidState)) => error,
            Err(error) => return Err(error),
        };
        let mut matched = None;
        for (avatar_path, metadata_path) in legacy_backups(user_dir).await? {
            match self
                .read_object(&avatar_path, &metadata_path, expected_version)
                .await
            {
                Ok(avatar) if matched.is_none() => matched = Some(avatar),
                Ok(_) => return Err(AvatarStorageError::InvalidState),
                Err(AvatarStorageError::Missing | AvatarStorageError::InvalidState) => {}
                Err(error) => return Err(error),
            }
        }
        matched.ok_or(primary)
    }

    async fn remove_candidate(
        &self,
        user_id: UserId,
        version: &str,
    ) -> Result<(), AvatarStorageError> {
        if !canonical_version(version) {
            return Err(AvatarStorageError::InvalidState);
        }
        let user_dir = self.check_user_dir(user_id).await?;
        let versions = user_dir.join(VERSIONS_DIRECTORY);
        check_directory_path(&versions).await?;
        let candidate = versions.join(version);
        match check_directory_path(&candidate).await {
            Err(AvatarStorageError::Missing) => return Ok(()),
            result => result?,
        }
        remove_pair(
            &candidate.join(AVATAR_FILE_NAME),
            &candidate.join(METADATA_FILE_NAME),
        )
        .await?;
        fs::remove_dir(&candidate).await.map_err(unavailable)?;
        sync_directory(&versions).await
    }

    async fn retire_version(&self, user_id: UserId, version: &str) {
        // An arbitrary historical version is metadata, never a path component.
        if canonical_version(version) {
            let result = async {
                let user_dir = self.check_user_dir(user_id).await?;
                let versions = user_dir.join(VERSIONS_DIRECTORY);
                check_directory_path(&versions).await?;
                let directory = versions.join(version);
                check_directory_path(&directory).await?;
                let metadata = read_metadata(&directory.join(METADATA_FILE_NAME))
                    .await?
                    .ok_or(AvatarStorageError::InvalidState)?;
                if metadata.version != version {
                    return Err(AvatarStorageError::InvalidState);
                }
                self.remove_candidate(user_id, version).await
            }
            .await;
            if let Err(error) = result
                && error != AvatarStorageError::Missing
            {
                tracing::warn!(%error, "failed to retire previous avatar version");
            }
        }

        let _guard = self.lock(user_id).lock_owned().await;
        let user_dir = match self.check_user_dir(user_id).await {
            Ok(directory) => directory,
            Err(AvatarStorageError::Missing) => return,
            Err(error) => {
                tracing::warn!(%error, "failed to inspect legacy avatar directory");
                return;
            }
        };
        let mut pairs = vec![(
            user_dir.join(AVATAR_FILE_NAME),
            user_dir.join(METADATA_FILE_NAME),
        )];
        match legacy_backups(&user_dir).await {
            Ok(backups) => pairs.extend(backups),
            Err(error) => tracing::warn!(%error, "failed to inspect legacy avatar backups"),
        }
        for (avatar_path, metadata_path) in pairs {
            let result = async {
                if let Some(metadata) = read_metadata(&metadata_path).await?
                    && metadata.version == version
                {
                    remove_pair(&avatar_path, &metadata_path).await?;
                    sync_directory(&user_dir).await?;
                }
                Ok::<(), AvatarStorageError>(())
            }
            .await;
            if let Err(error) = result {
                tracing::warn!(%error, "failed to retire matching legacy avatar files");
            }
        }
    }
}

impl AvatarStoragePort for LocalAvatarStorage {
    type Mutation = LocalAvatarMutation;

    fn begin_replace<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        avatar: AvatarObject,
    ) -> AvatarStorageFuture<'a, Self::Mutation> {
        Box::pin(async move {
            if !canonical_version(&avatar.version)
                || expected_version == Some(avatar.version.as_str())
            {
                return Err(AvatarStorageError::InvalidState);
            }
            let versions = self.user_dir(user_id).join(VERSIONS_DIRECTORY);
            ensure_directory_path(&versions)
                .await
                .map_err(as_preparation_failure)?;
            let candidate = versions.join(&avatar.version);
            // Exclusive creation gives this request sole cleanup ownership.
            // Existing directories (including partial ones) are never reused.
            fs::create_dir(&candidate).await.map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    AvatarStorageError::Conflict
                } else {
                    as_preparation_failure(unavailable(error))
                }
            })?;
            let prepared = async {
                restrict_directory(&candidate).await?;
                write_new_file(&candidate.join(AVATAR_FILE_NAME), &avatar.bytes).await?;
                let metadata = serde_json::to_vec(&AvatarMetadata {
                    content_type: avatar.content_type.as_str().to_owned(),
                    version: avatar.version.clone(),
                })
                .map_err(|_| AvatarStorageError::InvalidState)?;
                write_new_file(&candidate.join(METADATA_FILE_NAME), &metadata).await?;
                sync_directory(&candidate).await?;
                // Another request may have created a parent and then been
                // cancelled before syncing its entry. Complete our own entire
                // directory publication before permitting the database CAS.
                for directory in versions.ancestors() {
                    sync_directory(directory).await?;
                }
                Ok::<(), AvatarStorageError>(())
            }
            .await;
            if let Err(error) = prepared {
                // No database write has started. Cancellation may skip this
                // best-effort cleanup and leave an unreferenced partial version.
                let _ = self.remove_candidate(user_id, &avatar.version).await;
                return Err(as_preparation_failure(error));
            }
            Ok(self.mutation(user_id, Some(avatar.version), expected_version))
        })
    }

    fn begin_delete<'a>(
        &'a self,
        user_id: UserId,
        expected_version: Option<&'a str>,
        _revision: &'a str,
    ) -> AvatarStorageFuture<'a, Self::Mutation> {
        // The database reference is the sole authority. Deletion preparation
        // performs no filesystem mutation or active-version consistency CAS.
        Box::pin(async move { Ok(self.mutation(user_id, None, expected_version)) })
    }

    fn commit<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            self.check_mutation(mutation)?;
            if let Some(previous) = mutation.previous_version.as_deref() {
                self.retire_version(mutation.user_id, previous).await;
            }
            // The CAS already succeeded. Cleanup failure leaves an orphan;
            // it cannot turn the selected new version into a failed upload.
            Ok(())
        })
    }

    fn rollback<'a>(&'a self, mutation: &'a Self::Mutation) -> AvatarStorageFuture<'a, ()> {
        Box::pin(async move {
            self.check_mutation(mutation)?;
            if let Some(candidate) = mutation.candidate_version.as_deref() {
                self.remove_candidate(mutation.user_id, candidate).await?;
            }
            Ok(())
        })
    }

    fn read<'a>(
        &'a self,
        user_id: UserId,
        expected_version: &'a str,
    ) -> AvatarStorageFuture<'a, AvatarObject> {
        Box::pin(async move {
            let user_dir = self.check_user_dir(user_id).await?;
            if canonical_version(expected_version) {
                let versions = user_dir.join(VERSIONS_DIRECTORY);
                match check_directory_path(&versions).await {
                    Ok(()) => {
                        let directory = versions.join(expected_version);
                        match check_directory_path(&directory).await {
                            Ok(()) => {
                                return self
                                    .read_object(
                                        &directory.join(AVATAR_FILE_NAME),
                                        &directory.join(METADATA_FILE_NAME),
                                        expected_version,
                                    )
                                    .await;
                            }
                            Err(AvatarStorageError::Missing) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    Err(AvatarStorageError::Missing) => {}
                    Err(error) => return Err(error),
                }
            }
            let _guard = self.lock(user_id).lock_owned().await;
            self.read_legacy(&user_dir, expected_version).await
        })
    }
}

fn canonical_version(version: &str) -> bool {
    Uuid::parse_str(version).is_ok_and(|uuid| uuid.to_string() == version)
}

async fn legacy_backups(user_dir: &Path) -> Result<Vec<(PathBuf, PathBuf)>, AvatarStorageError> {
    let mut entries = fs::read_dir(user_dir).await.map_err(unavailable)?;
    let mut pairs = Vec::new();
    while let Some(entry) = entries.next_entry().await.map_err(unavailable)? {
        let name = entry.file_name();
        let Some(revision) = name
            .to_str()
            .and_then(|name| name.strip_prefix("meta-"))
            .and_then(|name| name.strip_suffix(".bak"))
            .filter(|revision| {
                !revision.is_empty()
                    && revision
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            })
        else {
            continue;
        };
        pairs.push((
            user_dir.join(format!("avatar-{revision}.bak")),
            entry.path(),
        ));
    }
    Ok(pairs)
}

async fn check_directory_path(path: &Path) -> Result<(), AvatarStorageError> {
    if !path.is_absolute() {
        return Err(AvatarStorageError::InvalidState);
    }
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component)
            .await
            .map_err(missing_or_unavailable)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AvatarStorageError::InvalidState);
        }
    }
    Ok(())
}

async fn ensure_directory_path(path: &Path) -> Result<(), AvatarStorageError> {
    if !path.is_absolute() {
        return Err(AvatarStorageError::InvalidState);
    }
    for directory in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(directory).await {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => return Err(AvatarStorageError::InvalidState),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match fs::create_dir(directory).await {
                    Ok(()) => {
                        restrict_directory(directory).await?;
                        sync_directory(directory).await?;
                        if let Some(parent) = directory.parent() {
                            sync_directory(parent).await?;
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        check_directory_path(directory).await?;
                    }
                    Err(error) => return Err(unavailable(error)),
                }
            }
            Err(error) => return Err(unavailable(error)),
        }
    }
    Ok(())
}

async fn restrict_directory(path: &Path) -> Result<(), AvatarStorageError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(unavailable)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

async fn sync_directory(path: &Path) -> Result<(), AvatarStorageError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW).bits() as i32,
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            options.custom_flags(0x0200_0000); // FILE_FLAG_BACKUP_SEMANTICS
        }
        options.open(path)?.sync_all()
    })
    .await
    .map_err(|error| AvatarStorageError::Unavailable(error.to_string()))?
    .map_err(unavailable)
}

async fn read_regular_file(path: &Path) -> Result<Vec<u8>, AvatarStorageError> {
    check_regular_file(path).await?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32);
    let mut file = options.open(path).await.map_err(missing_or_unavailable)?;
    if !file.metadata().await.map_err(unavailable)?.is_file() {
        return Err(AvatarStorageError::InvalidState);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await.map_err(unavailable)?;
    Ok(bytes)
}

async fn check_regular_file(path: &Path) -> Result<(), AvatarStorageError> {
    let metadata = fs::symlink_metadata(path)
        .await
        .map_err(missing_or_unavailable)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(AvatarStorageError::InvalidState);
    }
    Ok(())
}

async fn read_metadata(path: &Path) -> Result<Option<AvatarMetadata>, AvatarStorageError> {
    match read_regular_file(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| AvatarStorageError::InvalidState),
        Err(AvatarStorageError::Missing) => Ok(None),
        Err(error) => Err(error),
    }
}

async fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), AvatarStorageError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await.map_err(unavailable)?;
    file.write_all(bytes).await.map_err(unavailable)?;
    file.flush().await.map_err(unavailable)?;
    file.sync_all().await.map_err(unavailable)
}

async fn remove_pair(avatar: &Path, metadata: &Path) -> Result<(), AvatarStorageError> {
    // Inspect both paths before unlinking either. Never recursively remove a
    // directory or follow a symlink during best-effort retirement.
    for path in [avatar, metadata] {
        match check_regular_file(path).await {
            Ok(()) | Err(AvatarStorageError::Missing) => {}
            Err(error) => return Err(error),
        }
    }
    for path in [avatar, metadata] {
        match fs::remove_file(path).await {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(unavailable(error)),
        }
    }
    Ok(())
}

fn missing_or_unavailable(error: io::Error) -> AvatarStorageError {
    if error.kind() == io::ErrorKind::NotFound {
        AvatarStorageError::Missing
    } else {
        unavailable(error)
    }
}

fn unavailable(error: io::Error) -> AvatarStorageError {
    AvatarStorageError::Unavailable(error.to_string())
}

fn as_preparation_failure(error: AvatarStorageError) -> AvatarStorageError {
    match error {
        AvatarStorageError::Unavailable(message) => AvatarStorageError::PreparationFailed(message),
        AvatarStorageError::InvalidState => AvatarStorageError::PreparationFailed(
            "avatar directory or file path is invalid".to_owned(),
        ),
        other => other,
    }
}

#[cfg(test)]
#[path = "../../tests/unit/adapters/avatar_files.rs"]
mod tests;
