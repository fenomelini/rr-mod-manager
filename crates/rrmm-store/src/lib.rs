use rrmm_domain::{InstallationInspection, Profile};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const MIGRATIONS: &[&str] = &[
    r#"
    CREATE TABLE installations (
        id INTEGER PRIMARY KEY,
        manifest_path TEXT NOT NULL UNIQUE,
        game_root TEXT NOT NULL,
        app_id INTEGER NOT NULL,
        build_id INTEGER NOT NULL,
        build_status TEXT NOT NULL,
        inspection_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    );

    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
"#,
    r#"
    CREATE TABLE artifacts (
        sha256 TEXT PRIMARY KEY,
        root TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        accepted_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
"#,
    r#"
    CREATE TABLE pak_inventory_cache (
        canonical_path TEXT PRIMARY KEY,
        build_id INTEGER NOT NULL,
        archive_bytes INTEGER NOT NULL,
        modified_ns INTEGER NOT NULL,
        index_metadata_sha256 TEXT NOT NULL,
        inventory_json TEXT NOT NULL,
        cached_at INTEGER NOT NULL DEFAULT (unixepoch())
    );

    CREATE INDEX pak_inventory_cache_build_id
        ON pak_inventory_cache(build_id);
"#,
    r#"
    CREATE TABLE profiles (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        revision INTEGER NOT NULL,
        profile_json TEXT NOT NULL,
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    );

    CREATE TABLE active_profiles (
        installation_id TEXT PRIMARY KEY,
        profile_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE RESTRICT,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
"#,
    r#"
    CREATE TABLE catalog_trust_state (
        channel TEXT PRIMARY KEY,
        root_generation INTEGER NOT NULL,
        root_payload_sha256 TEXT NOT NULL,
        catalog_sequence INTEGER NOT NULL,
        catalog_payload_sha256 TEXT NOT NULL,
        updated_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
"#,
    r#"
    CREATE TABLE installation_bindings (
        installation_id TEXT PRIMARY KEY,
        manifest_path TEXT NOT NULL UNIQUE,
        game_root TEXT NOT NULL UNIQUE,
        created_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
"#,
    r#"
    -- Profile JSON from schema 6 remains valid through serde defaults.
"#,
    r#"
    CREATE TABLE file_verification_cache (
        canonical_path TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        file_id TEXT NOT NULL,
        bytes INTEGER NOT NULL,
        modified_ns INTEGER NOT NULL,
        changed_ns INTEGER NOT NULL,
        sha256 TEXT NOT NULL,
        verified_at INTEGER NOT NULL DEFAULT (unixepoch())
    );

    CREATE INDEX file_verification_cache_sha256
        ON file_verification_cache(sha256);
"#,
    r#"
    CREATE TABLE activation_pak_analysis_cache (
        cache_key TEXT PRIMARY KEY,
        analysis_json TEXT NOT NULL,
        cached_at INTEGER NOT NULL DEFAULT (unixepoch())
    );
"#,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PakCacheFingerprint {
    pub canonical_path: PathBuf,
    pub build_id: u64,
    pub archive_bytes: u64,
    pub modified_ns: i64,
    pub index_metadata_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVerificationFingerprint {
    pub canonical_path: PathBuf,
    pub device_id: String,
    pub file_id: String,
    pub bytes: u64,
    pub modified_ns: i64,
    pub changed_ns: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogTrustState {
    pub root_generation: u64,
    pub root_payload_sha256: String,
    pub catalog_sequence: u64,
    pub catalog_payload_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StoredArtifact {
    pub sha256: String,
    pub root: PathBuf,
    pub manifest: serde_json::Value,
    pub accepted_at: i64,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("failed to create database directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("invalid profile: {0}")]
    InvalidProfile(String),
    #[error("profile does not exist: {0}")]
    ProfileNotFound(String),
    #[error("artifact does not exist: {0}")]
    ArtifactNotFound(String),
    #[error("profile revision changed; expected {expected} for {id}")]
    ProfileRevisionConflict { id: String, expected: u64 },
    #[error("database schema {found} is newer than supported schema {supported}")]
    NewerSchema { found: u32, supported: u32 },
    #[error("catalog trust state would roll back or replace an accepted version for {0}")]
    CatalogTrustRollback(String),
    #[error("invalid catalog trust state: {0}")]
    InvalidCatalogTrust(String),
    #[error("installation identifier is already bound to a different Steam installation: {0}")]
    InstallationBindingMismatch(String),
}

pub struct Store {
    connection: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|source| StoreError::CreateDirectory {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let connection = Connection::open(path)?;
        Self::initialize(connection)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::initialize(Connection::open_in_memory()?)
    }

    fn initialize(connection: Connection) -> Result<Self, StoreError> {
        connection.pragma_update(None, "foreign_keys", true)?;
        let mut store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    pub fn schema_version(&self) -> Result<u32, StoreError> {
        Ok(self
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?)
    }

    pub fn upsert_installation(
        &self,
        inspection: &InstallationInspection,
    ) -> Result<(), StoreError> {
        let payload = serde_json::to_string(inspection)?;
        let build_status = serde_json::to_string(&inspection.build_status)?;
        self.connection.execute(
            r#"
            INSERT INTO installations (
                manifest_path, game_root, app_id, build_id, build_status, inspection_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(manifest_path) DO UPDATE SET
                game_root = excluded.game_root,
                app_id = excluded.app_id,
                build_id = excluded.build_id,
                build_status = excluded.build_status,
                inspection_json = excluded.inspection_json,
                updated_at = unixepoch()
            "#,
            params![
                inspection.installation.manifest_path.to_string_lossy(),
                inspection.installation.game_root.to_string_lossy(),
                inspection.installation.app_id,
                inspection.installation.build_id,
                build_status.trim_matches('"'),
                payload,
            ],
        )?;
        Ok(())
    }

    pub fn installations(&self) -> Result<Vec<InstallationInspection>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT inspection_json FROM installations ORDER BY manifest_path")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(serde_json::from_str(&row?)?);
        }
        Ok(result)
    }

    pub fn bind_installation_id(
        &self,
        installation_id: &str,
        manifest_path: &Path,
        game_root: &Path,
    ) -> Result<(), StoreError> {
        validate_identifier("installation", installation_id)?;
        let manifest_path = manifest_path.to_string_lossy();
        let game_root = game_root.to_string_lossy();
        self.connection.execute(
            r#"
            INSERT OR IGNORE INTO installation_bindings (
                installation_id, manifest_path, game_root
            ) VALUES (?1, ?2, ?3)
            "#,
            params![installation_id, manifest_path, game_root],
        )?;
        let existing = self
            .connection
            .query_row(
                r#"
                SELECT manifest_path, game_root
                FROM installation_bindings
                WHERE installation_id = ?1
                "#,
                [installation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        if existing
            .as_ref()
            .is_none_or(|existing| existing.0 != manifest_path || existing.1 != game_root)
        {
            return Err(StoreError::InstallationBindingMismatch(
                installation_id.to_owned(),
            ));
        }
        Ok(())
    }

    pub fn validate_installation_binding(
        &self,
        installation_id: &str,
        manifest_path: &Path,
        game_root: &Path,
    ) -> Result<(), StoreError> {
        validate_identifier("installation", installation_id)?;
        let existing = self
            .connection
            .query_row(
                r#"
                SELECT manifest_path, game_root
                FROM installation_bindings
                WHERE installation_id = ?1
                "#,
                [installation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let manifest_path = manifest_path.to_string_lossy();
        let game_root = game_root.to_string_lossy();
        if existing
            .as_ref()
            .is_none_or(|existing| existing.0 != manifest_path || existing.1 != game_root)
        {
            return Err(StoreError::InstallationBindingMismatch(
                installation_id.to_owned(),
            ));
        }
        Ok(())
    }

    pub fn installation_binding(
        &self,
        installation_id: &str,
    ) -> Result<Option<(PathBuf, PathBuf)>, StoreError> {
        validate_identifier("installation", installation_id)?;
        self.connection
            .query_row(
                "SELECT manifest_path, game_root FROM installation_bindings WHERE installation_id = ?1",
                [installation_id],
                |row| {
                    Ok((
                        PathBuf::from(row.get::<_, String>(0)?),
                        PathBuf::from(row.get::<_, String>(1)?),
                    ))
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn setting(&self, key: &str) -> Result<Option<serde_json::Value>, StoreError> {
        let value = self
            .connection
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        value
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(StoreError::from)
    }

    pub fn set_setting(&self, key: &str, value: &serde_json::Value) -> Result<(), StoreError> {
        let value_json = serde_json::to_string(value)?;
        self.connection.execute(
            r#"
            INSERT INTO settings (key, value_json) VALUES (?1, ?2)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = unixepoch()
            "#,
            params![key, value_json],
        )?;
        Ok(())
    }

    pub fn upsert_artifact(
        &self,
        sha256: &str,
        root: &Path,
        manifest: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let manifest_json = serde_json::to_string(manifest)?;
        self.connection.execute(
            r#"
            INSERT INTO artifacts (sha256, root, manifest_json) VALUES (?1, ?2, ?3)
            ON CONFLICT(sha256) DO UPDATE SET
                root = excluded.root,
                manifest_json = excluded.manifest_json
            "#,
            params![sha256, root.to_string_lossy(), manifest_json],
        )?;
        Ok(())
    }

    pub fn artifact(&self, sha256: &str) -> Result<Option<serde_json::Value>, StoreError> {
        let value = self
            .connection
            .query_row(
                "SELECT manifest_json FROM artifacts WHERE sha256 = ?1",
                [sha256],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        value
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(StoreError::from)
    }

    pub fn artifacts(&self) -> Result<Vec<StoredArtifact>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT sha256, root, manifest_json, accepted_at FROM artifacts ORDER BY accepted_at, sha256",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut artifacts = Vec::new();
        for row in rows {
            let (sha256, root, manifest, accepted_at) = row?;
            artifacts.push(StoredArtifact {
                sha256,
                root: PathBuf::from(root),
                manifest: serde_json::from_str(&manifest)?,
                accepted_at,
            });
        }
        Ok(artifacts)
    }

    pub fn delete_artifact_and_profile_references(
        &mut self,
        sha256: &str,
    ) -> Result<StoredArtifact, StoreError> {
        let transaction = self.connection.transaction()?;
        let artifact = transaction
            .query_row(
                "SELECT sha256, root, manifest_json, accepted_at FROM artifacts WHERE sha256 = ?1",
                [sha256],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::ArtifactNotFound(sha256.to_owned()))?;
        let artifact_manifest = serde_json::from_str(&artifact.2)?;
        let profile_rows = {
            let mut statement = transaction.prepare("SELECT profile_json FROM profiles")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        for profile_json in profile_rows {
            let mut profile: Profile = serde_json::from_str(&profile_json)?;
            if profile
                .packages
                .iter()
                .any(|package| package.artifact_sha256 == sha256 && package.enabled)
            {
                return Err(StoreError::InvalidProfile(format!(
                    "artifact '{sha256}' is enabled in profile '{}'",
                    profile.name
                )));
            }
            let previous_len = profile.packages.len();
            profile
                .packages
                .retain(|package| package.artifact_sha256 != sha256);
            if profile.packages.len() != previous_len {
                profile.revision = profile.revision.checked_add(1).ok_or_else(|| {
                    StoreError::InvalidProfile("profile revision overflowed".to_owned())
                })?;
                validate_profile(&profile)?;
                transaction.execute(
                    "UPDATE profiles SET revision = ?1, profile_json = ?2, updated_at = unixepoch() WHERE id = ?3",
                    params![profile.revision, serde_json::to_string(&profile)?, profile.id],
                )?;
            }
        }
        transaction.execute("DELETE FROM artifacts WHERE sha256 = ?1", [sha256])?;
        transaction.commit()?;
        Ok(StoredArtifact {
            sha256: artifact.0,
            root: PathBuf::from(artifact.1),
            manifest: artifact_manifest,
            accepted_at: artifact.3,
        })
    }

    pub fn update_profiles_batch(
        &mut self,
        profiles: &[(Profile, u64)],
    ) -> Result<Vec<Profile>, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut updated_profiles = Vec::with_capacity(profiles.len());
        for (profile, expected_revision) in profiles {
            validate_profile(profile)?;
            if profile.revision != *expected_revision {
                return Err(StoreError::ProfileRevisionConflict {
                    id: profile.id.clone(),
                    expected: *expected_revision,
                });
            }
            let mut updated = profile.clone();
            updated.revision = expected_revision.checked_add(1).ok_or_else(|| {
                StoreError::InvalidProfile("profile revision overflowed".to_owned())
            })?;
            let changed = transaction.execute(
                r#"
                UPDATE profiles
                SET name = ?1, revision = ?2, profile_json = ?3, updated_at = unixepoch()
                WHERE id = ?4 AND revision = ?5
                "#,
                params![
                    updated.name,
                    updated.revision,
                    serde_json::to_string(&updated)?,
                    updated.id,
                    expected_revision,
                ],
            )?;
            if changed == 0 {
                let exists = transaction
                    .query_row(
                        "SELECT 1 FROM profiles WHERE id = ?1",
                        [&profile.id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !exists {
                    return Err(StoreError::ProfileNotFound(profile.id.clone()));
                }
                return Err(StoreError::ProfileRevisionConflict {
                    id: profile.id.clone(),
                    expected: *expected_revision,
                });
            }
            updated_profiles.push(updated);
        }
        transaction.commit()?;
        Ok(updated_profiles)
    }

    pub fn replace_artifacts_and_update_profiles(
        &mut self,
        upserted: &[StoredArtifact],
        deleted_sha256: &[String],
        profiles: &[(Profile, u64)],
    ) -> Result<Vec<Profile>, StoreError> {
        let transaction = self.connection.transaction()?;
        for artifact in upserted {
            let manifest_json = serde_json::to_string(&artifact.manifest)?;
            transaction.execute(
                r#"
                INSERT INTO artifacts (sha256, root, manifest_json, accepted_at)
                VALUES (?1, ?2, ?3, CASE WHEN ?4 = 0 THEN unixepoch() ELSE ?4 END)
                ON CONFLICT(sha256) DO UPDATE SET
                    root = excluded.root,
                    manifest_json = excluded.manifest_json
                "#,
                params![
                    artifact.sha256,
                    artifact.root.to_string_lossy(),
                    manifest_json,
                    artifact.accepted_at,
                ],
            )?;
        }

        let mut updated_profiles = Vec::with_capacity(profiles.len());
        for (profile, expected_revision) in profiles {
            validate_profile(profile)?;
            if profile.revision != *expected_revision {
                return Err(StoreError::ProfileRevisionConflict {
                    id: profile.id.clone(),
                    expected: *expected_revision,
                });
            }
            let mut updated = profile.clone();
            updated.revision = expected_revision.checked_add(1).ok_or_else(|| {
                StoreError::InvalidProfile("profile revision overflowed".to_owned())
            })?;
            let changed = transaction.execute(
                r#"
                UPDATE profiles
                SET name = ?1, revision = ?2, profile_json = ?3, updated_at = unixepoch()
                WHERE id = ?4 AND revision = ?5
                "#,
                params![
                    updated.name,
                    updated.revision,
                    serde_json::to_string(&updated)?,
                    updated.id,
                    expected_revision,
                ],
            )?;
            if changed == 0 {
                let exists = transaction
                    .query_row(
                        "SELECT 1 FROM profiles WHERE id = ?1",
                        [&profile.id],
                        |_| Ok(()),
                    )
                    .optional()?
                    .is_some();
                if !exists {
                    return Err(StoreError::ProfileNotFound(profile.id.clone()));
                }
                return Err(StoreError::ProfileRevisionConflict {
                    id: profile.id.clone(),
                    expected: *expected_revision,
                });
            }
            updated_profiles.push(updated);
        }

        if !deleted_sha256.is_empty() {
            let deleted = deleted_sha256
                .iter()
                .collect::<std::collections::BTreeSet<_>>();
            let profile_rows = {
                let mut statement = transaction.prepare("SELECT profile_json FROM profiles")?;
                let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            for profile_json in profile_rows {
                let profile: Profile = serde_json::from_str(&profile_json)?;
                if let Some(package) = profile
                    .packages
                    .iter()
                    .find(|package| deleted.contains(&package.artifact_sha256))
                {
                    return Err(StoreError::InvalidProfile(format!(
                        "artifact '{}' is still referenced by profile '{}'",
                        package.artifact_sha256, profile.name
                    )));
                }
            }
        }
        for sha256 in deleted_sha256 {
            let changed =
                transaction.execute("DELETE FROM artifacts WHERE sha256 = ?1", [sha256])?;
            if changed == 0 {
                return Err(StoreError::ArtifactNotFound(sha256.clone()));
            }
        }
        transaction.commit()?;
        Ok(updated_profiles)
    }

    pub fn delete_artifacts_without_profile_references(
        &mut self,
        artifact_sha256: &[String],
    ) -> Result<Vec<StoredArtifact>, StoreError> {
        let transaction = self.connection.transaction()?;
        let profile_rows = {
            let mut statement = transaction.prepare("SELECT profile_json FROM profiles")?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<Result<Vec<_>, _>>()?
        };
        let profiles = profile_rows
            .into_iter()
            .map(|json| serde_json::from_str::<Profile>(&json))
            .collect::<Result<Vec<_>, _>>()?;
        let mut deleted = Vec::with_capacity(artifact_sha256.len());
        for sha256 in artifact_sha256 {
            if profiles.iter().any(|profile| {
                profile
                    .packages
                    .iter()
                    .any(|package| package.artifact_sha256 == *sha256)
            }) {
                return Err(StoreError::InvalidProfile(format!(
                    "artifact '{sha256}' is still referenced by a profile"
                )));
            }
            let artifact = transaction
                .query_row(
                    "SELECT sha256, root, manifest_json, accepted_at FROM artifacts WHERE sha256 = ?1",
                    [sha256],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()?
                .ok_or_else(|| StoreError::ArtifactNotFound(sha256.clone()))?;
            deleted.push(StoredArtifact {
                sha256: artifact.0,
                root: PathBuf::from(artifact.1),
                manifest: serde_json::from_str(&artifact.2)?,
                accepted_at: artifact.3,
            });
        }
        for sha256 in artifact_sha256 {
            transaction.execute("DELETE FROM artifacts WHERE sha256 = ?1", [sha256])?;
        }
        transaction.commit()?;
        Ok(deleted)
    }

    pub fn pak_inventory<T>(
        &self,
        fingerprint: &PakCacheFingerprint,
    ) -> Result<Option<T>, StoreError>
    where
        T: DeserializeOwned,
    {
        let canonical_path = fingerprint.canonical_path.to_string_lossy();
        let value = self
            .connection
            .query_row(
                r#"
                SELECT inventory_json
                FROM pak_inventory_cache
                WHERE canonical_path = ?1
                    AND build_id = ?2
                    AND archive_bytes = ?3
                    AND modified_ns = ?4
                    AND index_metadata_sha256 = ?5
                "#,
                params![
                    canonical_path,
                    fingerprint.build_id,
                    fingerprint.archive_bytes,
                    fingerprint.modified_ns,
                    fingerprint.index_metadata_sha256,
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(value) = value else {
            return Ok(None);
        };
        match serde_json::from_str(&value) {
            Ok(value) => Ok(Some(value)),
            Err(_) => {
                self.connection.execute(
                    "DELETE FROM pak_inventory_cache WHERE canonical_path = ?1",
                    [canonical_path],
                )?;
                Ok(None)
            }
        }
    }

    pub fn upsert_pak_inventory<T>(
        &self,
        fingerprint: &PakCacheFingerprint,
        inventory: &T,
    ) -> Result<(), StoreError>
    where
        T: Serialize,
    {
        let inventory_json = serde_json::to_string(inventory)?;
        self.connection.execute(
            r#"
            INSERT INTO pak_inventory_cache (
                canonical_path, build_id, archive_bytes, modified_ns,
                index_metadata_sha256, inventory_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(canonical_path) DO UPDATE SET
                build_id = excluded.build_id,
                archive_bytes = excluded.archive_bytes,
                modified_ns = excluded.modified_ns,
                index_metadata_sha256 = excluded.index_metadata_sha256,
                inventory_json = excluded.inventory_json,
                cached_at = unixepoch()
            "#,
            params![
                fingerprint.canonical_path.to_string_lossy(),
                fingerprint.build_id,
                fingerprint.archive_bytes,
                fingerprint.modified_ns,
                fingerprint.index_metadata_sha256,
                inventory_json,
            ],
        )?;
        Ok(())
    }

    pub fn file_is_verified(
        &self,
        fingerprint: &FileVerificationFingerprint,
    ) -> Result<bool, StoreError> {
        let found = self
            .connection
            .query_row(
                r#"
                SELECT 1
                FROM file_verification_cache
                WHERE canonical_path = ?1
                    AND device_id = ?2
                    AND file_id = ?3
                    AND bytes = ?4
                    AND modified_ns = ?5
                    AND changed_ns = ?6
                    AND sha256 = ?7
                "#,
                params![
                    fingerprint.canonical_path.to_string_lossy(),
                    fingerprint.device_id,
                    fingerprint.file_id,
                    fingerprint.bytes,
                    fingerprint.modified_ns,
                    fingerprint.changed_ns,
                    fingerprint.sha256,
                ],
                |_| Ok(()),
            )
            .optional()?;
        Ok(found.is_some())
    }

    pub fn verified_file_sha256(
        &self,
        fingerprint: &FileVerificationFingerprint,
    ) -> Result<Option<String>, StoreError> {
        Ok(self
            .connection
            .query_row(
                r#"
                SELECT sha256
                FROM file_verification_cache
                WHERE canonical_path = ?1
                    AND device_id = ?2
                    AND file_id = ?3
                    AND bytes = ?4
                    AND modified_ns = ?5
                    AND changed_ns = ?6
                "#,
                params![
                    fingerprint.canonical_path.to_string_lossy(),
                    fingerprint.device_id,
                    fingerprint.file_id,
                    fingerprint.bytes,
                    fingerprint.modified_ns,
                    fingerprint.changed_ns,
                ],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn upsert_file_verification(
        &self,
        fingerprint: &FileVerificationFingerprint,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            r#"
            INSERT INTO file_verification_cache (
                canonical_path, device_id, file_id, bytes, modified_ns,
                changed_ns, sha256
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(canonical_path) DO UPDATE SET
                device_id = excluded.device_id,
                file_id = excluded.file_id,
                bytes = excluded.bytes,
                modified_ns = excluded.modified_ns,
                changed_ns = excluded.changed_ns,
                sha256 = excluded.sha256,
                verified_at = unixepoch()
            "#,
            params![
                fingerprint.canonical_path.to_string_lossy(),
                fingerprint.device_id,
                fingerprint.file_id,
                fingerprint.bytes,
                fingerprint.modified_ns,
                fingerprint.changed_ns,
                fingerprint.sha256,
            ],
        )?;
        Ok(())
    }

    pub fn activation_pak_analysis<T>(&self, cache_key: &str) -> Result<Option<T>, StoreError>
    where
        T: DeserializeOwned,
    {
        let value = self
            .connection
            .query_row(
                "SELECT analysis_json FROM activation_pak_analysis_cache WHERE cache_key = ?1",
                [cache_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(value) = value else {
            return Ok(None);
        };
        match serde_json::from_str(&value) {
            Ok(value) => Ok(Some(value)),
            Err(_) => {
                self.connection.execute(
                    "DELETE FROM activation_pak_analysis_cache WHERE cache_key = ?1",
                    [cache_key],
                )?;
                Ok(None)
            }
        }
    }

    pub fn upsert_activation_pak_analysis<T>(
        &self,
        cache_key: &str,
        analysis: &T,
    ) -> Result<(), StoreError>
    where
        T: Serialize,
    {
        let analysis_json = serde_json::to_string(analysis)?;
        self.connection.execute(
            r#"
            INSERT INTO activation_pak_analysis_cache (cache_key, analysis_json)
            VALUES (?1, ?2)
            ON CONFLICT(cache_key) DO UPDATE SET
                analysis_json = excluded.analysis_json,
                cached_at = unixepoch()
            "#,
            params![cache_key, analysis_json],
        )?;
        self.connection.execute(
            r#"
            DELETE FROM activation_pak_analysis_cache
            WHERE cache_key NOT IN (
                SELECT cache_key
                FROM activation_pak_analysis_cache
                ORDER BY cached_at DESC, cache_key DESC
                LIMIT 64
            )
            "#,
            [],
        )?;
        Ok(())
    }

    pub fn create_profile(&self, profile: &Profile) -> Result<(), StoreError> {
        validate_profile(profile)?;
        if profile.revision != 0 {
            return Err(StoreError::InvalidProfile(
                "a new profile must have revision 0".to_owned(),
            ));
        }
        let profile_json = serde_json::to_string(profile)?;
        self.connection.execute(
            "INSERT INTO profiles (id, name, revision, profile_json) VALUES (?1, ?2, ?3, ?4)",
            params![profile.id, profile.name, profile.revision, profile_json],
        )?;
        Ok(())
    }

    pub fn profile(&self, id: &str) -> Result<Option<Profile>, StoreError> {
        let value = self
            .connection
            .query_row(
                "SELECT profile_json FROM profiles WHERE id = ?1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        value
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(StoreError::from)
    }

    pub fn profiles(&self) -> Result<Vec<Profile>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT profile_json FROM profiles ORDER BY name, id")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(serde_json::from_str(&row?)?);
        }
        Ok(profiles)
    }

    pub fn update_profile(
        &self,
        profile: &Profile,
        expected_revision: u64,
    ) -> Result<Profile, StoreError> {
        validate_profile(profile)?;
        let mut updated = profile.clone();
        updated.revision = expected_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidProfile("profile revision overflowed".to_owned()))?;
        let profile_json = serde_json::to_string(&updated)?;
        let changed = self.connection.execute(
            r#"
            UPDATE profiles
            SET name = ?1, revision = ?2, profile_json = ?3, updated_at = unixepoch()
            WHERE id = ?4 AND revision = ?5
            "#,
            params![
                updated.name,
                updated.revision,
                profile_json,
                updated.id,
                expected_revision
            ],
        )?;
        if changed == 0 {
            if self.profile(&profile.id)?.is_none() {
                return Err(StoreError::ProfileNotFound(profile.id.clone()));
            }
            return Err(StoreError::ProfileRevisionConflict {
                id: profile.id.clone(),
                expected: expected_revision,
            });
        }
        Ok(updated)
    }

    pub fn clone_profile(
        &self,
        source_id: &str,
        clone_id: &str,
        clone_name: &str,
    ) -> Result<Profile, StoreError> {
        let source = self
            .profile(source_id)?
            .ok_or_else(|| StoreError::ProfileNotFound(source_id.to_owned()))?;
        let clone = Profile {
            schema_version: source.schema_version,
            id: clone_id.to_owned(),
            name: clone_name.to_owned(),
            revision: 0,
            packages: source.packages,
            pak_load_order: source.pak_load_order,
        };
        self.create_profile(&clone)?;
        Ok(clone)
    }

    pub fn delete_profile(&self, id: &str) -> Result<(), StoreError> {
        let changed = self
            .connection
            .execute("DELETE FROM profiles WHERE id = ?1", [id])?;
        if changed == 0 {
            return Err(StoreError::ProfileNotFound(id.to_owned()));
        }
        Ok(())
    }

    pub fn set_active_profile(
        &self,
        installation_id: &str,
        profile_id: &str,
    ) -> Result<(), StoreError> {
        validate_identifier("installation", installation_id)?;
        if self.profile(profile_id)?.is_none() {
            return Err(StoreError::ProfileNotFound(profile_id.to_owned()));
        }
        self.connection.execute(
            r#"
            INSERT INTO active_profiles (installation_id, profile_id) VALUES (?1, ?2)
            ON CONFLICT(installation_id) DO UPDATE SET
                profile_id = excluded.profile_id,
                updated_at = unixepoch()
            "#,
            params![installation_id, profile_id],
        )?;
        Ok(())
    }

    pub fn active_profile(&self, installation_id: &str) -> Result<Option<Profile>, StoreError> {
        let value = self
            .connection
            .query_row(
                r#"
                SELECT profiles.profile_json
                FROM active_profiles
                JOIN profiles ON profiles.id = active_profiles.profile_id
                WHERE active_profiles.installation_id = ?1
                "#,
                [installation_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        value
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(StoreError::from)
    }

    pub fn catalog_trust_state(
        &self,
        channel: &str,
    ) -> Result<Option<CatalogTrustState>, StoreError> {
        validate_identifier("catalog channel", channel)?;
        self.connection
            .query_row(
                r#"
                SELECT root_generation, root_payload_sha256,
                       catalog_sequence, catalog_payload_sha256
                FROM catalog_trust_state
                WHERE channel = ?1
                "#,
                [channel],
                |row| {
                    Ok(CatalogTrustState {
                        root_generation: row.get(0)?,
                        root_payload_sha256: row.get(1)?,
                        catalog_sequence: row.get(2)?,
                        catalog_payload_sha256: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn advance_catalog_trust_state(
        &self,
        channel: &str,
        next: &CatalogTrustState,
    ) -> Result<(), StoreError> {
        validate_identifier("catalog channel", channel)?;
        validate_lowercase_sha256(&next.root_payload_sha256)?;
        validate_lowercase_sha256(&next.catalog_payload_sha256)?;
        if next.root_generation == 0 || next.catalog_sequence == 0 {
            return Err(StoreError::InvalidCatalogTrust(
                "catalog generations and sequences must be non-zero".to_owned(),
            ));
        }
        let changed = self.connection.execute(
            r#"
            INSERT INTO catalog_trust_state (
                channel, root_generation, root_payload_sha256,
                catalog_sequence, catalog_payload_sha256
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(channel) DO UPDATE SET
                root_generation = excluded.root_generation,
                root_payload_sha256 = excluded.root_payload_sha256,
                catalog_sequence = excluded.catalog_sequence,
                catalog_payload_sha256 = excluded.catalog_payload_sha256,
                updated_at = unixepoch()
            WHERE
                excluded.root_generation > catalog_trust_state.root_generation
                OR (
                    excluded.root_generation = catalog_trust_state.root_generation
                    AND excluded.root_payload_sha256 = catalog_trust_state.root_payload_sha256
                    AND (
                        excluded.catalog_sequence > catalog_trust_state.catalog_sequence
                        OR (
                            excluded.catalog_sequence = catalog_trust_state.catalog_sequence
                            AND excluded.catalog_payload_sha256 = catalog_trust_state.catalog_payload_sha256
                        )
                    )
                )
            "#,
            params![
                channel,
                next.root_generation,
                next.root_payload_sha256,
                next.catalog_sequence,
                next.catalog_payload_sha256,
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::CatalogTrustRollback(channel.to_owned()));
        }
        Ok(())
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        let current_version = self.schema_version()?;
        let supported = MIGRATIONS.len() as u32;
        if current_version > supported {
            return Err(StoreError::NewerSchema {
                found: current_version,
                supported,
            });
        }
        let current = current_version as usize;
        for (index, migration) in MIGRATIONS.iter().enumerate().skip(current) {
            let transaction = self.connection.transaction()?;
            transaction.execute_batch(migration)?;
            transaction.pragma_update(None, "user_version", (index + 1) as u32)?;
            transaction.commit()?;
        }
        Ok(())
    }
}

fn validate_profile(profile: &Profile) -> Result<(), StoreError> {
    if profile.schema_version != 1 {
        return Err(StoreError::InvalidProfile(format!(
            "unsupported schema version {}",
            profile.schema_version
        )));
    }
    validate_identifier("profile", &profile.id)?;
    if profile.name.trim().is_empty() || profile.name.len() > 200 {
        return Err(StoreError::InvalidProfile(
            "profile name must contain 1 to 200 bytes".to_owned(),
        ));
    }
    let mut artifacts = std::collections::BTreeSet::new();
    for package in &profile.packages {
        if package.artifact_sha256.len() != 64
            || !package
                .artifact_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(StoreError::InvalidProfile(format!(
                "invalid artifact SHA-256 '{}'",
                package.artifact_sha256
            )));
        }
        let key = (&package.artifact_sha256, &package.variant);
        if !artifacts.insert(key) {
            return Err(StoreError::InvalidProfile(format!(
                "duplicate package selection '{}'",
                package.artifact_sha256
            )));
        }
    }
    let mut pak_load_order = std::collections::BTreeSet::new();
    for preference in &profile.pak_load_order {
        if preference.build_id == 0 {
            return Err(StoreError::InvalidProfile(
                "PAK load-order build ID must be non-zero".to_owned(),
            ));
        }
        for sha256 in [
            &preference.first_pak_sha256,
            &preference.second_pak_sha256,
            &preference.winner_pak_sha256,
        ] {
            if !is_lowercase_sha256(sha256) {
                return Err(StoreError::InvalidProfile(format!(
                    "invalid PAK SHA-256 '{sha256}'"
                )));
            }
        }
        if preference.first_pak_sha256 >= preference.second_pak_sha256 {
            return Err(StoreError::InvalidProfile(
                "PAK load-order pair must be stored with first_pak_sha256 less than second_pak_sha256"
                    .to_owned(),
            ));
        }
        if preference.winner_pak_sha256 != preference.first_pak_sha256
            && preference.winner_pak_sha256 != preference.second_pak_sha256
        {
            return Err(StoreError::InvalidProfile(
                "PAK load-order winner must be one of the paired PAKs".to_owned(),
            ));
        }
        let key = (
            preference.build_id,
            &preference.first_pak_sha256,
            &preference.second_pak_sha256,
        );
        if !pak_load_order.insert(key) {
            return Err(StoreError::InvalidProfile(format!(
                "duplicate PAK load-order pair for build {}",
                preference.build_id
            )));
        }
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StoreError::InvalidProfile(format!(
            "invalid {field} identifier '{value}'"
        )));
    }
    Ok(())
}

fn validate_lowercase_sha256(value: &str) -> Result<(), StoreError> {
    if is_lowercase_sha256(value) {
        Ok(())
    } else {
        Err(StoreError::InvalidCatalogTrust(format!(
            "invalid lowercase SHA-256 '{value}'"
        )))
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rrmm_domain::{
        BuildStatus, GameInstallation, InstallationSource, LayoutStatus, PakLoadOrderPreference,
        ProfilePackageSelection,
    };

    fn inspection(build_id: u64) -> InstallationInspection {
        InstallationInspection {
            installation: GameInstallation {
                app_id: 3_552_140,
                build_id,
                state_flags: 4,
                install_dir_name: "RetroRewind".to_owned(),
                steam_root: PathBuf::from("/steam"),
                library_root: PathBuf::from("/steam"),
                manifest_path: PathBuf::from("/steam/steamapps/appmanifest_3552140.acf"),
                game_root: PathBuf::from("/steam/steamapps/common/RetroRewind"),
                source: InstallationSource::SteamLibrary,
            },
            layout_status: LayoutStatus::Complete,
            build_status: BuildStatus::SupportedUnfingerprinted,
            game_running: false,
            writable_hint: true,
            critical_files: Vec::new(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn migrates_and_upserts_installations() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.schema_version().unwrap(), 9);

        store.upsert_installation(&inspection(1)).unwrap();
        store.upsert_installation(&inspection(2)).unwrap();
        let records = store.installations().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].installation.build_id, 2);
    }

    #[test]
    fn migrates_an_existing_schema_two_database_to_three() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(MIGRATIONS[0]).unwrap();
        connection.execute_batch(MIGRATIONS[1]).unwrap();
        connection
            .pragma_update(None, "user_version", 2_u32)
            .unwrap();

        let store = Store::initialize(connection).unwrap();

        assert_eq!(store.schema_version().unwrap(), 9);
        let table: String = store
            .connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'pak_inventory_cache'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table, "pak_inventory_cache");
    }

    #[test]
    fn migrates_an_existing_schema_three_database_to_six() {
        let connection = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..3] {
            connection.execute_batch(migration).unwrap();
        }
        connection
            .pragma_update(None, "user_version", 3_u32)
            .unwrap();

        let store = Store::initialize(connection).unwrap();

        assert_eq!(store.schema_version().unwrap(), 9);
        let table: String = store
            .connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'profiles'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table, "profiles");
    }

    #[test]
    fn migrates_an_existing_schema_four_database_to_six() {
        let connection = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..4] {
            connection.execute_batch(migration).unwrap();
        }
        connection
            .pragma_update(None, "user_version", 4_u32)
            .unwrap();

        let store = Store::initialize(connection).unwrap();

        assert_eq!(store.schema_version().unwrap(), 9);
        let table: String = store
            .connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'catalog_trust_state'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table, "catalog_trust_state");
    }

    #[test]
    fn migrates_schema_five_and_keeps_installation_bindings_stable() {
        let connection = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..5] {
            connection.execute_batch(migration).unwrap();
        }
        connection
            .pragma_update(None, "user_version", 5_u32)
            .unwrap();

        let store = Store::initialize(connection).unwrap();
        assert_eq!(store.schema_version().unwrap(), 9);
        store
            .bind_installation_id(
                "retro_rewind",
                Path::new("/steam/appmanifest_3552140.acf"),
                Path::new("/steam/common/RetroRewind"),
            )
            .unwrap();
        store
            .bind_installation_id(
                "retro_rewind",
                Path::new("/steam/appmanifest_3552140.acf"),
                Path::new("/steam/common/RetroRewind"),
            )
            .unwrap();
        assert!(matches!(
            store.bind_installation_id(
                "retro_rewind",
                Path::new("/other/appmanifest_3552140.acf"),
                Path::new("/other/common/RetroRewind"),
            ),
            Err(StoreError::InstallationBindingMismatch(_))
        ));
        assert!(matches!(
            store.bind_installation_id(
                "second_id",
                Path::new("/steam/appmanifest_3552140.acf"),
                Path::new("/steam/common/RetroRewind"),
            ),
            Err(StoreError::InstallationBindingMismatch(_))
        ));
    }

    #[test]
    fn migrates_schema_six_profiles_to_seven_without_json1() {
        let connection = Connection::open_in_memory().unwrap();
        for migration in &MIGRATIONS[..6] {
            connection.execute_batch(migration).unwrap();
        }
        connection
            .execute(
                "INSERT INTO profiles (id, name, revision, profile_json) VALUES (?1, ?2, ?3, ?4)",
                params![
                    "legacy",
                    "Legacy",
                    0_u64,
                    r#"{"schema_version":1,"id":"legacy","name":"Legacy","revision":0,"packages":[]}"#
                ],
            )
            .unwrap();
        connection
            .pragma_update(None, "user_version", 6_u32)
            .unwrap();

        let store = Store::initialize(connection).unwrap();

        assert_eq!(store.schema_version().unwrap(), 9);
        assert!(
            store
                .profile("legacy")
                .unwrap()
                .unwrap()
                .pak_load_order
                .is_empty()
        );
    }

    #[test]
    fn round_trips_json_settings() {
        let store = Store::open_in_memory().unwrap();
        let value = serde_json::json!({"deepScan": true});
        store.set_setting("scan", &value).unwrap();
        assert_eq!(store.setting("scan").unwrap(), Some(value));
    }

    #[test]
    fn round_trips_artifact_manifests() {
        let store = Store::open_in_memory().unwrap();
        let sha256 = "a".repeat(64);
        let manifest = serde_json::json!({"sha256": sha256});
        store
            .upsert_artifact(&sha256, Path::new("/store/artifact"), &manifest)
            .unwrap();
        assert_eq!(store.artifact(&sha256).unwrap(), Some(manifest));
    }

    #[test]
    fn deletes_an_artifact_and_its_disabled_profile_references() {
        let mut store = Store::open_in_memory().unwrap();
        let sha256 = "a".repeat(64);
        store
            .upsert_artifact(
                &sha256,
                Path::new("/store/artifact"),
                &serde_json::json!({"sha256": sha256}),
            )
            .unwrap();
        store
            .create_profile(&Profile {
                schema_version: 1,
                id: "default".to_owned(),
                name: "Default".to_owned(),
                revision: 0,
                packages: vec![rrmm_domain::ProfilePackageSelection {
                    artifact_sha256: sha256.clone(),
                    variant: None,
                    enabled: false,
                }],
                pak_load_order: Vec::new(),
            })
            .unwrap();

        store
            .delete_artifact_and_profile_references(&sha256)
            .unwrap();

        assert!(store.artifact(&sha256).unwrap().is_none());
        let profile = store.profile("default").unwrap().unwrap();
        assert!(profile.packages.is_empty());
        assert_eq!(profile.revision, 1);
    }

    #[test]
    fn refuses_to_delete_an_artifact_enabled_in_a_profile() {
        let mut store = Store::open_in_memory().unwrap();
        let sha256 = "a".repeat(64);
        store
            .upsert_artifact(
                &sha256,
                Path::new("/store/artifact"),
                &serde_json::json!({"sha256": sha256}),
            )
            .unwrap();
        store
            .create_profile(&Profile {
                schema_version: 1,
                id: "default".to_owned(),
                name: "Default".to_owned(),
                revision: 0,
                packages: vec![rrmm_domain::ProfilePackageSelection {
                    artifact_sha256: sha256.clone(),
                    variant: None,
                    enabled: true,
                }],
                pak_load_order: Vec::new(),
            })
            .unwrap();

        assert!(matches!(
            store.delete_artifact_and_profile_references(&sha256),
            Err(StoreError::InvalidProfile(_))
        ));
        assert!(store.artifact(&sha256).unwrap().is_some());
    }

    #[test]
    fn batch_profile_update_rolls_back_every_profile_on_a_revision_conflict() {
        let mut store = Store::open_in_memory().unwrap();
        for id in ["first", "second"] {
            store
                .create_profile(&Profile {
                    schema_version: 1,
                    id: id.to_owned(),
                    name: id.to_owned(),
                    revision: 0,
                    packages: Vec::new(),
                    pak_load_order: Vec::new(),
                })
                .unwrap();
        }
        let mut first = store.profile("first").unwrap().unwrap();
        first.name = "changed".to_owned();
        let second = store.profile("second").unwrap().unwrap();

        assert!(matches!(
            store.update_profiles_batch(&[(first, 0), (second, 1)]),
            Err(StoreError::ProfileRevisionConflict { .. })
        ));
        assert_eq!(store.profile("first").unwrap().unwrap().name, "first");
        assert_eq!(store.profile("first").unwrap().unwrap().revision, 0);
    }

    #[test]
    fn replaces_artifacts_and_profile_references_in_one_transaction() {
        let mut store = Store::open_in_memory().unwrap();
        let old_sha256 = "a".repeat(64);
        let new_sha256 = "b".repeat(64);
        store
            .upsert_artifact(
                &old_sha256,
                Path::new("/store/old"),
                &serde_json::json!({"sha256": old_sha256}),
            )
            .unwrap();
        store
            .create_profile(&Profile {
                schema_version: 1,
                id: "default".to_owned(),
                name: "Default".to_owned(),
                revision: 0,
                packages: vec![ProfilePackageSelection {
                    artifact_sha256: old_sha256.clone(),
                    variant: None,
                    enabled: true,
                }],
                pak_load_order: Vec::new(),
            })
            .unwrap();
        let mut updated = store.profile("default").unwrap().unwrap();
        updated.packages[0].artifact_sha256 = new_sha256.clone();
        let new_artifact = StoredArtifact {
            sha256: new_sha256.clone(),
            root: PathBuf::from("/store/new"),
            manifest: serde_json::json!({"sha256": new_sha256}),
            accepted_at: 0,
        };

        let profiles = store
            .replace_artifacts_and_update_profiles(
                &[new_artifact],
                std::slice::from_ref(&old_sha256),
                &[(updated, 0)],
            )
            .unwrap();

        assert_eq!(profiles[0].revision, 1);
        assert_eq!(profiles[0].packages[0].artifact_sha256, new_sha256);
        assert!(store.artifact(&old_sha256).unwrap().is_none());
        assert!(store.artifact(&new_sha256).unwrap().is_some());
    }

    #[test]
    fn artifact_replacement_rolls_back_when_a_profile_still_references_the_old_hash() {
        let mut store = Store::open_in_memory().unwrap();
        let old_sha256 = "a".repeat(64);
        let new_sha256 = "b".repeat(64);
        store
            .upsert_artifact(
                &old_sha256,
                Path::new("/store/old"),
                &serde_json::json!({"sha256": old_sha256}),
            )
            .unwrap();
        store
            .create_profile(&Profile {
                schema_version: 1,
                id: "default".to_owned(),
                name: "Default".to_owned(),
                revision: 0,
                packages: vec![ProfilePackageSelection {
                    artifact_sha256: old_sha256.clone(),
                    variant: None,
                    enabled: false,
                }],
                pak_load_order: Vec::new(),
            })
            .unwrap();
        let new_artifact = StoredArtifact {
            sha256: new_sha256.clone(),
            root: PathBuf::from("/store/new"),
            manifest: serde_json::json!({"sha256": new_sha256}),
            accepted_at: 0,
        };

        assert!(matches!(
            store.replace_artifacts_and_update_profiles(
                &[new_artifact],
                std::slice::from_ref(&old_sha256),
                &[],
            ),
            Err(StoreError::InvalidProfile(_))
        ));
        assert!(store.artifact(&old_sha256).unwrap().is_some());
        assert!(store.artifact(&new_sha256).unwrap().is_none());
    }

    #[test]
    fn caches_pak_inventories_only_for_an_exact_fingerprint() {
        let store = Store::open_in_memory().unwrap();
        let fingerprint = PakCacheFingerprint {
            canonical_path: PathBuf::from("/game/base.pak"),
            build_id: 23_896_268,
            archive_bytes: 1024,
            modified_ns: 123,
            index_metadata_sha256: "a".repeat(64),
        };
        let inventory = serde_json::json!({"entries": 21_705});
        store
            .upsert_pak_inventory(&fingerprint, &inventory)
            .unwrap();
        assert_eq!(
            store
                .pak_inventory::<serde_json::Value>(&fingerprint)
                .unwrap(),
            Some(inventory)
        );

        for stale in [
            PakCacheFingerprint {
                build_id: fingerprint.build_id + 1,
                ..fingerprint.clone()
            },
            PakCacheFingerprint {
                archive_bytes: fingerprint.archive_bytes + 1,
                ..fingerprint.clone()
            },
            PakCacheFingerprint {
                modified_ns: fingerprint.modified_ns + 1,
                ..fingerprint.clone()
            },
            PakCacheFingerprint {
                index_metadata_sha256: "b".repeat(64),
                ..fingerprint.clone()
            },
        ] {
            assert!(
                store
                    .pak_inventory::<serde_json::Value>(&stale)
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn removes_a_corrupt_pak_inventory_cache_entry() {
        let store = Store::open_in_memory().unwrap();
        let fingerprint = PakCacheFingerprint {
            canonical_path: PathBuf::from("/game/base.pak"),
            build_id: 23_896_268,
            archive_bytes: 1024,
            modified_ns: 123,
            index_metadata_sha256: "a".repeat(64),
        };
        store
            .upsert_pak_inventory(&fingerprint, &serde_json::json!({"valid": true}))
            .unwrap();
        store
            .connection
            .execute(
                "UPDATE pak_inventory_cache SET inventory_json = 'not json'",
                [],
            )
            .unwrap();

        assert!(
            store
                .pak_inventory::<serde_json::Value>(&fingerprint)
                .unwrap()
                .is_none()
        );
        let rows: u32 = store
            .connection
            .query_row("SELECT COUNT(*) FROM pak_inventory_cache", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
    }

    #[test]
    fn reuses_file_verification_only_for_the_exact_identity() {
        let store = Store::open_in_memory().unwrap();
        let fingerprint = FileVerificationFingerprint {
            canonical_path: PathBuf::from("/store/mod.pak"),
            device_id: "8".to_owned(),
            file_id: "42".to_owned(),
            bytes: 1024,
            modified_ns: 100,
            changed_ns: 200,
            sha256: "a".repeat(64),
        };
        store.upsert_file_verification(&fingerprint).unwrap();
        assert!(store.file_is_verified(&fingerprint).unwrap());
        assert_eq!(
            store.verified_file_sha256(&fingerprint).unwrap(),
            Some(fingerprint.sha256.clone())
        );
        for stale in [
            FileVerificationFingerprint {
                file_id: "43".to_owned(),
                ..fingerprint.clone()
            },
            FileVerificationFingerprint {
                bytes: 1025,
                ..fingerprint.clone()
            },
            FileVerificationFingerprint {
                modified_ns: 101,
                ..fingerprint.clone()
            },
            FileVerificationFingerprint {
                changed_ns: 201,
                ..fingerprint.clone()
            },
        ] {
            assert!(!store.file_is_verified(&stale).unwrap());
        }
    }

    #[test]
    fn caches_activation_pak_analysis_and_drops_corrupt_rows() {
        let store = Store::open_in_memory().unwrap();
        let analysis = serde_json::json!({"conflicts": 2});
        store
            .upsert_activation_pak_analysis("key", &analysis)
            .unwrap();
        assert_eq!(
            store
                .activation_pak_analysis::<serde_json::Value>("key")
                .unwrap(),
            Some(analysis)
        );
        store
            .connection
            .execute(
                "UPDATE activation_pak_analysis_cache SET analysis_json = 'invalid'",
                [],
            )
            .unwrap();
        assert!(
            store
                .activation_pak_analysis::<serde_json::Value>("key")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn creates_clones_updates_activates_and_deletes_profiles() {
        let store = Store::open_in_memory().unwrap();
        let profile = Profile {
            schema_version: 1,
            id: "default".to_owned(),
            name: "Default".to_owned(),
            revision: 0,
            packages: vec![rrmm_domain::ProfilePackageSelection {
                artifact_sha256: "a".repeat(64),
                variant: None,
                enabled: true,
            }],
            pak_load_order: vec![PakLoadOrderPreference {
                build_id: 23_896_268,
                first_pak_sha256: "a".repeat(64),
                second_pak_sha256: "b".repeat(64),
                winner_pak_sha256: "b".repeat(64),
            }],
        };
        store.create_profile(&profile).unwrap();
        assert_eq!(store.profile("default").unwrap(), Some(profile.clone()));
        let clone = store
            .clone_profile("default", "testing", "Testing")
            .unwrap();
        assert_eq!(clone.packages, profile.packages);
        assert_eq!(clone.pak_load_order, profile.pak_load_order);
        assert_eq!(store.profiles().unwrap().len(), 2);

        let mut edited = clone.clone();
        edited.name = "Testing Edited".to_owned();
        let edited = store.update_profile(&edited, 0).unwrap();
        assert_eq!(edited.revision, 1);
        assert!(matches!(
            store.update_profile(&edited, 0),
            Err(StoreError::ProfileRevisionConflict { .. })
        ));

        store.set_active_profile("retro_rewind", "testing").unwrap();
        assert_eq!(store.active_profile("retro_rewind").unwrap(), Some(edited));
        assert!(store.delete_profile("testing").is_err());
        store.delete_profile("default").unwrap();
        assert_eq!(store.profiles().unwrap().len(), 1);
    }

    #[test]
    fn validates_pak_load_order_preferences() {
        let valid = Profile {
            schema_version: 1,
            id: "default".to_owned(),
            name: "Default".to_owned(),
            revision: 0,
            packages: Vec::new(),
            pak_load_order: vec![PakLoadOrderPreference {
                build_id: 23_896_268,
                first_pak_sha256: "a".repeat(64),
                second_pak_sha256: "b".repeat(64),
                winner_pak_sha256: "b".repeat(64),
            }],
        };
        assert!(validate_profile(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.pak_load_order[0].build_id = 0;
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));

        let mut invalid = valid.clone();
        invalid.pak_load_order[0].first_pak_sha256 = "A".repeat(64);
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));

        let mut invalid = valid.clone();
        invalid.pak_load_order[0].second_pak_sha256 = "short".to_owned();
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));

        let mut invalid = valid.clone();
        invalid.pak_load_order[0].winner_pak_sha256 = "g".repeat(64);
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));

        let mut invalid = valid.clone();
        invalid.pak_load_order[0].first_pak_sha256 = "c".repeat(64);
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));

        let mut invalid = valid.clone();
        invalid.pak_load_order[0].winner_pak_sha256 = "c".repeat(64);
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));

        let mut invalid = valid;
        invalid
            .pak_load_order
            .push(invalid.pak_load_order[0].clone());
        assert!(matches!(
            validate_profile(&invalid),
            Err(StoreError::InvalidProfile(_))
        ));
    }

    #[test]
    fn rejects_a_database_created_by_a_newer_binary() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .pragma_update(None, "user_version", 10_u32)
            .unwrap();

        let result = Store::initialize(connection);

        assert!(matches!(
            result,
            Err(StoreError::NewerSchema {
                found: 10,
                supported: 9
            })
        ));
    }

    #[test]
    fn advances_catalog_trust_without_allowing_rollback_or_same_version_substitution() {
        let store = Store::open_in_memory().unwrap();
        let first = CatalogTrustState {
            root_generation: 1,
            root_payload_sha256: "a".repeat(64),
            catalog_sequence: 1,
            catalog_payload_sha256: "b".repeat(64),
        };
        store.advance_catalog_trust_state("stable", &first).unwrap();
        store.advance_catalog_trust_state("stable", &first).unwrap();
        assert_eq!(
            store.catalog_trust_state("stable").unwrap(),
            Some(first.clone())
        );

        let second = CatalogTrustState {
            catalog_sequence: 2,
            catalog_payload_sha256: "c".repeat(64),
            ..first.clone()
        };
        store
            .advance_catalog_trust_state("stable", &second)
            .unwrap();
        assert!(matches!(
            store.advance_catalog_trust_state("stable", &first),
            Err(StoreError::CatalogTrustRollback(_))
        ));
        let substituted = CatalogTrustState {
            catalog_payload_sha256: "d".repeat(64),
            ..second.clone()
        };
        assert!(matches!(
            store.advance_catalog_trust_state("stable", &substituted),
            Err(StoreError::CatalogTrustRollback(_))
        ));
        let next_root_epoch = CatalogTrustState {
            root_generation: 2,
            root_payload_sha256: "e".repeat(64),
            catalog_sequence: 1,
            catalog_payload_sha256: "f".repeat(64),
        };
        store
            .advance_catalog_trust_state("stable", &next_root_epoch)
            .unwrap();
        assert!(matches!(
            store.advance_catalog_trust_state("stable", &second),
            Err(StoreError::CatalogTrustRollback(_))
        ));
        let substituted_next_root = CatalogTrustState {
            catalog_payload_sha256: "0".repeat(64),
            ..next_root_epoch.clone()
        };
        assert!(matches!(
            store.advance_catalog_trust_state("stable", &substituted_next_root),
            Err(StoreError::CatalogTrustRollback(_))
        ));
        assert_eq!(
            store.catalog_trust_state("stable").unwrap(),
            Some(next_root_epoch)
        );
    }
}
