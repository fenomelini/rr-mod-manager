use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use rrmm_recipes::{
    AuthenticatedRootMetadata, CatalogTrustFloor, DelegatedOnlineKey, DetachedSignature,
    RecipeCatalog, RootMetadata, SignatureAlgorithm, SignedRecipeCatalog, SignedRootMetadata,
    TrustedRootKey, authenticate_historical_recipe_catalog_for_authoring,
    authenticate_historical_root_metadata_for_authoring, catalog_signing_payload, load_recipe,
    root_signing_payload, validate_recipe_catalog, validate_root_metadata, verify_signed_catalog,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(
    name = "rrmm-catalog-author",
    version,
    about = "Offline bootstrap authoring for RRMM signed recipe catalogs"
)]
struct Arguments {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate one Ed25519 key pair without printing private material.
    KeyGenerate {
        #[arg(long)]
        role: KeyRole,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Create unsigned generation-1 root metadata for one online key.
    RootBootstrap {
        #[arg(long)]
        online_public_key: PathBuf,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        valid_until: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign root metadata with an offline root key.
    RootSign {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Validate public root records and export the deterministic runtime trust-anchor array.
    TrustedRootsExport {
        #[arg(long, required = true)]
        trusted_root: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Authenticate previous root metadata, rotate the online key, and sign generation + 1.
    RootUpdate {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        trusted_root: PathBuf,
        #[arg(long)]
        floor: PathBuf,
        #[arg(long)]
        previous_root_metadata: PathBuf,
        #[arg(long)]
        online_public_key: PathBuf,
        #[arg(long)]
        valid_from: u64,
        #[arg(long)]
        valid_until: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Create an unsigned sequence-1 catalog from reviewed recipe files.
    CatalogBootstrap {
        #[arg(long, required = true)]
        recipe: Vec<PathBuf>,
        #[arg(long)]
        issued_at: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign and immediately verify a catalog with a delegated online key.
    CatalogSign {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        trusted_root: PathBuf,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Authenticate the predecessor and derive the next sequence in the current root epoch.
    CatalogUpdate {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        trusted_root: PathBuf,
        #[arg(long)]
        floor: PathBuf,
        #[arg(long)]
        previous_root_metadata: PathBuf,
        #[arg(long)]
        previous_catalog: Option<PathBuf>,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long, required = true)]
        recipe: Vec<PathBuf>,
        #[arg(long)]
        issued_at: u64,
        #[arg(long)]
        expires_at: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify signed metadata without mutating SQLite or other trust state.
    Verify {
        #[arg(long)]
        trusted_root: PathBuf,
        #[arg(long)]
        root_metadata: PathBuf,
        #[arg(long)]
        recipe_catalog: PathBuf,
        #[arg(long)]
        floor: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum KeyRole {
    Root,
    Online,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateKeyEnvelope {
    schema_version: u32,
    role: KeyRole,
    algorithm: SignatureAlgorithm,
    key_id: String,
    private_key: String,
}

fn main() -> Result<()> {
    match Arguments::parse().command {
        Command::KeyGenerate {
            role,
            private_key,
            public_key,
        } => generate_key(role, &private_key, &public_key),
        Command::RootBootstrap {
            online_public_key,
            valid_from,
            valid_until,
            expires_at,
            output,
        } => {
            let online: TrustedRootKey = read_json(&online_public_key)?;
            validate_public_key_record(&online)?;
            let now = system_unix_time()?;
            if valid_from > now || valid_until < now || expires_at < valid_until {
                bail!("online validity must contain the current time and fit within root expiry");
            }
            let metadata = RootMetadata {
                schema_version: 1,
                generation: 1,
                expires_at,
                online_keys: vec![DelegatedOnlineKey {
                    key_id: online.key_id,
                    public_key: online.public_key,
                    valid_from,
                    valid_until,
                }],
                revoked_online_key_ids: Vec::new(),
            };
            validate_root_metadata(&metadata)?;
            write_json_new(&output, &metadata, false)
        }
        Command::RootSign {
            private_key,
            metadata,
            output,
        } => {
            let key = read_private_key(&private_key, KeyRole::Root)?;
            let metadata: RootMetadata = read_json(&metadata)?;
            if metadata.generation != 1 || metadata.online_keys.len() != 1 {
                bail!("root-sign accepts only generation-1 bootstrap metadata");
            }
            if metadata.expires_at < system_unix_time()? {
                bail!("root metadata is already expired");
            }
            let signed = sign_root_metadata(&key.private_key, &key.key_id, metadata)?;
            write_json_new(&output, &signed, false)
        }
        Command::TrustedRootsExport {
            trusted_root,
            output,
        } => {
            let mut roots = trusted_root
                .iter()
                .map(|path| read_json(path))
                .collect::<Result<Vec<TrustedRootKey>>>()?;
            for root in &roots {
                validate_public_key_record(root)?;
            }
            roots.sort_by(|left, right| left.key_id.cmp(&right.key_id));
            if roots
                .windows(2)
                .any(|pair| pair[0].key_id == pair[1].key_id)
            {
                bail!("trusted root key IDs must be unique");
            }
            write_json_new(&output, &roots, false)
        }
        Command::RootUpdate {
            private_key,
            trusted_root,
            floor,
            previous_root_metadata,
            online_public_key,
            valid_from,
            valid_until,
            expires_at,
            output,
        } => {
            let key = read_private_key(&private_key, KeyRole::Root)?;
            let trusted: TrustedRootKey = read_json(&trusted_root)?;
            ensure_private_matches_public(&key, &trusted, "root")?;
            let previous: SignedRootMetadata = read_json(&previous_root_metadata)?;
            let authenticated = authenticate_historical_root_metadata_for_authoring(
                std::slice::from_ref(&trusted),
                &previous,
            )?;
            let expected_floor: CatalogTrustFloor = read_json(&floor)?;
            if expected_floor.root_generation != authenticated.generation
                || expected_floor.root_payload_sha256.as_deref()
                    != Some(&authenticated.payload_sha256)
            {
                bail!("previous root metadata does not match the reviewed trust floor");
            }
            let generation = authenticated
                .generation
                .checked_add(1)
                .context("root generation overflow")?;
            let online: TrustedRootKey = read_json(&online_public_key)?;
            validate_public_key_record(&online)?;
            let mut revoked: std::collections::BTreeSet<_> = previous
                .signed
                .revoked_online_key_ids
                .iter()
                .cloned()
                .collect();
            revoked.extend(
                previous
                    .signed
                    .online_keys
                    .iter()
                    .map(|key| key.key_id.clone()),
            );
            if revoked.contains(&online.key_id) {
                bail!("root-update cannot reuse a current or historically revoked online key");
            }
            let now = system_unix_time()?;
            if valid_from > now || valid_until < now || expires_at < valid_until {
                bail!("online validity must contain the current time and fit within root expiry");
            }
            let metadata = RootMetadata {
                schema_version: 1,
                generation,
                expires_at,
                online_keys: vec![DelegatedOnlineKey {
                    key_id: online.key_id,
                    public_key: online.public_key,
                    valid_from,
                    valid_until,
                }],
                revoked_online_key_ids: revoked.into_iter().collect(),
            };
            let signed = sign_root_metadata(&key.private_key, &key.key_id, metadata)?;
            let next = authenticate_historical_root_metadata_for_authoring(
                std::slice::from_ref(&trusted),
                &signed,
            )?;
            if next.generation != generation {
                bail!("signed root generation changed unexpectedly");
            }
            write_json_new(&output, &signed, false)
        }
        Command::CatalogBootstrap {
            recipe,
            issued_at,
            expires_at,
            output,
        } => {
            let now = system_unix_time()?;
            if issued_at > now || expires_at < now {
                bail!("catalog validity must contain the current system time");
            }
            let catalog = RecipeCatalog {
                schema_version: 1,
                sequence: 1,
                issued_at,
                expires_at,
                recipes: load_reviewed_recipes(&recipe)?,
            };
            validate_recipe_catalog(&catalog)?;
            write_json_new(&output, &catalog, false)
        }
        Command::CatalogSign {
            private_key,
            trusted_root,
            root_metadata,
            catalog,
            output,
        } => {
            let key = read_private_key(&private_key, KeyRole::Online)?;
            let trusted_root: TrustedRootKey = read_json(&trusted_root)?;
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let catalog: RecipeCatalog = read_json(&catalog)?;
            if root.signed.generation != 1 || catalog.sequence != 1 {
                bail!("catalog-sign accepts only generation-1 and sequence-1 bootstrap metadata");
            }
            let delegated = root
                .signed
                .online_keys
                .iter()
                .find(|delegated| delegated.key_id == key.key_id)
                .context("online signing key is not delegated by root metadata")?;
            if delegated.public_key != ed25519_public_key(&key.private_key) {
                bail!("delegated online public key does not match the private key");
            }
            if catalog.issued_at < delegated.valid_from
                || catalog.expires_at > delegated.valid_until
                || catalog.expires_at > root.signed.expires_at
            {
                bail!("catalog validity is not contained by root and online-key validity");
            }
            let signed = sign_recipe_catalog(&key.private_key, &key.key_id, catalog)?;
            verify_signed_catalog(&[trusted_root], &root, &signed, &empty_floor())?;
            write_json_new(&output, &signed, false)
        }
        Command::CatalogUpdate {
            private_key,
            trusted_root,
            floor,
            previous_root_metadata,
            previous_catalog,
            root_metadata,
            recipe,
            issued_at,
            expires_at,
            output,
        } => {
            let key = read_private_key(&private_key, KeyRole::Online)?;
            let trusted: TrustedRootKey = read_json(&trusted_root)?;
            let previous_root: SignedRootMetadata = read_json(&previous_root_metadata)?;
            let previous_root_auth = authenticate_historical_root_metadata_for_authoring(
                std::slice::from_ref(&trusted),
                &previous_root,
            )?;
            let expected_floor: CatalogTrustFloor = read_json(&floor)?;
            if expected_floor.root_generation != previous_root_auth.generation
                || expected_floor.root_payload_sha256.as_deref()
                    != Some(&previous_root_auth.payload_sha256)
            {
                bail!("previous root metadata does not match the reviewed trust floor");
            }
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let current_root = authenticate_historical_root_metadata_for_authoring(
                std::slice::from_ref(&trusted),
                &root,
            )?;
            let root_advanced = validate_root_successor(&expected_floor, &current_root)?;
            match previous_catalog {
                Some(path) => {
                    let previous_catalog: SignedRecipeCatalog = read_json(&path)?;
                    let authenticated = authenticate_historical_recipe_catalog_for_authoring(
                        std::slice::from_ref(&trusted),
                        &previous_root,
                        &previous_catalog,
                    )?;
                    if authenticated != expected_floor {
                        bail!("previous catalog does not match the reviewed trust floor");
                    }
                }
                None if !root_advanced => {
                    bail!("catalog update in the same root epoch requires --previous-catalog");
                }
                None => {}
            }
            let delegated = root
                .signed
                .online_keys
                .iter()
                .find(|delegated| delegated.key_id == key.key_id)
                .context("online signing key is not delegated by current root metadata")?;
            ensure_private_matches_delegation(&key, delegated)?;
            let now = system_unix_time()?;
            if issued_at > now || expires_at < now {
                bail!("catalog validity must contain the current system time");
            }
            if issued_at < delegated.valid_from
                || expires_at > delegated.valid_until
                || expires_at > root.signed.expires_at
            {
                bail!("catalog validity is not contained by root and online-key validity");
            }
            let sequence = if root_advanced {
                1
            } else {
                expected_floor
                    .catalog_sequence
                    .checked_add(1)
                    .context("catalog sequence overflow")?
            };
            let catalog = RecipeCatalog {
                schema_version: 1,
                sequence,
                issued_at,
                expires_at,
                recipes: load_reviewed_recipes(&recipe)?,
            };
            let signed = sign_recipe_catalog(&key.private_key, &key.key_id, catalog)?;
            let verified = verify_signed_catalog(
                std::slice::from_ref(&trusted),
                &root,
                &signed,
                &expected_floor,
            )?;
            if verified.trust_floor().catalog_sequence != sequence {
                bail!("signed catalog sequence changed unexpectedly");
            }
            write_json_new(&output, &signed, false)
        }
        Command::Verify {
            trusted_root,
            root_metadata,
            recipe_catalog,
            floor,
        } => {
            let trusted_root: TrustedRootKey = read_json(&trusted_root)?;
            let root: SignedRootMetadata = read_json(&root_metadata)?;
            let catalog: SignedRecipeCatalog = read_json(&recipe_catalog)?;
            let floor = match floor {
                Some(path) => read_json(&path)?,
                None => empty_floor(),
            };
            let verified = verify_signed_catalog(&[trusted_root], &root, &catalog, &floor)?;
            println!("{}", serde_json::to_string_pretty(&verified.trust_floor())?);
            Ok(())
        }
    }
}

struct LoadedPrivateKey {
    key_id: String,
    private_key: Zeroizing<[u8; 32]>,
}

fn load_reviewed_recipes(paths: &[PathBuf]) -> Result<Vec<rrmm_recipes::CompatibilityRecipe>> {
    let mut recipes = paths
        .iter()
        .map(|path| load_recipe(path))
        .collect::<Result<Vec<_>, _>>()?;
    recipes.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(recipes)
}

fn ensure_private_matches_public(
    private: &LoadedPrivateKey,
    public: &TrustedRootKey,
    role: &str,
) -> Result<()> {
    if private.key_id != public.key_id
        || ed25519_public_key(&private.private_key) != public.public_key
    {
        bail!("{role} private key does not match the trusted public key");
    }
    Ok(())
}

fn ensure_private_matches_delegation(
    private: &LoadedPrivateKey,
    delegated: &DelegatedOnlineKey,
) -> Result<()> {
    if private.key_id != delegated.key_id
        || ed25519_public_key(&private.private_key) != delegated.public_key
    {
        bail!("online private key does not match the current root delegation");
    }
    Ok(())
}

fn validate_root_successor(
    previous: &CatalogTrustFloor,
    current: &AuthenticatedRootMetadata,
) -> Result<bool> {
    if current.generation == previous.root_generation {
        if previous.root_payload_sha256.as_deref() != Some(&current.payload_sha256) {
            bail!("current root replaces metadata at an accepted generation");
        }
        return Ok(false);
    }
    let expected = previous
        .root_generation
        .checked_add(1)
        .context("root generation overflow")?;
    if current.generation != expected {
        bail!("current root generation must equal the previous generation or generation + 1");
    }
    Ok(true)
}

fn ed25519_public_key(private_key: &[u8; 32]) -> String {
    let signing_key = SigningKey::from_bytes(private_key);
    STANDARD.encode(signing_key.verifying_key().as_bytes())
}

fn ed25519_key_id(private_key: &[u8; 32]) -> String {
    let signing_key = SigningKey::from_bytes(private_key);
    format!(
        "ed25519-{:x}",
        Sha256::digest(signing_key.verifying_key().as_bytes())
    )
}

fn validate_public_key_record(key: &TrustedRootKey) -> Result<()> {
    let decoded = STANDARD
        .decode(&key.public_key)
        .context("public key is not valid base64")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key has an invalid length"))?;
    VerifyingKey::from_bytes(&bytes).context("public key is not valid Ed25519")?;
    let expected_id = format!("ed25519-{:x}", Sha256::digest(bytes));
    if key.key_id != expected_id {
        bail!("public key ID does not match SHA-256 of its Ed25519 key");
    }
    Ok(())
}

fn sign_root_metadata(
    private_key: &[u8; 32],
    key_id: &str,
    metadata: RootMetadata,
) -> Result<SignedRootMetadata> {
    if key_id != ed25519_key_id(private_key) {
        bail!("root key ID does not match its derived public key");
    }
    let signing_key = SigningKey::from_bytes(private_key);
    let payload = root_signing_payload(&metadata)?;
    Ok(SignedRootMetadata {
        signed: metadata,
        signatures: vec![DetachedSignature {
            key_id: key_id.to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            signature: STANDARD.encode(signing_key.sign(&payload).to_bytes()),
        }],
    })
}

fn sign_recipe_catalog(
    private_key: &[u8; 32],
    key_id: &str,
    catalog: RecipeCatalog,
) -> Result<SignedRecipeCatalog> {
    if key_id != ed25519_key_id(private_key) {
        bail!("online key ID does not match its derived public key");
    }
    let signing_key = SigningKey::from_bytes(private_key);
    let payload = catalog_signing_payload(&catalog)?;
    Ok(SignedRecipeCatalog {
        signed: catalog,
        signatures: vec![DetachedSignature {
            key_id: key_id.to_owned(),
            algorithm: SignatureAlgorithm::Ed25519,
            signature: STANDARD.encode(signing_key.sign(&payload).to_bytes()),
        }],
    })
}

fn generate_key(role: KeyRole, private_path: &Path, public_path: &Path) -> Result<()> {
    validate_private_path(private_path)?;
    if private_path == public_path {
        bail!("private and public key paths must differ");
    }
    ensure_absent(private_path)?;
    ensure_absent(public_path)?;
    let mut private_key = [0_u8; 32];
    OsRng.fill_bytes(&mut private_key);
    let key_id = ed25519_key_id(&private_key);
    let mut private = PrivateKeyEnvelope {
        schema_version: 1,
        role,
        algorithm: SignatureAlgorithm::Ed25519,
        key_id: key_id.clone(),
        private_key: STANDARD.encode(private_key),
    };
    let public = TrustedRootKey {
        key_id: key_id.clone(),
        public_key: ed25519_public_key(&private_key),
    };
    write_json_new(public_path, &public, false)?;
    let private_write = write_json_new(private_path, &private, true);
    private.private_key.zeroize();
    private_key.zeroize();
    private_write?;
    println!("{}", serde_json::to_string_pretty(&public)?);
    Ok(())
}

fn read_private_key(path: &Path, expected_role: KeyRole) -> Result<LoadedPrivateKey> {
    validate_private_path(path)?;
    let mut file = open_private_key(path)?;
    let mut input = Zeroizing::new(Vec::new());
    file.read_to_end(&mut input)
        .with_context(|| format!("failed to read private key {}", path.display()))?;
    let mut envelope: PrivateKeyEnvelope = serde_json::from_slice(&input)
        .with_context(|| format!("invalid private-key JSON at {}", path.display()))?;
    let valid_header = envelope.schema_version == 1
        && envelope.role == expected_role
        && envelope.algorithm == SignatureAlgorithm::Ed25519;
    let decoded = STANDARD.decode(&envelope.private_key).map(Zeroizing::new);
    envelope.private_key.zeroize();
    if !valid_header {
        bail!("private key role, algorithm, or schema does not match the command");
    }
    let decoded = decoded.context("private key payload is not valid base64")?;
    if decoded.len() != 32 {
        bail!("private key payload has an invalid length");
    }
    let mut private_key = Zeroizing::new([0_u8; 32]);
    private_key.copy_from_slice(&decoded);
    let expected_id = ed25519_key_id(&private_key);
    if envelope.key_id != expected_id {
        bail!("private key ID does not match its derived public key");
    }
    Ok(LoadedPrivateKey {
        key_id: envelope.key_id,
        private_key,
    })
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let input = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&input).with_context(|| format!("invalid JSON at {}", path.display()))
}

fn write_json_new<T: Serialize>(path: &Path, value: &T, private: bool) -> Result<()> {
    ensure_absent(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect output directory {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "output parent must be a real directory: {}",
            parent.display()
        );
    }
    if private && !cfg!(unix) {
        bail!("secure private-key creation is currently supported only on Unix");
    }
    if private {
        secure_private_parent(path)?;
    }
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary output in {}", parent.display()))?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(if private {
            0o600
        } else {
            0o644
        }))
        .with_context(|| format!("failed to set permissions for {}", path.display()))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)
        .with_context(|| format!("failed to serialize {}", path.display()))?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    sync_parent(parent)?;
    Ok(())
}

fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("refusing to replace existing path {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn validate_private_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("private key path must be absolute");
    }
    if !path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".rrmm-private.json"))
    {
        bail!("private key filename must end with .rrmm-private.json");
    }
    let parent = secure_private_parent(path)?;
    let candidate = parent.join(
        path.file_name()
            .context("private key path has no filename")?,
    );
    for ancestor in candidate.ancestors() {
        let rrmm_checkout = ancestor.join("Cargo.toml").is_file()
            && ancestor.join("apps/catalog-author/Cargo.toml").is_file()
            && ancestor.join("crates/rrmm-recipes/Cargo.toml").is_file();
        let version_controlled = [".git", ".hg", ".svn"]
            .iter()
            .any(|name| fs::symlink_metadata(ancestor.join(name)).is_ok());
        if rrmm_checkout || version_controlled {
            bail!("private key path must be outside source and version-controlled directories");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_path(_path: &Path) -> Result<()> {
    bail!("secure private-key handling is currently supported only on Unix")
}

#[cfg(unix)]
fn secure_private_parent(path: &Path) -> Result<PathBuf> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("private key path has no parent directory")?;
    let canonical = fs::canonicalize(parent).with_context(|| {
        format!(
            "failed to resolve private-key directory {}",
            parent.display()
        )
    })?;
    if canonical != parent {
        bail!("private-key path must not traverse symlinks or non-canonical components");
    }
    let metadata = fs::symlink_metadata(&canonical).with_context(|| {
        format!(
            "failed to inspect private-key directory {}",
            canonical.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("private-key parent must be a real directory");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("private-key directory must be accessible only by its owner");
    }
    // SAFETY: geteuid has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!("private-key directory must be owned by the current user");
    }
    Ok(canonical)
}

#[cfg(not(unix))]
fn secure_private_parent(_path: &Path) -> Result<PathBuf> {
    bail!("secure private-key handling is currently supported only on Unix")
}

#[cfg(unix)]
fn open_private_key(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("failed to open private key {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect private key {}", path.display()))?;
    if !metadata.is_file() {
        bail!("private key must be a regular file");
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        bail!("private key must not be accessible by group or other users");
    }
    // SAFETY: geteuid has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!("private key must be owned by the current user");
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_key(_path: &Path) -> Result<File> {
    bail!("secure private-key handling is currently supported only on Unix")
}

fn sync_parent(_parent: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(_parent)?.sync_all()?;
    Ok(())
}

fn system_unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

fn empty_floor() -> CatalogTrustFloor {
    CatalogTrustFloor {
        root_generation: 0,
        root_payload_sha256: None,
        catalog_sequence: 0,
        catalog_payload_sha256: None,
    }
}
