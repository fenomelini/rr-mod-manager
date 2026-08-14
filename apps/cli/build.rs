use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedRootKey {
    key_id: String,
    public_key: String,
}

fn main() {
    let path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("../../trust/production-roots.json");
    println!("cargo:rerun-if-changed={}", path.display());
    let input = fs::read(&path).expect("failed to read trust/production-roots.json");
    let roots: Vec<TrustedRootKey> =
        serde_json::from_slice(&input).expect("invalid production root JSON");
    let mut ids = BTreeSet::new();
    for root in &roots {
        let decoded = STANDARD
            .decode(&root.public_key)
            .expect("production root public key is not base64");
        let bytes: [u8; 32] = decoded
            .try_into()
            .expect("production root public key has invalid length");
        VerifyingKey::from_bytes(&bytes).expect("production root public key is invalid Ed25519");
        let expected_id = format!("ed25519-{:x}", Sha256::digest(bytes));
        assert_eq!(
            root.key_id, expected_id,
            "production root key ID does not match its public key"
        );
        assert!(ids.insert(&root.key_id), "duplicate production root key ID");
    }
    if env::var("PROFILE").as_deref() == Ok("release") {
        assert!(
            !roots.is_empty(),
            "release builds require at least one embedded production root"
        );
    }
}
