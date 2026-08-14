#![no_main]

use libfuzzer_sys::fuzz_target;
use rrmm_archive::{ArchiveLimits, preflight_archive};
use std::fs;

fuzz_target!(|data: &[u8]| {
    const MAX_INPUT_BYTES: usize = 1024 * 1024;
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut bytes = Vec::with_capacity(data.len() + 6);
    match data.first().map(|byte| byte % 3) {
        Some(0) => bytes.extend_from_slice(b"PK\x03\x04"),
        Some(1) => bytes.extend_from_slice(&[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]),
        _ => {}
    }
    bytes.extend_from_slice(data);

    let Ok(temporary) = tempfile::tempdir() else {
        return;
    };
    let archive = temporary.path().join("input.archive");
    if fs::write(&archive, bytes).is_err() {
        return;
    }
    let limits = ArchiveLimits {
        max_archive_bytes: (MAX_INPUT_BYTES + 6) as u64,
        max_expanded_bytes: 4 * 1024 * 1024,
        max_file_bytes: 2 * 1024 * 1024,
        max_entries: 1024,
        max_depth: 32,
        max_compression_ratio: 100,
    };

    let _ = preflight_archive(&archive, &limits);
});
