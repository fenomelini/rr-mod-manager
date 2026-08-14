#![no_main]

use libfuzzer_sys::fuzz_target;
use rrmm_pak::{PakLimits, inspect_pak};
use std::fs;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    const MAX_INPUT_BYTES: usize = 64 * 1024;
    if data.len() > MAX_INPUT_BYTES {
        return;
    }

    let bytes = match data.first().map(|byte| byte % 3) {
        Some(1) => generated_pak(&data[1..]),
        Some(2) => {
            let mut bytes = generated_pak(data.get(3..).unwrap_or_default());
            if !bytes.is_empty() {
                let selector = data.get(1).copied().unwrap_or_default() as usize
                    | ((data.get(2).copied().unwrap_or_default() as usize) << 8);
                let offset = selector % bytes.len();
                bytes[offset] ^= data.get(3).copied().unwrap_or(0xff);
            }
            bytes
        }
        _ => data.to_vec(),
    };
    let Ok(temporary) = tempfile::tempdir() else {
        return;
    };
    let pak = temporary.path().join("input.pak");
    if fs::write(&pak, bytes).is_err() {
        return;
    }
    let limits = PakLimits {
        max_archive_bytes: (MAX_INPUT_BYTES * 2) as u64,
        max_index_bytes: MAX_INPUT_BYTES as u64,
        max_entries: 1024,
        max_member_bytes: MAX_INPUT_BYTES as u64,
    };

    let _ = inspect_pak(&pak, &limits);
});

fn generated_pak(payload: &[u8]) -> Vec<u8> {
    let mut writer = repak_trumank::PakBuilder::new().writer(
        Cursor::new(Vec::new()),
        repak_trumank::Version::V11,
        "../../../".to_owned(),
        Some(0x6493_4de7),
    );
    if writer
        .write_file("RetroRewind/Content/Fuzz.uasset", false, payload)
        .is_err()
    {
        return Vec::new();
    }
    writer
        .write_index()
        .map(|cursor| cursor.into_inner())
        .unwrap_or_default()
}
