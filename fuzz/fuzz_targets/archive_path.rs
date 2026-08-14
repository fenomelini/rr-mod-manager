#![no_main]

use libfuzzer_sys::fuzz_target;
use rrmm_archive::validate_entry_path;

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };

    let _ = validate_entry_path(path, false, 32);
    let _ = validate_entry_path(path, true, 32);
});
