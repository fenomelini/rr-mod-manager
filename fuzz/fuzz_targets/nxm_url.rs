#![no_main]

use libfuzzer_sys::fuzz_target;
use rrmm_nexus::parse_nxm_url;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = parse_nxm_url(input);
    }
});
