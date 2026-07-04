#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpxd::fuzz_support::parse_h3_content_length_state(data);
});
