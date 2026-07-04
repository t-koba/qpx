#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpxd::fuzz_support::sanitize_h3_trailers(data);
});
