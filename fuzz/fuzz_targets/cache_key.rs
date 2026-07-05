#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpxd::fuzz_support::derive_cache_key(data);
});
