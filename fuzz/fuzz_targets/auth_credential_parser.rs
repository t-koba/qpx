#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpx_auth::fuzz_support::parse_auth_credential(data);
});
