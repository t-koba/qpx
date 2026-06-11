#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpxd::fuzz_support::parse_ipc_meta_frame(data);
});
