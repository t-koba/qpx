#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpxd::fuzz_support::observe_grpc_web_binary_frames(data);
});
