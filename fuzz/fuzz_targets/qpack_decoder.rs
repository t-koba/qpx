#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    qpx_h3::fuzz_support::decode_qpack(data);
});
