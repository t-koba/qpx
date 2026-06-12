#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_yaml::from_slice::<qpx_core::config::StreamingRequirement>(data);
    let _ = serde_yaml::from_slice::<qpx_core::config::RuntimeConfig>(data);
});
