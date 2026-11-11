#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let _ = serde_json::from_slice::<brigalow_core::policy::Submission>(data);
    let _ = serde_json::from_slice::<brigalow_core::policy::Policy>(data);
});
