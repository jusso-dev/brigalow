#![no_main]
use brigalow_core::audit::{Entry, SignedCheckpoint, Verifier};
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    if let Ok(entries) = serde_json::from_slice::<Vec<Entry>>(data) {
        let mut verifier = Verifier::default();
        for entry in entries.iter().take(1000) {
            if verifier.push(entry).is_err() {
                break;
            }
        }
        let _ = verifier.finish();
    }
    if let Ok(checkpoint) = serde_json::from_slice::<SignedCheckpoint>(data) {
        let _ = checkpoint.checkpoint.message();
    }
});
