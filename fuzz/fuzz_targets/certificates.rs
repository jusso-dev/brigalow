#![no_main]
use der::Decode;
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if data.len() > 65536 {
        return;
    }
    let _ = x509_cert::Certificate::from_der(data);
    let _ = cms::content_info::ContentInfo::from_der(data);
    let _ = brigalow_crypto::private_ca::csr_public_key(data);
    let _ = brigalow_crypto::certificates::validate_chain(&[], &[data.to_vec()], &[], 1);
});
