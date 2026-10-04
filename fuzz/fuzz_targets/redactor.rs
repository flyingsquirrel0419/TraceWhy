#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let r = tracewhy_redact::Redactor::with_home(Some("/home/fuzz".into()));
    let once = r.redact(&text).into_owned();
    // Redaction must be idempotent.
    assert_eq!(r.redact(&once), once);
});
