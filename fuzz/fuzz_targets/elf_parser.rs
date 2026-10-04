#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tracewhy_investigator_linux::parse_elf(data);
});
