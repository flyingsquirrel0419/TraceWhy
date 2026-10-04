use super::*;

#[test]
fn parses_own_test_binary() {
    let exe = std::env::current_exe().unwrap();
    let s = read_elf(&exe.to_string_lossy()).unwrap();
    assert_eq!(s.machine, host_machine());
    assert_eq!(s.class, 64);
}

#[test]
fn parses_system_binary_needed() {
    let Some(s) = read_elf("/bin/ls") else { return };
    assert!(s.interpreter.is_some());
    assert!(s.needed.iter().any(|n| n.starts_with("libc.so")));
}

#[test]
fn garbage_is_not_elf() {
    assert!(parse_elf(b"").is_none());
    assert!(parse_elf(b"#!/bin/sh\n").is_none());
    let mut fake = b"\x7fELF\x02\x01\x01".to_vec();
    fake.resize(64, 0xff);
    let _ = parse_elf(&fake);
    let mut fake = b"\x7fELF\x01\x02\x01".to_vec();
    fake.resize(52, 0x7f);
    let _ = parse_elf(&fake);
}

#[test]
fn library_search_finds_libc() {
    let env = EnvSnapshot::default();
    let f = search_library(
        "libc.so.6",
        Some("/bin/ls"),
        &env,
        Path::new("/tmp"),
        Instant::now() + std::time::Duration::from_secs(5),
    );
    if let FactKind::LibrarySearch { found, .. } = &f[0] {
        assert!(found.iter().any(|c| c.compatible));
    }
    let f = search_library(
        "libdefinitely-missing-xyz.so.9",
        Some("/bin/ls"),
        &env,
        Path::new("/tmp"),
        Instant::now() + std::time::Duration::from_secs(5),
    );
    assert!(matches!(&f[0], FactKind::LibrarySearch { found, .. } if found.is_empty()));
}
