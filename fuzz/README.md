# Fuzz targets

Requires nightly Rust and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz):

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run strace_parser
cargo +nightly fuzz run whytrace_loader
cargo +nightly fuzz run dns_decoder
cargo +nightly fuzz run elf_parser
cargo +nightly fuzz run redactor
```

The same properties (no panics, idempotent redaction) are also checked on
every `cargo test` by the deterministic randomized tests in
`crates/tracewhy-tracer-strace/tests/robustness.rs` and
`crates/tracewhy-format/tests/robustness.rs`.
