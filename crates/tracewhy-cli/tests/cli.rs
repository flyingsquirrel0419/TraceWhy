//! End-to-end CLI behavior: subcommands, exit-code policy, output hygiene.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn why() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_why"));
    c.stdin(Stdio::null()).env("NO_COLOR", "1");
    c
}

fn run(args: &[&str]) -> Output {
    why().args(args).output().unwrap()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("tracewhy-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn has_strace() -> bool {
    let present = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("strace").is_file()))
        .unwrap_or(false);
    if !present {
        assert!(
            std::env::var("TRACEWHY_REQUIRE_ALL")
                .map(|v| v != "1")
                .unwrap_or(true),
            "strace is required (TRACEWHY_REQUIRE_ALL=1)"
        );
        eprintln!("strace not installed: skipping");
    }
    present
}

#[test]
fn version_and_help() {
    let o = run(&["--version"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).starts_with("TraceWhy "));
    let o = run(&["--help"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("why [OPTIONS] <command>"));
    assert!(run(&[]).status.success());
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(
        run(&["--definitely-not-an-option", "ls"]).status.code(),
        Some(2)
    );
    assert_eq!(run(&["diff", "only-one"]).status.code(), Some(2));
}

#[test]
fn json_stdout_is_pure_json_even_when_the_program_prints() {
    if !has_strace() {
        return;
    }
    let o = run(&[
        "--json",
        "sh",
        "-c",
        "echo program-stdout; echo program-stderr >&2; exit 4",
    ]);
    assert_eq!(o.status.code(), Some(4));
    let v: Value = serde_json::from_slice(&o.stdout).expect("stdout must be pure JSON");
    assert_eq!(v["schema"], "tracewhy.report/v1");
    assert_eq!(v["exit_code"], 4);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("program-stdout"),
        "program stdout moves to stderr in --json mode"
    );
}

#[test]
fn plain_output_has_no_ansi_when_not_a_tty() {
    if !has_strace() {
        return;
    }
    let o = why()
        .args(["true"])
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&o.stdout).contains('\x1b'));
    let o = why().args(["--color", "always", "true"]).output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains('\x1b'));
}

#[test]
fn missing_strace_is_unsupported_environment() {
    let dir = tmp("nostrace");
    std::os::unix::fs::symlink("/bin/true", dir.join("mytrue")).unwrap();
    let o = why().arg("mytrue").env("PATH", &dir).output().unwrap();
    assert_eq!(o.status.code(), Some(124));
    assert!(String::from_utf8_lossy(&o.stderr).contains("strace"));
}

#[test]
fn command_not_found_works_without_tracing() {
    let o = run(&["--json", "tracewhy-cli-test-missing-command"]);
    assert_eq!(o.status.code(), Some(127));
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["root_cause"]["kind"], "command_not_in_path");
}

#[test]
fn record_show_explain_roundtrip() {
    if !has_strace() {
        return;
    }
    let dir = tmp("record");
    let file = dir.join("run.whytrace");
    let o = why()
        .current_dir(&dir)
        .args(["record", "-o"])
        .arg(&file)
        .args(["cat", "nope.txt"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let show: Value = serde_json::from_slice(
        &why()
            .args(["show", "--json"])
            .arg(&file)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert_eq!(show["root_cause"]["kind"], "file_missing");
    let explain = why()
        .args(["explain", "--json"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(explain.status.success());
    let explain: Value = serde_json::from_slice(&explain.stdout).unwrap();
    assert_eq!(
        explain["root_cause"]["kind"], "file_missing",
        "re-analysis from recorded facts agrees"
    );
    let text =
        String::from_utf8_lossy(&why().arg("show").arg(&file).output().unwrap().stdout).to_string();
    assert!(
        text.contains("Root cause") && text.contains("Observed") && text.contains("Confidence")
    );
}

#[test]
fn show_rejects_garbage_files() {
    let dir = tmp("garbage");
    let f = dir.join("bad.whytrace");
    std::fs::write(&f, b"{\"format\":\"whytrace\",\"format_version\":999}").unwrap();
    let o = why().arg("show").arg(&f).output().unwrap();
    assert_eq!(o.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&o.stderr).contains("version 999"));
    std::fs::write(&f, b"\x00\x01garbage").unwrap();
    assert_eq!(
        why().arg("show").arg(&f).output().unwrap().status.code(),
        Some(125)
    );
}

#[test]
fn diff_finds_causal_divergence() {
    if !has_strace() {
        return;
    }
    let dir = tmp("diff");
    std::fs::write(dir.join("present.txt"), "ok").unwrap();
    let good = dir.join("good.whytrace");
    let bad = dir.join("bad.whytrace");
    why()
        .current_dir(&dir)
        .args(["record", "-o"])
        .arg(&good)
        .args(["cat", "present.txt"])
        .output()
        .unwrap();
    std::fs::remove_file(dir.join("present.txt")).unwrap();
    why()
        .current_dir(&dir)
        .args(["record", "-o"])
        .arg(&bad)
        .args(["cat", "present.txt"])
        .output()
        .unwrap();
    let o = why()
        .args(["diff", "--json"])
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert!(o.status.success());
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    let key = v["divergence"]["key"].as_str().unwrap();
    assert!(
        key.starts_with("file:") && key.ends_with("present.txt"),
        "{v}"
    );
    assert_eq!(v["divergence"]["confidence"], "high");
    let text = String::from_utf8_lossy(
        &why()
            .arg("diff")
            .arg(&good)
            .arg(&bad)
            .output()
            .unwrap()
            .stdout,
    )
    .to_string();
    assert!(
        text.contains("Causal divergence") && text.contains("WORKING") && text.contains("BROKEN")
    );
}

#[test]
fn doctor_reports() {
    let o = run(&["doctor", "--json"]);
    let v: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "strace"));
    assert_eq!(
        o.status.code(),
        Some(if v["ready"] == true { 0 } else { 124 })
    );
}
