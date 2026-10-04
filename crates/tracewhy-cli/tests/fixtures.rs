//! Fixture corpus: runs the real `why` binary over every `fixtures/<name>/`
//! scenario and checks the *semantic* result (root-cause kind, confidence,
//! exit status, evidence, forbidden output) — never exact report text.
//!
//! Fixtures whose requirements are missing (Docker, gcc, root, ...) are
//! reported as skipped. Set `TRACEWHY_REQUIRE_ALL=1` to fail instead.
//! Set `TRACEWHY_FIXTURE=<name>` to run a single fixture.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn in_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
        .unwrap_or(false)
}

fn ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn missing_requirement(req: &str) -> Option<String> {
    let ok = match req {
        "root" | "mount" => is_root(),
        "docker" => {
            in_path("docker") && ok("docker", &["info"]) && ok("docker", &["compose", "version"])
        }
        "dns-nxdomain" => {
            use std::net::ToSocketAddrs;
            ("probe.tracewhy.invalid", 80).to_socket_addrs().is_err()
        }
        r if r.starts_with("docker-image:") => {
            ok("docker", &["image", "inspect", &r["docker-image:".len()..]])
        }
        r if r.starts_with("port-free:") => {
            let port: u16 = r["port-free:".len()..].parse().unwrap_or(0);
            std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
                && std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
        }
        tool => in_path(tool),
    };
    (!ok).then(|| req.to_string())
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let dest = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            std::fs::copy(&p, &dest).unwrap();
        }
    }
}

fn run_script(work: &Path, name: &str) -> Result<(), String> {
    let s = work.join(name);
    if !s.exists() {
        return Ok(());
    }
    let out = Command::new("sh")
        .arg(&s)
        .current_dir(work)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

struct Outcome {
    name: String,
    result: Result<(), String>,
    skipped: Option<String>,
}

fn text_of(report: &Value) -> String {
    let mut parts = Vec::new();
    for key in ["evidence", "inferences", "contributing"] {
        if let Some(a) = report[key].as_array() {
            parts.extend(a.iter().filter_map(|v| v.as_str().map(String::from)));
        }
    }
    if let Some(a) = report["chain"].as_array() {
        parts.extend(
            a.iter()
                .filter_map(|v| v["label"].as_str().map(String::from)),
        );
    }
    for k in ["title", "detail"] {
        if let Some(s) = report["root_cause"][k].as_str() {
            parts.push(s.to_string());
        }
    }
    parts.join("\n")
}

fn check(name: &str, dir: &Path, why: &Path) -> Outcome {
    let spec: Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut reqs: Vec<String> = spec["requires"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    reqs.push("strace".into());
    if spec["as_user"].is_string() {
        reqs.push("setpriv".into());
    }
    let missing: Vec<String> = reqs.iter().filter_map(|r| missing_requirement(r)).collect();
    if !missing.is_empty() {
        return Outcome {
            name: name.into(),
            result: Ok(()),
            skipped: Some(format!("missing: {}", missing.join(", "))),
        };
    }

    let work = std::env::temp_dir().join(format!("tracewhy-fixture-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    copy_dir(dir, &work);
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o755));
    let result = (|| -> Result<(), String> {
        run_script(&work, "setup.sh")?;
        let command: Vec<String> = spec["command"]
            .as_array()
            .ok_or("expected.json: command missing")?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        // A copy of the binary readable by any user (for as_user fixtures).
        let bin = work.join(".why");
        std::fs::copy(why, &bin).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
            .map_err(|e| e.to_string())?;
        let mut cmd = if spec["as_user"].as_str() == Some("nobody") {
            let mut c = Command::new("setpriv");
            c.args(["--reuid=65534", "--regid=65534", "--clear-groups"])
                .arg(&bin);
            c
        } else {
            Command::new(&bin)
        };
        cmd.arg("--json");
        // Fixtures running as another user cannot write into the traces dir.
        if let (Ok(dir), false) = (
            std::env::var("TRACEWHY_FIXTURE_TRACES_DIR"),
            spec["as_user"].is_string(),
        ) {
            cmd.arg("-o")
                .arg(Path::new(&dir).join(format!("{name}.whytrace")));
        }
        cmd.arg("--")
            .args(&command)
            .current_dir(&work)
            .stdin(Stdio::null());
        if let Some(env) = spec["env"].as_object() {
            for (k, v) in env {
                cmd.env(k, v.as_str().unwrap_or(""));
            }
        }
        let out = cmd.output().map_err(|e| e.to_string())?;
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let report: Value = serde_json::from_str(&stdout)
            .map_err(|e| format!("stdout is not JSON ({e}): {stdout}\nstderr: {stderr}"))?;
        let exp = &spec["expect"];
        let mut errors = Vec::new();
        if let Some(st) = exp["status"].as_str() {
            if report["status"].as_str() != Some(st) {
                errors.push(format!("status: expected {st}, got {}", report["status"]));
            }
        }
        if let Some(rc) = exp["root_cause"].as_str() {
            if report["root_cause"]["kind"].as_str() != Some(rc) {
                errors.push(format!(
                    "root cause: expected {rc}, got {} ({})",
                    report["root_cause"]["kind"], report["root_cause"]["title"]
                ));
            }
        }
        if let Some(min) = exp["minimum_confidence"].as_str() {
            let rank = |s: &str| match s {
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0,
            };
            let got = report["confidence"].as_str().unwrap_or("");
            if rank(got) < rank(min) {
                errors.push(format!("confidence: expected at least {min}, got {got:?}"));
            }
        }
        if let Some(code) = exp["exit_code"].as_i64() {
            if out.status.code() != Some(code as i32) {
                errors.push(format!(
                    "exit status: expected {code}, got {:?}",
                    out.status.code()
                ));
            }
        }
        let text = text_of(&report);
        for ev in exp["required_evidence"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            if !text.contains(ev) {
                errors.push(format!("missing evidence {ev:?} in:\n{text}"));
            }
        }
        for f in exp["forbidden_root_causes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
        {
            if report["root_cause"]["kind"].as_str() == Some(f) {
                errors.push(format!("forbidden root cause {f}"));
            }
        }
        if let Some(forbidden) = exp["forbidden_output"].as_array() {
            // Also check the text report and a recorded .whytrace.
            let text_out = Command::new(&bin)
                .arg("--")
                .args(&command)
                .current_dir(&work)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| e.to_string())?;
            let rec = work.join("check.whytrace");
            let rec_out = Command::new(&bin)
                .arg("record")
                .arg("-o")
                .arg(&rec)
                .arg("--")
                .args(&command)
                .current_dir(&work)
                .stdin(Stdio::null())
                .output()
                .map_err(|e| e.to_string())?;
            let recorded = std::fs::read_to_string(&rec).unwrap_or_default();
            let show = Command::new(&bin)
                .arg("show")
                .arg(&rec)
                .output()
                .map_err(|e| e.to_string())?;
            let views = [
                ("json", stdout.clone()),
                (
                    "text",
                    String::from_utf8_lossy(&text_out.stdout).to_string(),
                ),
                (
                    "record-report",
                    String::from_utf8_lossy(&rec_out.stderr).to_string(),
                ),
                ("whytrace", recorded),
                ("show", String::from_utf8_lossy(&show.stdout).to_string()),
            ];
            for f in forbidden.iter().filter_map(|v| v.as_str()) {
                for (view, content) in &views {
                    // The program's own stderr passes through untouched; only TraceWhy output is checked.
                    let content = if *view == "text" || *view == "record-report" {
                        content.split("TraceWhy\n").nth(1).unwrap_or("").to_string()
                    } else {
                        content.clone()
                    };
                    if content.contains(f) {
                        errors.push(format!("secret {f:?} leaked in {view} output"));
                    }
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n"))
        }
    })();
    let _ = run_script(&work, "cleanup.sh");
    let _ = std::fs::remove_dir_all(&work);
    Outcome {
        name: name.into(),
        result,
        skipped: None,
    }
}

#[test]
fn fixture_corpus() {
    let why = PathBuf::from(env!("CARGO_BIN_EXE_why"));
    let only = std::env::var("TRACEWHY_FIXTURE").ok();
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.path().join("expected.json").is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| only.as_ref().map(|o| o == n).unwrap_or(true))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "no fixtures found");
    let outcomes: Vec<Outcome> = names
        .iter()
        .map(|n| check(n, &fixtures_dir().join(n), &why))
        .collect();
    let require_all = std::env::var("TRACEWHY_REQUIRE_ALL")
        .map(|v| v == "1")
        .unwrap_or(false);
    let mut failed = 0;
    eprintln!("\nfixture results:");
    for o in &outcomes {
        match (&o.skipped, &o.result) {
            (Some(why), _) => {
                eprintln!("  SKIP {:<36} {why}", o.name);
                if require_all {
                    failed += 1;
                }
            }
            (None, Ok(())) => eprintln!("  PASS {}", o.name),
            (None, Err(e)) => {
                failed += 1;
                eprintln!(
                    "  FAIL {}\n{}",
                    o.name,
                    e.lines()
                        .map(|l| format!("       {l}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        }
    }
    let skipped = outcomes.iter().filter(|o| o.skipped.is_some()).count();
    let passed = outcomes
        .iter()
        .filter(|o| o.skipped.is_none() && o.result.is_ok())
        .count();
    eprintln!("{passed} passed, {failed} failed, {skipped} skipped");
    assert_eq!(failed, 0, "fixture failures (see above)");
}
