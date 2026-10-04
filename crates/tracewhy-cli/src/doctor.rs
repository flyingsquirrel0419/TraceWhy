//! `why doctor`: can TraceWhy work here?

use serde_json::json;
use tracewhy_report::Style;

struct Check {
    name: &'static str,
    ok: Option<bool>,
    detail: String,
}

pub fn run(as_json: bool, color: bool) -> i32 {
    let s = Style { color };
    let mut checks = Vec::new();
    let linux = cfg!(target_os = "linux");
    checks.push(Check {
        name: "platform",
        ok: Some(linux),
        detail: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
    });
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|k| k.trim().to_string())
        .unwrap_or_default();
    checks.push(Check {
        name: "kernel",
        ok: None,
        detail: kernel,
    });
    let strace = tracewhy_tracer_strace::find_in_path("strace");
    let version = strace
        .as_deref()
        .and_then(tracewhy_tracer_strace::strace_version);
    checks.push(Check {
        name: "strace",
        ok: Some(strace.is_some()),
        detail: match (&strace, &version) {
            (Some(p), Some(v)) => format!("strace {v} ({})", p.display()),
            (Some(p), None) => format!("{}", p.display()),
            (None, _) => {
                "not installed — install with your package manager (apt/dnf/apk install strace)"
                    .into()
            }
        },
    });
    let tracing = strace.as_deref().map(tracewhy_tracer_strace::probe);
    checks.push(Check {
        name: "process tracing",
        ok: tracing.as_ref().map(|r| r.is_ok()),
        detail: match &tracing {
            Some(Ok(())) => "works".into(),
            Some(Err(e)) => format!("blocked: {e} (containers need CAP_SYS_PTRACE / --cap-add=SYS_PTRACE; check kernel.yama.ptrace_scope)"),
            None => "skipped (no strace)".into(),
        },
    });
    if let Ok(scope) = std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        let scope = scope.trim().to_string();
        checks.push(Check {
            name: "ptrace_scope",
            ok: Some(scope != "3"),
            detail: format!("{scope} (TraceWhy traces its own children, which works with 0–2)"),
        });
    }
    let docker = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join("docker").is_file()))
        .unwrap_or(false);
    let docker_ok = docker
        && std::process::Command::new("docker")
            .args(["info", "--format", "{{.ServerVersion}}"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|st| st.success())
            .unwrap_or(false);
    checks.push(Check {
        name: "docker",
        ok: None,
        detail: match (docker, docker_ok) {
            (false, _) => "not installed (optional; Docker investigation disabled)".into(),
            (true, false) => "CLI present, daemon not reachable (optional)".into(),
            (true, true) => "available".into(),
        },
    });
    let compose = docker_ok
        && std::process::Command::new("docker")
            .args(["compose", "version"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|st| st.success())
            .unwrap_or(false);
    if docker_ok {
        checks.push(Check {
            name: "compose",
            ok: None,
            detail: if compose {
                "available".into()
            } else {
                "plugin missing (optional)".into()
            },
        });
    }
    let ready = checks.iter().all(|c| c.ok != Some(false));
    if as_json {
        let v = json!({
            "tracewhy_version": crate::run::VERSION,
            "ready": ready,
            "checks": checks.iter().map(|c| json!({"name": c.name, "ok": c.ok, "detail": c.detail})).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap_or_default());
    } else {
        println!("{}", s.bold(&format!("TraceWhy {}", crate::run::VERSION)));
        for c in &checks {
            let mark = match c.ok {
                Some(true) => s.green("✓"),
                Some(false) => s.red("✗"),
                None => s.dim("•"),
            };
            println!("{mark} {:<16} {}", c.name, c.detail);
        }
        println!();
        if ready {
            println!("{}", s.green("Ready."));
        } else {
            println!("{}", s.red("Not ready: fix the ✗ items above."));
        }
    }
    if ready {
        0
    } else {
        124
    }
}
