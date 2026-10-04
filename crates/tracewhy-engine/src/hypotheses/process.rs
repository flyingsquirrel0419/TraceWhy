//! Process hypotheses: exec failures, crashes, shared libraries.

use super::fs::view;
use super::library::library_eval;
use super::{shell_quote, Ctx, Eval};
use tracewhy_core::{FactKind, InvestigationTarget, ObservationKind};
use tracewhy_event::EventKind;

pub fn evaluate(kind: &str, ctx: &Ctx<'_>) -> Option<Eval> {
    match &ctx.obs.kind {
        ObservationKind::ExecFailed {
            executable, error, ..
        } => exec(kind, ctx, executable, error.as_str()),
        ObservationKind::ProcessCrashed {
            signal,
            core_dumped,
            executable,
        } => crash(kind, ctx, signal, *core_dumped, executable.as_deref()),
        ObservationKind::LibraryLoadFailed {
            library,
            executable,
            ..
        } => library_eval(kind, ctx, library, executable.as_deref()),
        _ => None,
    }
}

fn exec(kind: &str, ctx: &Ctx<'_>, exe: &str, err: &str) -> Option<Eval> {
    let explicit = exe.contains('/');
    let name = exe.rsplit('/').next().unwrap_or(exe);
    let pv = if explicit { view(ctx, exe) } else { None };
    match (kind, err) {
        ("command_not_in_path", "ENOENT") => {
            if explicit
                && ctx.obs.events.len() <= 1
                && !matches!(&ctx.obs.kind, ObservationKind::ExecFailed { attempts, .. } if attempts.len() > 1)
            {
                return None;
            }
            let Some(f) = ctx.facts.by_key("executable_search", name) else {
                return Some(
                    Eval::new(format!("`{name}` is not installed or not on PATH.")).unresolved(
                        0.5,
                        &format!("Is {name} anywhere on PATH?"),
                        Some(InvestigationTarget::Executable {
                            name: name.to_string(),
                        }),
                    ),
                );
            };
            let FactKind::ExecutableSearch {
                path_dirs,
                candidates,
                elsewhere,
                ..
            } = &f.kind
            else {
                return None;
            };
            if candidates
                .iter()
                .any(|c| c.exists && c.executable && !c.is_dir)
            {
                return Some(Eval::new("found").refuted(f.id));
            }
            if candidates
                .iter()
                .any(|c| c.broken_symlink || (c.exists && !c.executable))
            {
                return None;
            }
            let mut e = Eval::new(format!("`{name}` is not installed or not on PATH."))
                .fact(f.id, ctx)
                .step(
                    format!("not found in {} PATH directories", path_dirs.len()),
                    Some(f.id),
                )
                .supported(0.92);
            if let Some(other) = elsewhere.first() {
                let dir = super::parent_dir(other);
                e = e.infer(format!("A copy exists at {other}, which is not on PATH."));
                return Some(e.fix(
                    format!("Add {dir} to PATH, or invoke it by full path"),
                    Some(format!("export PATH=\"{dir}:$PATH\"")),
                ));
            }
            Some(e.next(
                format!("Install `{name}`, or add the directory containing it to PATH"),
                None,
            ))
        }
        ("explicit_path_missing", "ENOENT") => {
            let p = pv?;
            if p.exists || p.broken {
                return None;
            }
            Some(
                Eval::new(format!("{exe} does not exist."))
                    .fact(p.fact.id, ctx)
                    .step("no such file", Some(p.fact.id))
                    .supported(0.9)
                    .next(format!("Build or install {exe}, or fix the path"), None),
            )
        }
        ("broken_symlink", "ENOENT") => {
            let p = pv.or_else(|| {
                // PATH search: look for a broken candidate.
                let f = ctx.facts.by_key("executable_search", name)?;
                if let FactKind::ExecutableSearch { candidates, .. } = &f.kind {
                    let c = candidates.iter().find(|c| c.broken_symlink)?;
                    return view(ctx, &c.path);
                }
                None
            })?;
            if !p.broken {
                return None;
            }
            Some(
                Eval::new(format!(
                    "`{name}` is a broken symbolic link (→ {}).",
                    p.target.unwrap_or("?")
                ))
                .fact(p.fact.id, ctx)
                .step("broken symlink", Some(p.fact.id))
                .supported(0.93)
                .fix(
                    "Reinstall the program or repoint the symlink at an existing file",
                    None,
                ),
            )
        }
        ("missing_interpreter", "ENOENT") => {
            let p = pv?;
            if !p.exists {
                return None;
            }
            if let Some(f) = ctx.facts.by_key("script_interpreter", exe) {
                if let FactKind::ScriptInterpreter {
                    interpreter,
                    interpreter_exists,
                    ..
                } = &f.kind
                {
                    if *interpreter_exists {
                        return Some(Eval::new("interpreter present").refuted(f.id));
                    }
                    return Some(
                        Eval::new(format!("{exe} needs interpreter {interpreter}, which is not installed."))
                            .fact(p.fact.id, ctx)
                            .fact(f.id, ctx)
                            .step(format!("#! {interpreter} missing"), Some(f.id))
                            .infer("The kernel reports ENOENT for the script because its #! interpreter does not exist.")
                            .supported(0.93)
                            .fix(format!("Install {interpreter}, or change the #! line of {exe}"), None),
                    );
                }
            }
            if let Some(f) = ctx.facts.by_key("elf_info", exe) {
                if let FactKind::ElfInfo {
                    interpreter: Some(interp),
                    machine,
                    ..
                } = &f.kind
                {
                    if let Some(ip) = view(ctx, interp) {
                        if !ip.exists {
                            return Some(
                                Eval::new(format!("{exe} needs the dynamic loader {interp}, which does not exist (binary built for {machine}?)."))
                                    .fact(f.id, ctx)
                                    .fact(ip.fact.id, ctx)
                                    .step(format!("loader {interp} missing"), Some(ip.fact.id))
                                    .supported(0.9)
                                    .next("Use a binary built for this system, or install its loader/libc", None),
                            );
                        }
                    }
                }
            }
            Some(
                Eval::new(format!(
                    "{exe} exists but cannot be executed (missing interpreter?)."
                ))
                .unresolved(
                    0.4,
                    "Which interpreter does it need?",
                    Some(InvestigationTarget::Elf {
                        path: exe.to_string(),
                    }),
                ),
            )
        }
        ("is_directory", "EACCES") => {
            let p = pv?;
            if p.file_type != Some("directory") {
                return None;
            }
            Some(
                Eval::new(format!("{exe} is a directory, not a program."))
                    .fact(p.fact.id, ctx)
                    .supported(0.9)
                    .next("Run the program inside it instead", None),
            )
        }
        ("not_executable", "EACCES") => {
            let path = if explicit {
                exe.to_string()
            } else {
                let f = ctx.facts.by_key("executable_search", name)?;
                let FactKind::ExecutableSearch { candidates, .. } = &f.kind else {
                    return None;
                };
                candidates
                    .iter()
                    .find(|c| c.exists && !c.executable && !c.is_dir)?
                    .path
                    .clone()
            };
            let f = ctx.facts.path(&path)?;
            let FactKind::PathStatus {
                exists,
                mode,
                access,
                file_type,
                ..
            } = &f.kind
            else {
                return None;
            };
            if !exists || file_type.as_deref() == Some("directory") {
                return None;
            }
            if access.execute {
                return Some(Eval::new("executable").refuted(f.id));
            }
            let m = mode
                .map(|m| format!("{:o}", m & 0o7777))
                .unwrap_or_else(|| "?".into());
            Some(
                Eval::new(format!("{path} is not executable (mode {m})."))
                    .fact(f.id, ctx)
                    .step(format!("mode {m}: no execute bit"), Some(f.id))
                    .supported(0.93)
                    .fix(
                        "Make it executable",
                        Some(format!("chmod +x {}", shell_quote(&path))),
                    ),
            )
        }
        ("noexec_mount", "EACCES") => {
            let f = ctx.facts.of_type("filesystem").into_iter().find(|f| matches!(&f.kind, FactKind::Filesystem { path, noexec: true, .. } if path == exe))?;
            let FactKind::Filesystem { mount_point, .. } = &f.kind else {
                return None;
            };
            let mp = mount_point.clone().unwrap_or_default();
            Some(
                Eval::new(format!("{exe} is on a filesystem mounted noexec ({mp})."))
                    .fact(f.id, ctx)
                    .step(format!("{mp} mounted noexec"), Some(f.id))
                    .supported(0.92)
                    .next("Move the program to an executable filesystem, or run it through its interpreter", None),
            )
        }
        ("ancestor_not_searchable", "EACCES") => {
            let f = ctx.facts.by_key("ancestor_not_searchable", exe)?;
            let FactKind::AncestorNotSearchable { ancestor, .. } = &f.kind else {
                return None;
            };
            Some(
                Eval::new(format!(
                    "The current user cannot enter {ancestor}, so {exe} cannot be executed."
                ))
                .fact(f.id, ctx)
                .step(format!("{ancestor} not searchable"), Some(f.id))
                .supported(0.9)
                .fix(
                    format!("Grant search permission on {ancestor}"),
                    Some(format!("chmod o+x {}", shell_quote(ancestor))),
                ),
            )
        }
        ("wrong_architecture", "ENOEXEC") => {
            let f = ctx.facts.by_key("elf_info", exe)?;
            let FactKind::ElfInfo { machine, class, .. } = &f.kind else {
                return None;
            };
            let host = ctx.facts.first_of("host_architecture")?;
            let FactKind::HostArchitecture { machine: hm } = &host.kind else {
                return None;
            };
            if machine == hm {
                return Some(Eval::new("same arch").refuted(f.id));
            }
            Some(
                Eval::new(format!(
                    "{exe} is built for {machine} ({class}-bit), but this host is {hm}."
                ))
                .fact(f.id, ctx)
                .fact(host.id, ctx)
                .step(format!("{machine} binary on {hm} host"), Some(f.id))
                .supported(0.93)
                .fix(format!("Use a {hm} build of the program"), None),
            )
        }
        ("not_an_executable", "ENOEXEC") => {
            let f = ctx.facts.by_key("not_elf", exe)?;
            Some(
                Eval::new(format!(
                    "{exe} is neither an ELF binary nor a script with a #! line."
                ))
                .fact(f.id, ctx)
                .step("unknown executable format", Some(f.id))
                .supported(0.85)
                .fix(
                    format!("Add a #! line to {exe}, or run it with its interpreter"),
                    None,
                ),
            )
        }
        ("executable_busy", "ETXTBSY") => Some(
            Eval::new(format!(
                "{exe} is still open for writing by another process (being built or copied)."
            ))
            .supported(0.7)
            .next("Wait for the build/copy to finish, then retry", None),
        ),
        _ => None,
    }
}

fn signal_meaning(sig: &str) -> &'static str {
    match sig {
        "SIGSEGV" => "segmentation fault: invalid memory access",
        "SIGBUS" => "bus error: invalid memory access",
        "SIGABRT" => "aborted: assertion failure or abort()",
        "SIGILL" => "illegal instruction",
        "SIGFPE" => "arithmetic exception",
        "SIGKILL" => "killed unconditionally",
        "SIGTERM" => "asked to terminate",
        "SIGPIPE" => "wrote to a closed pipe",
        "SIGXCPU" => "CPU time limit exceeded",
        "SIGXFSZ" => "file size limit exceeded",
        "SIGSYS" => "disallowed system call",
        _ => "terminated by a signal",
    }
}

fn crash(kind: &str, ctx: &Ctx<'_>, signal: &str, core: bool, exe: Option<&str>) -> Option<Eval> {
    let pid = ctx.obs.pid;
    let name = exe
        .map(|e| e.rsplit('/').next().unwrap_or(e))
        .unwrap_or("The process")
        .to_string();
    // A process signalling itself (abort(), raise(), `kill $$`) crashed on its own.
    let sender = ctx.events.iter().find(|e| {
        e.process() != pid
            && matches!(&e.kind, EventKind::SignalSent { target, signal: s } if (*target == i64::from(pid) || *target == -i64::from(pid)) && s == signal)
    });
    match kind {
        "killed_by_traced_process" => {
            let ev = sender?;
            let who = ctx
                .tree
                .get(ev.process())
                .map(|p| p.display_name())
                .unwrap_or_else(|| format!("pid {}", ev.process()));
            Some(
                Eval::new(format!(
                    "{name} (pid {pid}) was killed with {signal} by {who} (pid {}).",
                    ev.process()
                ))
                .step(format!("{who} sent {signal}"), None)
                .supported(0.9)
                .next(
                    format!("Check why {who} terminated it (timeout, supervisor, test runner)"),
                    None,
                ),
            )
        }
        "process_crashed" => {
            if sender.is_some()
                || !matches!(
                    signal,
                    "SIGSEGV"
                        | "SIGBUS"
                        | "SIGABRT"
                        | "SIGILL"
                        | "SIGFPE"
                        | "SIGSYS"
                        | "SIGXCPU"
                        | "SIGXFSZ"
                )
            {
                return None;
            }
            let mut e = Eval::new(format!(
                "{name} crashed with {signal} ({}).",
                signal_meaning(signal)
            ))
            .supported(0.75);
            if core {
                e = e.infer("A core dump was written; it contains the crash location.");
            }
            Some(e.next(
                format!("Run {name} under a debugger, or inspect the core dump (`coredumpctl debug` with systemd-coredump)"),
                None,
            ))
        }
        "killed_externally" => {
            if sender.is_some()
                || !matches!(
                    signal,
                    "SIGKILL" | "SIGTERM" | "SIGINT" | "SIGHUP" | "SIGPIPE"
                )
            {
                return None;
            }
            if matches!(signal, "SIGINT" | "SIGHUP") {
                let how = if signal == "SIGINT" {
                    "interrupted (SIGINT, e.g. Ctrl-C)"
                } else {
                    "hung up (SIGHUP: its terminal closed)"
                };
                return Some(
                    Eval::new(format!("{name} was {how}; it did not fail on its own."))
                        .supported(0.6)
                        .next(
                            "Re-run without interrupting it to see whether it fails by itself",
                            None,
                        ),
                );
            }
            let why = if signal == "SIGKILL" {
                "from outside the traced command (commonly the kernel OOM killer, a timeout, or a container limit)"
            } else {
                "from outside the traced command"
            };
            Some(
                Eval::new(format!("{name} was killed by {signal} {why}."))
                    .supported(0.5)
                    .next("Check `dmesg` / `journalctl -k` for OOM-killer messages and any supervising timeouts", None),
            )
        }
        _ => None,
    }
}
