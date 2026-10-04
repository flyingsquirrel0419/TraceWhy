//! Symptom detectors: turn semantic events into raw observations.

use super::index::SuccessIndex;
use super::text::{basename, Output};
use super::{RawObs, BENIGN_PATHS};
use std::collections::{HashMap, HashSet};
use tracewhy_core::ObservationKind;
use tracewhy_event::{DnsRcode, Endpoint, Errno, Event, EventKind, ProcessTree, Protocol};

/// Exec failures: the last failed attempt per process with no later success.
pub(super) fn exec_failures<'a>(
    events: &'a [Event],
    index: &SuccessIndex,
    raw: &mut Vec<RawObs>,
) -> HashMap<u32, Vec<&'a Event>> {
    let mut exec_attempts: HashMap<u32, Vec<&Event>> = HashMap::new();
    for e in events {
        if let EventKind::ExecFailed { .. } = &e.kind {
            exec_attempts.entry(e.process()).or_default().push(e);
        }
    }
    for (pid, attempts) in &exec_attempts {
        let Some(last) = attempts.last() else {
            continue;
        };
        if index.exec_after(*pid, last.seq) {
            continue;
        }
        if let EventKind::ExecFailed {
            executable, error, ..
        } = &last.kind
        {
            let name = basename(executable);
            let tried: Vec<String> = attempts
                .iter()
                .filter_map(|a| match &a.kind {
                    EventKind::ExecFailed { executable, .. } if basename(executable) == name => {
                        Some(executable.clone())
                    }
                    _ => None,
                })
                .collect();
            // A PATH search reports the most informative error (EACCES over ENOENT).
            let error = attempts
                .iter()
                .filter_map(|a| a.kind.error())
                .find(|e| !e.is("ENOENT"))
                .unwrap_or(error)
                .clone();
            let exe = if tried.len() > 1 && error.is("ENOENT") {
                name.to_string()
            } else {
                executable.clone()
            };
            raw.push((
                ObservationKind::ExecFailed {
                    executable: exe,
                    error,
                    attempts: tried,
                },
                *pid,
                attempts.iter().map(|a| a.seq).collect(),
                last.ts,
                0.55,
            ));
        }
    }

    exec_attempts
}

/// Shell "command not found": PATH probing by stat() and exit status 127.
pub(super) fn shell_not_found(
    events: &[Event],
    tree: &ProcessTree,
    index: &SuccessIndex,
    outputs: &[Output],
    exec_attempts: &HashMap<u32, Vec<&Event>>,
    raw: &mut Vec<RawObs>,
) {
    for info in tree.processes.values() {
        if info.thread_of.is_some() || info.exit.as_ref().map(|s| s.shell_code()) != Some(127) {
            continue;
        }
        if exec_attempts.contains_key(&info.pid) {
            continue;
        }
        let mut by_name: HashMap<&str, Vec<&Event>> = HashMap::new();
        for e in events.iter().filter(|e| e.process() == info.pid) {
            if let EventKind::PathOpFailed { path, error, .. } = &e.kind {
                if error.is("ENOENT") {
                    by_name.entry(basename(path)).or_default().push(e);
                }
            }
        }
        let path_dirs_hit = |v: &Vec<&Event>| {
            v.iter()
                .filter_map(|e| match &e.kind {
                    EventKind::PathOpFailed { path, .. } => path.rsplit_once('/').map(|x| x.0),
                    _ => None,
                })
                .collect::<HashSet<_>>()
                .len()
        };
        let is_shell = info
            .executable
            .as_deref()
            .map(|e| {
                matches!(
                    basename(e),
                    "sh" | "bash" | "dash" | "zsh" | "ksh" | "mksh" | "ash" | "busybox" | "fish"
                )
            })
            .unwrap_or(false);
        let said_not_found = |n: &str| {
            outputs.iter().any(|o| {
                o.pid == info.pid
                    && (o.text.contains(&format!("{n}: not found"))
                        || o.text.contains(&format!("{n}: command not found")))
            })
        };
        if let Some((name, probes)) = by_name
            .iter()
            .filter(|(n, v)| {
                path_dirs_hit(v) >= 2 && !n.is_empty() && !index.exec_name_ok(info.pid, n)
            })
            .filter(|(n, _)| is_shell || said_not_found(n))
            .max_by_key(|(_, v)| v.last().map(|e| e.seq).unwrap_or(0))
        {
            raw.push((
                ObservationKind::ExecFailed {
                    executable: name.to_string(),
                    error: Errno::new("ENOENT"),
                    attempts: probes
                        .iter()
                        .filter_map(|e| match &e.kind {
                            EventKind::PathOpFailed { path, .. } => Some(path.clone()),
                            _ => None,
                        })
                        .collect(),
                },
                info.pid,
                probes.iter().map(|e| e.seq).collect(),
                probes.last().and_then(|e| e.ts),
                0.6,
            ));
        }
    }
}

/// Shared libraries: loader probes with no success, in a process exiting 127
/// or reporting a loader error.
pub(super) fn library_failures(
    events: &[Event],
    tree: &ProcessTree,
    index: &SuccessIndex,
    outputs: &[Output],
    raw: &mut Vec<RawObs>,
) {
    for info in tree.processes.values() {
        if info.thread_of.is_some() {
            continue;
        }
        let loader_failed = info.exit.as_ref().map(|s| s.shell_code()) == Some(127)
            || outputs.iter().any(|o| {
                o.pid == info.pid && o.text.contains("error while loading shared libraries")
            });
        if !loader_failed {
            continue;
        }
        let mut libs: HashMap<&str, Vec<&Event>> = HashMap::new();
        for e in events.iter().filter(|e| e.process() == info.pid) {
            if let EventKind::FileOpenFailed { path, error, .. } = &e.kind {
                let b = basename(path);
                if error.is("ENOENT") && is_shared_object(b) {
                    libs.entry(b).or_default().push(e);
                }
            }
        }
        for (lib, probes) in libs {
            if index.opened_basename(info.pid, lib) {
                continue;
            }
            raw.push((
                ObservationKind::LibraryLoadFailed {
                    library: lib.to_string(),
                    executable: info.executable.clone(),
                    searched: probes
                        .iter()
                        .filter_map(|e| match &e.kind {
                            EventKind::FileOpenFailed { path, .. } => {
                                path.rsplit_once('/').map(|x| x.0.to_string())
                            }
                            _ => None,
                        })
                        .collect(),
                },
                info.pid,
                probes.iter().map(|e| e.seq).collect(),
                probes.last().and_then(|e| e.ts),
                0.6,
            ));
        }
    }
}

/// Per-event symptoms (file, network, write, resource, signal). Returns the
/// failed DNS answers for grouping.
pub(super) fn event_symptoms<'a>(
    events: &'a [Event],
    tree: &ProcessTree,
    raw: &mut Vec<RawObs>,
) -> Vec<&'a Event> {
    let mut resource_seen: HashSet<(u32, String)> = HashSet::new();
    let mut dns_failures: Vec<&Event> = Vec::new();
    for e in events {
        let pid = e.process();
        match &e.kind {
            EventKind::FileOpenFailed {
                path,
                requested,
                error,
                access,
            } => {
                if BENIGN_PATHS.contains(&path.as_str()) {
                    continue;
                }
                if error.is("EMFILE") || error.is("ENFILE") {
                    if resource_seen.insert((pid, error.0.clone())) {
                        raw.push((
                            ObservationKind::ResourceLimit {
                                syscall: "open".into(),
                                error: error.clone(),
                            },
                            pid,
                            vec![e.seq],
                            e.ts,
                            0.55,
                        ));
                    }
                    continue;
                }
                if error.is("ENOSPC") || error.is("EDQUOT") {
                    raw.push((
                        ObservationKind::WriteFailed {
                            target: Some(path.clone()),
                            error: error.clone(),
                        },
                        pid,
                        vec![e.seq],
                        e.ts,
                        0.55,
                    ));
                    continue;
                }
                if is_shared_object(basename(path)) && error.is("ENOENT") {
                    // Loader probes are handled as LibraryLoadFailed above.
                    continue;
                }
                let base = file_base_score(error);
                if base > 0.0 {
                    raw.push((
                        ObservationKind::FileAccessFailed {
                            path: path.clone(),
                            requested: requested.clone(),
                            op: "open".into(),
                            access: Some(*access),
                            error: error.clone(),
                        },
                        pid,
                        vec![e.seq],
                        e.ts,
                        base,
                    ));
                }
            }
            EventKind::PathOpFailed {
                op,
                path,
                requested,
                error,
            } => {
                if BENIGN_PATHS.contains(&path.as_str()) {
                    continue;
                }
                if error.is("ENOSPC") || error.is("EDQUOT") {
                    raw.push((
                        ObservationKind::WriteFailed {
                            target: Some(path.clone()),
                            error: error.clone(),
                        },
                        pid,
                        vec![e.seq],
                        e.ts,
                        0.55,
                    ));
                    continue;
                }
                // stat/access/readlink failures are existence checks, usually optional.
                let probe_op = matches!(op.as_str(), "stat" | "access" | "readlink");
                let mut base = file_base_score(error);
                if probe_op {
                    base *= 0.5;
                }
                if base > 0.0 {
                    raw.push((
                        ObservationKind::FileAccessFailed {
                            path: path.clone(),
                            requested: requested.clone(),
                            op: op.clone(),
                            access: None,
                            error: error.clone(),
                        },
                        pid,
                        vec![e.seq],
                        e.ts,
                        base,
                    ));
                }
            }
            EventKind::ConnectFailed {
                endpoint,
                protocol,
                error,
            } => {
                if let Endpoint::Unix { path } = endpoint {
                    if BENIGN_PATHS.contains(&path.as_str()) {
                        continue;
                    }
                }
                let base = match (protocol, error.as_str()) {
                    (Protocol::Udp, _) => 0.15,
                    (_, "ECONNREFUSED") => 0.5,
                    (Protocol::Unix, _) => 0.35,
                    (_, "ENETUNREACH" | "EHOSTUNREACH" | "ETIMEDOUT") => 0.45,
                    _ => 0.35,
                };
                raw.push((
                    ObservationKind::ConnectFailed {
                        endpoint: endpoint.clone(),
                        protocol: *protocol,
                        error: error.clone(),
                    },
                    pid,
                    vec![e.seq],
                    e.ts,
                    base,
                ));
            }
            EventKind::BindFailed {
                endpoint,
                protocol,
                error,
            } => {
                raw.push((
                    ObservationKind::BindFailed {
                        endpoint: endpoint.clone(),
                        protocol: *protocol,
                        error: error.clone(),
                    },
                    pid,
                    vec![e.seq],
                    e.ts,
                    0.6,
                ));
            }
            EventKind::DnsAnswer {
                rcode: DnsRcode::NxDomain | DnsRcode::ServFail | DnsRcode::Refused,
                ..
            } => {
                dns_failures.push(e);
            }
            EventKind::WriteFailed { target, error } => {
                let base = match error.as_str() {
                    "ENOSPC" | "EDQUOT" => 0.6,
                    "EIO" | "EFBIG" => 0.45,
                    "EPIPE" | "ECONNRESET" => 0.2,
                    _ => 0.3,
                };
                raw.push((
                    ObservationKind::WriteFailed {
                        target: target.clone(),
                        error: error.clone(),
                    },
                    pid,
                    vec![e.seq],
                    e.ts,
                    base,
                ));
            }
            EventKind::SyscallFailed { syscall, error, .. } => {
                if (error.is("EMFILE") || error.is("ENFILE"))
                    && resource_seen.insert((pid, error.0.clone()))
                {
                    raw.push((
                        ObservationKind::ResourceLimit {
                            syscall: syscall.clone(),
                            error: error.clone(),
                        },
                        pid,
                        vec![e.seq],
                        e.ts,
                        0.55,
                    ));
                } else if error.is("ENOSPC") || error.is("EDQUOT") {
                    raw.push((
                        ObservationKind::WriteFailed {
                            target: None,
                            error: error.clone(),
                        },
                        pid,
                        vec![e.seq],
                        e.ts,
                        0.5,
                    ));
                }
            }
            EventKind::ProcessKilled {
                signal,
                core_dumped,
            } => {
                let exe = tree.get(e.pid).and_then(|p| p.executable.clone());
                let base = match signal.as_str() {
                    "SIGSEGV" | "SIGBUS" | "SIGILL" | "SIGFPE" | "SIGABRT" | "SIGSYS" => 0.6,
                    "SIGKILL" | "SIGTERM" | "SIGXCPU" | "SIGXFSZ" => 0.5,
                    "SIGPIPE" => 0.3,
                    _ => 0.35,
                };
                raw.push((
                    ObservationKind::ProcessCrashed {
                        signal: signal.clone(),
                        core_dumped: *core_dumped,
                        executable: exe,
                    },
                    pid,
                    vec![e.seq],
                    e.ts,
                    base,
                ));
            }
            _ => {}
        }
    }

    dns_failures
}

fn file_base_score(error: &Errno) -> f64 {
    match error.as_str() {
        "ENOENT" => 0.2,
        "EACCES" | "EPERM" => 0.35,
        "EROFS" => 0.45,
        "ENOTDIR" | "ELOOP" | "EISDIR" | "ENAMETOOLONG" => 0.25,
        _ => 0.0,
    }
}

fn is_shared_object(name: &str) -> bool {
    name.ends_with(".so") || name.contains(".so.")
}
