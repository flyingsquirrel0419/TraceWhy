//! Graph construction helpers and observation wording for explanations.

use crate::observe::{basename, contains_token, output_lines_after};
use crate::AnalysisInput;
use tracewhy_core::{EvidenceRef, Observation, ObservationKind};
use tracewhy_event::Endpoint;
use tracewhy_graph::{CauseGraph, EdgeKind, NodeId, NodeKind};

/// Command and process nodes, linked by `spawned` edges.
pub(super) fn build_process_graph(
    graph: &mut CauseGraph,
    input: &AnalysisInput<'_>,
) -> Option<NodeId> {
    let root = input.tree.root.and_then(|r| input.tree.get(r));
    let label = Some(input.command.join(" "))
        .filter(|s| !s.is_empty())
        .or_else(|| root.map(|p| p.args.join(" ")).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| "command".into());
    let cmd = graph.node(NodeKind::Command, "command", label, Vec::new());
    for p in input
        .tree
        .processes
        .values()
        .filter(|p| p.thread_of.is_none())
    {
        let Some(n) = graph.node(
            NodeKind::Process,
            format!("proc:{}", p.pid),
            p.display_name(),
            vec![EvidenceRef::Event { seq: p.first_seq }],
        ) else {
            break;
        };
        match p.parent {
            Some(parent) => {
                if let Some(pn) = graph.find(&format!("proc:{parent}")).map(|x| x.id) {
                    graph.edge(pn, n, EdgeKind::Spawned, Vec::new());
                }
            }
            None => {
                if let Some(c) = cmd {
                    graph.edge(c, n, EdgeKind::Spawned, Vec::new());
                }
            }
        }
    }
    cmd
}

/// Observation node, linked from its process and to the resource it concerns.
pub(super) fn add_observation(
    graph: &mut CauseGraph,
    o: &Observation,
    input: &AnalysisInput<'_>,
) -> Option<NodeId> {
    let evidence: Vec<EvidenceRef> = o
        .events
        .iter()
        .map(|s| EvidenceRef::Event { seq: *s })
        .collect();
    let node = graph.node(
        NodeKind::Observation,
        format!("obs:{}", o.id),
        action_label(o),
        evidence.clone(),
    )?;
    let proc_key = if o.pid == 0 {
        input.tree.root.unwrap_or(0)
    } else {
        o.pid
    };
    let proc = graph
        .find(&format!("proc:{proc_key}"))
        .map(|n| n.id)
        .or_else(|| graph.find("command").map(|n| n.id));
    if let Some(p) = proc {
        graph.edge(p, node, EdgeKind::Attempted, evidence.clone());
    }
    let resource = match &o.kind {
        ObservationKind::ConnectFailed {
            endpoint: Endpoint::Inet { port, .. },
            ..
        }
        | ObservationKind::BindFailed {
            endpoint: Endpoint::Inet { port, .. },
            ..
        } => Some((NodeKind::Port, format!("port:{port}"), format!(":{port}"))),
        ObservationKind::ConnectFailed {
            endpoint: Endpoint::Unix { path },
            ..
        } => Some((NodeKind::Socket, format!("socket:{path}"), path.clone())),
        ObservationKind::FileAccessFailed { path, .. } => {
            Some((NodeKind::File, format!("file:{path}"), path.clone()))
        }
        ObservationKind::ExecFailed { executable, .. } => Some((
            NodeKind::Executable,
            format!("exe:{executable}"),
            executable.clone(),
        )),
        ObservationKind::DnsFailed { hostname, .. } => {
            Some((NodeKind::Host, format!("host:{hostname}"), hostname.clone()))
        }
        ObservationKind::LibraryLoadFailed { library, .. } => {
            Some((NodeKind::File, format!("lib:{library}"), library.clone()))
        }
        _ => None,
    };
    if let Some((k, key, label)) = resource {
        if let Some(r) = graph.node(k, key, label, Vec::new()) {
            graph.edge(node, r, EdgeKind::AssociatedWith, evidence);
        }
    }
    Some(node)
}

pub(super) fn action_label(o: &Observation) -> String {
    match &o.kind {
        ObservationKind::ConnectFailed { endpoint, .. } => format!("connect {endpoint}"),
        ObservationKind::BindFailed { endpoint, .. } => format!("bind {endpoint}"),
        ObservationKind::FileAccessFailed { path, op, .. } => format!("{op} {path}"),
        ObservationKind::ExecFailed { executable, .. } => format!("exec {executable}"),
        ObservationKind::DnsFailed { hostname, .. } => format!("resolve {hostname}"),
        ObservationKind::WriteFailed { target, .. } => {
            format!("write {}", target.as_deref().unwrap_or(""))
                .trim_end()
                .to_string()
        }
        ObservationKind::ResourceLimit { syscall, .. } => syscall.clone(),
        ObservationKind::LibraryLoadFailed { library, .. } => format!("load {library}"),
        ObservationKind::ProcessCrashed { executable, .. } => {
            format!(
                "run {}",
                executable.as_deref().map(basename).unwrap_or("process")
            )
        }
        ObservationKind::Runtime { subject, .. } => subject.clone(),
    }
}

pub(super) fn failure_label(o: &Observation) -> String {
    match &o.kind {
        ObservationKind::DnsFailed { rcode, .. } => rcode
            .map(|r| r.label())
            .unwrap_or_else(|| "no answer".into()),
        ObservationKind::LibraryLoadFailed { .. } => "not found".into(),
        ObservationKind::ProcessCrashed { signal, .. } => signal.clone(),
        ObservationKind::Runtime { code, .. } => code.clone(),
        k => k.error_code().unwrap_or_else(|| "failed".into()),
    }
}

/// The kernel-level statement of what was observed.
pub(super) fn observed_statement(o: &Observation) -> String {
    match &o.kind {
        ObservationKind::ConnectFailed {
            endpoint, error, ..
        } => {
            if error.is("ECONNREFUSED") {
                format!("Connection to {endpoint} was refused (ECONNREFUSED)")
            } else {
                format!(
                    "Connecting to {endpoint} failed: {} ({error})",
                    error.describe()
                )
            }
        }
        ObservationKind::BindFailed {
            endpoint, error, ..
        } => {
            format!("Binding {endpoint} failed: {} ({error})", error.describe())
        }
        ObservationKind::FileAccessFailed {
            path, op, error, ..
        } => {
            format!("{op}({path}) failed: {} ({error})", error.describe())
        }
        ObservationKind::ExecFailed {
            executable,
            error,
            attempts,
        } => {
            if attempts.len() > 1 {
                format!(
                    "Executing {executable} failed in {} locations: {} ({error})",
                    attempts.len(),
                    error.describe()
                )
            } else {
                format!(
                    "Executing {executable} failed: {} ({error})",
                    error.describe()
                )
            }
        }
        ObservationKind::DnsFailed { hostname, rcode } => match rcode {
            Some(r) => format!("DNS lookup for {hostname} returned {}", r.label()),
            None => format!("DNS lookup for {hostname} got no answer"),
        },
        ObservationKind::WriteFailed { target, error } => format!(
            "Writing {} failed: {} ({error})",
            target.as_deref().unwrap_or("output"),
            error.describe()
        ),
        ObservationKind::ResourceLimit { syscall, error } => {
            format!("{syscall}() failed: {} ({error})", error.describe())
        }
        ObservationKind::LibraryLoadFailed {
            library, searched, ..
        } => format!(
            "The dynamic loader looked for {library} in {} directories and found nothing",
            searched.len().max(1)
        ),
        ObservationKind::ProcessCrashed {
            signal,
            core_dumped,
            executable,
        } => format!(
            "{} was killed by {signal}{}",
            executable.as_deref().map(basename).unwrap_or("The process"),
            if *core_dumped { " (core dumped)" } else { "" }
        ),
        ObservationKind::Runtime { code, subject, .. } => format!("{code}: {subject}"),
    }
}

/// The line of program output that reported this observation.
pub(super) fn reported_line(input: &AnalysisInput<'_>, o: &Observation) -> Option<String> {
    let after = o.events.last().copied().unwrap_or(0);
    let tokens: Vec<String> = match &o.kind {
        ObservationKind::ConnectFailed { endpoint, .. } => match endpoint {
            Endpoint::Inet { port, .. } => vec![format!(":{port}"), format!("port {port}")],
            Endpoint::Unix { path } => vec![path.clone()],
        },
        ObservationKind::BindFailed {
            endpoint, error, ..
        } => {
            let mut v = vec![error.0.clone()];
            if let Some(p) = endpoint.port() {
                v.push(format!(":{p}"));
            }
            v
        }
        ObservationKind::FileAccessFailed {
            path, requested, ..
        } => {
            let mut v = vec![path.clone()];
            v.extend(requested.clone());
            v.push(basename(path).to_string());
            v
        }
        ObservationKind::ExecFailed { executable, .. } => vec![basename(executable).to_string()],
        ObservationKind::DnsFailed { hostname, .. } => vec![hostname.clone()],
        ObservationKind::LibraryLoadFailed { library, .. } => vec![library.clone()],
        ObservationKind::Runtime { subject, .. } => vec![subject.clone()],
        ObservationKind::WriteFailed { target, error } => {
            let mut v: Vec<String> = target
                .iter()
                .filter(|t| t.starts_with('/'))
                .cloned()
                .collect();
            v.push(error.describe().to_string());
            v
        }
        ObservationKind::ResourceLimit { error, .. } => {
            vec![error.describe().to_string(), error.0.clone()]
        }
        k => vec![k.error_code().unwrap_or_default()],
    };
    let since = (!o.events.is_empty()).then_some(after);
    for line in output_lines_after(input.events, since) {
        if tokens
            .iter()
            .any(|t| !t.is_empty() && contains_token(&line, t))
        {
            let l = line.trim();
            return Some(if l.chars().count() > 160 {
                l.chars().take(157).collect::<String>() + "..."
            } else {
                l.to_string()
            });
        }
    }
    None
}
