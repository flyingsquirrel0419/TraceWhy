//! Indexes of successful operations, used to recognize failures that were
//! recovered from and search-path probes.

use super::text::basename;
use std::collections::{HashMap, HashSet};
use tracewhy_core::ObservationKind;
use tracewhy_event::{Endpoint, Event, EventKind, ProcessTree, Protocol};

/// Indexes of successful operations used to recognize recovered failures and probes.
pub(super) struct SuccessIndex {
    /// (process, path) → seqs of successful opens.
    opened: HashMap<String, Vec<(u32, u64)>>,
    opened_base: HashMap<(u32, String), Vec<u64>>,
    execs: HashMap<u32, Vec<(u64, String)>>,
    connected_port: HashMap<(u32, u16), Vec<u64>>,
    connected_unix: HashMap<String, Vec<u64>>,
    bound_port: HashMap<(u32, u16), Vec<u64>>,
    resolved: HashSet<String>,
    killed_by: HashMap<u32, u32>,
}

impl SuccessIndex {
    pub(super) fn build(events: &[Event], tree: &ProcessTree) -> Self {
        let mut s = SuccessIndex {
            opened: HashMap::new(),
            opened_base: HashMap::new(),
            execs: HashMap::new(),
            connected_port: HashMap::new(),
            connected_unix: HashMap::new(),
            bound_port: HashMap::new(),
            resolved: HashSet::new(),
            killed_by: HashMap::new(),
        };
        for e in events {
            let pid = e.process();
            match &e.kind {
                EventKind::FileOpened {
                    path, requested, ..
                } => {
                    s.opened.entry(path.clone()).or_default().push((pid, e.seq));
                    if let Some(r) = requested {
                        s.opened.entry(r.clone()).or_default().push((pid, e.seq));
                    }
                    s.opened_base
                        .entry((pid, basename(path).to_string()))
                        .or_default()
                        .push(e.seq);
                    if let Some(r) = requested {
                        s.opened_base
                            .entry((pid, basename(r).to_string()))
                            .or_default()
                            .push(e.seq);
                    }
                }
                EventKind::ProcessExec { executable, .. } => {
                    s.execs
                        .entry(pid)
                        .or_default()
                        .push((e.seq, executable.clone()));
                    // A forked child exec counts for the parent's PATH search too.
                    if let Some(parent) = tree.get(pid).and_then(|p| p.parent) {
                        s.execs
                            .entry(parent)
                            .or_default()
                            .push((e.seq, executable.clone()));
                    }
                }
                EventKind::Connected { endpoint, protocol } if *protocol != Protocol::Udp => {
                    match endpoint {
                        Endpoint::Inet { port, .. } => s
                            .connected_port
                            .entry((pid, *port))
                            .or_default()
                            .push(e.seq),
                        Endpoint::Unix { path } => s
                            .connected_unix
                            .entry(path.clone())
                            .or_default()
                            .push(e.seq),
                    }
                }
                EventKind::Bound { endpoint, .. } => {
                    if let Some(p) = endpoint.port() {
                        s.bound_port.entry((pid, p)).or_default().push(e.seq);
                    }
                }
                EventKind::DnsAnswer {
                    hostname,
                    addresses,
                    ..
                } if !addresses.is_empty() => {
                    s.resolved.insert(hostname.clone());
                }
                EventKind::SignalSent { target, signal }
                    if (signal == "SIGKILL" || signal == "SIGTERM") && *target > 0 =>
                {
                    s.killed_by.insert(*target as u32, pid);
                }
                _ => {}
            }
        }
        s
    }

    pub(super) fn exec_after(&self, pid: u32, seq: u64) -> bool {
        self.execs
            .get(&pid)
            .map(|v| v.iter().any(|(s, _)| *s > seq))
            .unwrap_or(false)
    }

    pub(super) fn exec_name_ok(&self, pid: u32, name: &str) -> bool {
        self.execs
            .get(&pid)
            .map(|v| v.iter().any(|(_, e)| basename(e) == name))
            .unwrap_or(false)
    }

    pub(super) fn opened_basename(&self, pid: u32, b: &str) -> bool {
        self.opened_base.contains_key(&(pid, b.to_string()))
    }

    pub(super) fn resolved(&self, host: &str) -> bool {
        self.resolved
            .iter()
            .any(|h| h == host || h.starts_with(&format!("{host}.")))
    }

    pub(super) fn recovered(&self, kind: &ObservationKind, pid: u32, seq: u64) -> bool {
        match kind {
            ObservationKind::FileAccessFailed {
                path, requested, ..
            } => {
                let hit = |p: &str| {
                    self.opened
                        .get(p)
                        .map(|v| v.iter().any(|(_, s)| *s > seq))
                        .unwrap_or(false)
                };
                hit(path) || requested.as_deref().map(hit).unwrap_or(false)
            }
            ObservationKind::ConnectFailed { endpoint, .. } => match endpoint {
                Endpoint::Inet { port, .. } => self
                    .connected_port
                    .get(&(pid, *port))
                    .map(|v| v.iter().any(|s| *s > seq))
                    .unwrap_or(false),
                Endpoint::Unix { path } => self
                    .connected_unix
                    .get(path)
                    .map(|v| v.iter().any(|s| *s > seq))
                    .unwrap_or(false),
            },
            ObservationKind::BindFailed { endpoint, .. } => endpoint
                .port()
                .and_then(|p| self.bound_port.get(&(pid, p)))
                .map(|v| v.iter().any(|s| *s > seq))
                .unwrap_or(false),
            ObservationKind::ExecFailed { .. } => self.exec_after(pid, seq),
            _ => false,
        }
    }

    pub(super) fn probe(&self, kind: &ObservationKind, pid: u32, seq: u64) -> bool {
        match kind {
            ObservationKind::FileAccessFailed { path, error, .. } if error.is("ENOENT") => {
                // Same file name found in a different directory later on.
                self.opened_base
                    .get(&(pid, basename(path).to_string()))
                    .map(|v| v.iter().any(|s| *s > seq))
                    .unwrap_or(false)
            }
            _ => false,
        }
    }
}
