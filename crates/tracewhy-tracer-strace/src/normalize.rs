//! Turns parsed strace records into semantic [`Event`]s.
//!
//! The normalizer tracks just enough per-process state to make events
//! meaningful on their own: thread groups, working directories, and a small
//! socket table (protocol, pending non-blocking connects, bound address).

mod io;
mod limits;
mod net;
mod paths;
mod util;

pub use limits::NormalizeLimits;
pub use paths::lexical_normalize;
use util::{is_essential, protocol_from};

use crate::args::{parse_fd, parse_sockaddr, parse_string, parse_string_array, split_args};
use crate::parse::{LineParser, LineResult, RawKind, RawRecord, Syscall};
use std::collections::HashMap;
use tracewhy_event::{
    Diagnostic, Endpoint, Errno, Event, EventKind, Protocol, SourceRef, TraceStats,
};

#[derive(Debug, Default)]
struct SockState {
    protocol: Option<Protocol>,
    pending: Option<Endpoint>,
    bound: Option<Endpoint>,
    peer: Option<Endpoint>,
}

#[derive(Debug, Default)]
pub struct NormalizedTrace {
    pub events: Vec<Event>,
    pub stats: TraceStats,
    pub diagnostics: Vec<Diagnostic>,
}

/// Streaming normalizer: feed lines, then call [`Normalizer::finish`].
pub struct Normalizer {
    parser: LineParser,
    limits: NormalizeLimits,
    events: Vec<Option<Event>>,
    seq: u64,
    tgid: HashMap<u32, u32>,
    cwd: HashMap<u32, String>,
    socks: HashMap<(u32, i64), SockState>,
    outputs: HashMap<u32, (usize, std::collections::VecDeque<usize>)>,
    stats: TraceStats,
    diagnostics: Vec<Diagnostic>,
    live: usize,
}

impl Normalizer {
    pub fn new(limits: NormalizeLimits) -> Self {
        Normalizer {
            parser: LineParser::new(),
            limits,
            events: Vec::new(),
            seq: 0,
            tgid: HashMap::new(),
            cwd: HashMap::new(),
            socks: HashMap::new(),
            outputs: HashMap::new(),
            stats: TraceStats::default(),
            diagnostics: Vec::new(),
            live: 0,
        }
    }

    pub fn set_initial_cwd(&mut self, pid: u32, cwd: &str) {
        self.cwd.insert(pid, cwd.to_string());
    }

    pub fn feed_line(&mut self, line_no: u64, line: &str) {
        self.stats.raw_lines += 1;
        self.stats.raw_bytes += line.len() as u64 + 1;
        match self.parser.parse_line(line_no, line) {
            LineResult::Record(r) => {
                self.stats.raw_events += 1;
                self.handle(r);
            }
            LineResult::Pending | LineResult::Ignored => {}
            LineResult::Unparsed(l) => {
                self.stats.unparsed_lines += 1;
                if self.diagnostics.len() < self.limits.max_diagnostics {
                    let mut msg: String = l.chars().take(160).collect();
                    msg.insert_str(0, "unrecognized strace line: ");
                    self.diagnostics.push(Diagnostic {
                        line: Some(line_no),
                        message: msg,
                    });
                }
            }
        }
    }

    pub fn finish(mut self) -> NormalizedTrace {
        if self.parser.pending_count() > 0 && self.diagnostics.len() < self.limits.max_diagnostics {
            self.diagnostics.push(Diagnostic {
                line: None,
                message: format!(
                    "{} syscalls never completed (process killed or trace truncated)",
                    self.parser.pending_count()
                ),
            });
        }
        let events: Vec<Event> = self.events.into_iter().flatten().collect();
        self.stats.semantic_events = events.len() as u64;
        let mut pids: Vec<u32> = events.iter().map(|e| e.process()).collect();
        pids.sort_unstable();
        pids.dedup();
        self.stats.processes = pids.len() as u64;
        NormalizedTrace {
            events,
            stats: self.stats,
            diagnostics: self.diagnostics,
        }
    }

    fn group(&self, pid: u32) -> u32 {
        *self.tgid.get(&pid).unwrap_or(&pid)
    }

    fn push(&mut self, rec: &RawRecord, kind: EventKind) {
        let pid = rec.pid.unwrap_or(0);
        let group = self.group(pid);
        let essential = is_essential(&kind);
        if self.live >= self.limits.max_events
            && (!essential || self.live >= self.limits.max_events.saturating_mul(2))
        {
            self.stats.dropped_events += 1;
            self.stats.truncated = true;
            return;
        }
        let is_output = matches!(kind, EventKind::Output { .. });
        let out_len = match &kind {
            EventKind::Output { text, .. } => text.len(),
            _ => 0,
        };
        let ev = Event {
            seq: self.seq,
            ts: rec.ts,
            pid,
            tgid: (group != pid).then_some(group),
            source: Some(SourceRef {
                backend: "strace".into(),
                line: rec.line,
            }),
            kind,
        };
        self.seq += 1;
        let idx = self.events.len();
        self.events.push(Some(ev));
        self.live += 1;
        if is_output {
            let budget = self.limits.max_output_bytes_per_process;
            let entry = self.outputs.entry(group).or_default();
            entry.0 += out_len;
            entry.1.push_back(idx);
            // Keep only the most recent output of each process.
            while entry.0 > budget && entry.1.len() > 1 {
                let Some(old) = entry.1.pop_front() else {
                    break;
                };
                if let Some(Some(Event {
                    kind: EventKind::Output { text, .. },
                    ..
                })) = self.events.get(old)
                {
                    entry.0 = entry.0.saturating_sub(text.len());
                }
                if let Some(slot) = self.events.get_mut(old) {
                    *slot = None;
                    self.live = self.live.saturating_sub(1);
                    self.stats.dropped_events += 1;
                }
            }
        }
    }

    fn handle(&mut self, rec: RawRecord) {
        let pid = rec.pid.unwrap_or(0);
        match &rec.kind {
            RawKind::Exited { code } => self.push(&rec, EventKind::ProcessExited { code: *code }),
            RawKind::Killed {
                signal,
                core_dumped,
            } => self.push(
                &rec,
                EventKind::ProcessKilled {
                    signal: signal.clone(),
                    core_dumped: *core_dumped,
                },
            ),
            RawKind::Signal { name } => {
                if !matches!(name.as_str(), "SIGCHLD" | "SIGWINCH" | "SIGURG" | "SIGIO") {
                    self.push(
                        &rec,
                        EventKind::SignalReceived {
                            signal: name.clone(),
                        },
                    );
                }
            }
            RawKind::Syscall(sc) => {
                let sc = sc.clone();
                self.syscall(&rec, pid, &sc);
            }
        }
    }

    fn resolve_path(&self, pid: u32, dirfd: Option<&str>, path: &str) -> String {
        if path.starts_with('/') {
            return lexical_normalize(path);
        }
        let base = match dirfd.and_then(parse_fd) {
            Some(fd) => match (fd.fd, fd.annotation) {
                (_, Some(a)) if a.starts_with('/') => Some(a),
                (None, None) => self.cwd.get(&self.group(pid)).cloned(),
                _ => None,
            },
            None => self.cwd.get(&self.group(pid)).cloned(),
        };
        match base {
            Some(b) if path.is_empty() => b,
            Some(b) => lexical_normalize(&format!("{b}/{path}")),
            None => path.to_string(),
        }
    }

    fn note_cwd_from(&mut self, pid: u32, dirfd_arg: &str) {
        if let Some(fd) = parse_fd(dirfd_arg) {
            if fd.fd.is_none() {
                if let Some(a) = fd.annotation {
                    if a.starts_with('/') {
                        let g = self.group(pid);
                        self.cwd.insert(g, a);
                    }
                }
            }
        }
    }

    fn syscall(&mut self, rec: &RawRecord, pid: u32, sc: &Syscall) {
        let args = split_args(&sc.args);
        let err = sc.ret.errno.clone().map(Errno::new);
        let name = sc.name.as_str();
        match name {
            "execve" | "execveat" => {
                let (pi, ai) = if name == "execveat" { (1, 2) } else { (0, 1) };
                let Some(path) = args.get(pi).and_then(|a| parse_string(a)) else {
                    return;
                };
                let argv = args
                    .get(ai)
                    .map(|a| parse_string_array(a))
                    .unwrap_or_default();
                let executable = self.resolve_path(pid, None, &path);
                match err {
                    None if sc.ret.value == Some(0) => self.push(
                        rec,
                        EventKind::ProcessExec {
                            executable,
                            args: argv,
                        },
                    ),
                    Some(error) => self.push(
                        rec,
                        EventKind::ExecFailed {
                            executable,
                            args: argv,
                            error,
                        },
                    ),
                    None => {}
                }
            }
            "fork" | "vfork" | "clone" | "clone2" | "clone3" => match (sc.ret.value, err) {
                (Some(child), None) if child > 0 => {
                    let thread = sc.args.contains("CLONE_THREAD");
                    let child = child as u32;
                    if thread {
                        let g = self.group(pid);
                        self.tgid.insert(child, g);
                    } else if let Some(c) = self.cwd.get(&self.group(pid)).cloned() {
                        self.cwd.insert(child, c);
                    }
                    self.push(rec, EventKind::ProcessSpawned { child, thread });
                }
                (_, Some(error)) => self.push(
                    rec,
                    EventKind::SyscallFailed {
                        syscall: name.to_string(),
                        detail: None,
                        error,
                    },
                ),
                _ => {}
            },
            "open" | "openat" | "openat2" | "creat" => self.open_like(rec, pid, sc, &args, err),
            "chdir" => {
                let Some(p) = args.first().and_then(|a| parse_string(a)) else {
                    return;
                };
                let path = self.resolve_path(pid, None, &p);
                match err {
                    None => {
                        let g = self.group(pid);
                        self.cwd.insert(g, path.clone());
                        self.push(rec, EventKind::ChangedDirectory { path });
                    }
                    Some(error) => self.push(
                        rec,
                        EventKind::PathOpFailed {
                            op: "chdir".into(),
                            path,
                            requested: Some(p),
                            error,
                        },
                    ),
                }
            }
            "fchdir" => {
                if err.is_none() {
                    if let Some(a) = args
                        .first()
                        .and_then(|a| parse_fd(a))
                        .and_then(|f| f.annotation)
                    {
                        if a.starts_with('/') {
                            let g = self.group(pid);
                            self.cwd.insert(g, a.clone());
                            self.push(rec, EventKind::ChangedDirectory { path: a });
                        }
                    }
                }
            }
            "socket" => {
                if let (Some(fd), None) = (sc.ret.value, &err) {
                    let protocol =
                        protocol_from(sc.ret.annotation.as_deref().unwrap_or(""), &sc.args);
                    let g = self.group(pid);
                    self.socks.insert(
                        (g, fd),
                        SockState {
                            protocol: Some(protocol),
                            ..SockState::default()
                        },
                    );
                } else if let Some(error) = err {
                    self.push(
                        rec,
                        EventKind::SyscallFailed {
                            syscall: "socket".into(),
                            detail: None,
                            error,
                        },
                    );
                }
            }
            "connect" => self.connect(rec, pid, sc, &args, err),
            "getsockopt" => {
                if args.get(2).map(|a| a.trim()) != Some("SO_ERROR") {
                    return;
                }
                let Some(fd) = args.first().and_then(|a| parse_fd(a)).and_then(|f| f.fd) else {
                    return;
                };
                let g = self.group(pid);
                let Some(st) = self.socks.get_mut(&(g, fd)) else {
                    return;
                };
                let Some(endpoint) = st.pending.take() else {
                    return;
                };
                let protocol = st.protocol.unwrap_or(Protocol::Tcp);
                let val = args
                    .get(3)
                    .map(|a| {
                        a.trim()
                            .trim_start_matches('[')
                            .trim_end_matches(']')
                            .to_string()
                    })
                    .unwrap_or_default();
                if val == "0" {
                    st.peer = Some(endpoint.clone());
                    self.push(rec, EventKind::Connected { endpoint, protocol });
                } else if val.starts_with('E') {
                    self.push(
                        rec,
                        EventKind::ConnectFailed {
                            endpoint,
                            protocol,
                            error: Errno::new(val),
                        },
                    );
                }
            }
            "bind" => {
                let Some(endpoint) = args.get(1).and_then(|a| parse_sockaddr(a)) else {
                    return;
                };
                let fdarg = args.first().and_then(|a| parse_fd(a));
                let g = self.group(pid);
                let protocol = self.sock_protocol(g, fdarg.as_ref());
                match err {
                    None => {
                        if let Some(fd) = fdarg.and_then(|f| f.fd) {
                            self.socks.entry((g, fd)).or_default().bound = Some(endpoint.clone());
                        }
                        self.push(rec, EventKind::Bound { endpoint, protocol });
                    }
                    Some(error) => self.push(
                        rec,
                        EventKind::BindFailed {
                            endpoint,
                            protocol,
                            error,
                        },
                    ),
                }
            }
            "listen" => {
                let fdarg = args.first().and_then(|a| parse_fd(a));
                let g = self.group(pid);
                match err {
                    None => {
                        let endpoint = fdarg
                            .and_then(|f| f.fd)
                            .and_then(|fd| self.socks.get(&(g, fd)))
                            .and_then(|s| s.bound.clone());
                        self.push(rec, EventKind::Listening { endpoint });
                    }
                    Some(error) => self.push(
                        rec,
                        EventKind::SyscallFailed {
                            syscall: "listen".into(),
                            detail: None,
                            error,
                        },
                    ),
                }
            }
            "sendto" | "sendmsg" | "sendmmsg" | "recvfrom" | "recvmsg" | "recvmmsg" => {
                self.maybe_dns(rec, pid, sc, &args);
                if let Some(error) = err.filter(|e| e.is_diagnostic()) {
                    self.push(
                        rec,
                        EventKind::SyscallFailed {
                            syscall: name.to_string(),
                            detail: args
                                .first()
                                .and_then(|a| parse_fd(a))
                                .and_then(|f| f.annotation),
                            error,
                        },
                    );
                }
            }
            "write" | "writev" | "pwrite64" | "pwritev" | "pwritev2" => {
                self.write_like(rec, pid, sc, &args, err)
            }
            "kill" | "tkill" | "tgkill" => {
                if err.is_some() {
                    return;
                }
                let (ti, si) = if name == "tgkill" { (1, 2) } else { (0, 1) };
                let target: Option<i64> = args.get(ti).and_then(|a| a.trim().parse().ok());
                let signal = args
                    .get(si)
                    .map(|s| s.trim().to_string())
                    .unwrap_or_default();
                if let Some(target) = target {
                    if signal.starts_with("SIG") && signal != "SIGCHLD" {
                        self.push(rec, EventKind::SignalSent { target, signal });
                    }
                }
            }
            _ => self.path_op(rec, pid, sc, &args, err),
        }
    }
}

/// Normalize a whole trace held in memory.
pub fn normalize_str(text: &str, limits: NormalizeLimits) -> NormalizedTrace {
    let mut n = Normalizer::new(limits);
    for (i, line) in text.lines().enumerate() {
        n.feed_line(i as u64 + 1, line);
    }
    n.finish()
}

#[cfg(test)]
mod tests;
