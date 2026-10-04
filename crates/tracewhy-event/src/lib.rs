//! Semantic runtime events.
//!
//! Trace backends (strace today; eBPF, ETW or macOS backends later) translate
//! their raw output into the backend-neutral [`Event`] stream defined here.
//! Everything after this layer — facts, hypotheses, the cause graph — only
//! ever sees semantic events, never raw backend text.

pub mod backend;
mod errno;
mod process;

pub use backend::{
    BackendCapabilities, BackendError, BackendInfo, CommandSpec, TraceBackend, TraceOutput,
};
pub use errno::Errno;
pub use process::{signal_name, signal_number, ExitStatus, ProcessInfo, ProcessTree};

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A single normalized runtime event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic sequence number, unique within a trace. Preserves backend order.
    pub seq: u64,
    /// Wall-clock timestamp (seconds since the Unix epoch), when the backend provides one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<f64>,
    /// Thread / process id that performed the action.
    pub pid: u32,
    /// Thread-group id (process id) when `pid` is a thread of another process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    /// Where in the raw backend output this event came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceRef>,
    pub kind: EventKind,
}

impl Event {
    /// The process (thread group) this event belongs to.
    pub fn process(&self) -> u32 {
        self.tgid.unwrap_or(self.pid)
    }

    /// True when the event records a failed operation.
    pub fn is_failure(&self) -> bool {
        self.kind.error().is_some()
            || matches!(
                self.kind,
                EventKind::ProcessKilled { .. }
                    | EventKind::DnsAnswer {
                        rcode: DnsRcode::NxDomain | DnsRcode::ServFail | DnsRcode::Refused,
                        ..
                    }
            )
    }
}

/// Reference back to the raw backend record (e.g. a strace line number).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRef {
    pub backend: String,
    pub line: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    Read,
    Write,
    ReadWrite,
    Directory,
    Path,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Unix,
    Other,
}

/// A network endpoint as seen by a connect/bind call.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum Endpoint {
    Inet { address: IpAddr, port: u16 },
    Unix { path: String },
}

impl Endpoint {
    pub fn port(&self) -> Option<u16> {
        match self {
            Endpoint::Inet { port, .. } => Some(*port),
            Endpoint::Unix { .. } => None,
        }
    }

    pub fn address(&self) -> Option<IpAddr> {
        match self {
            Endpoint::Inet { address, .. } => Some(*address),
            Endpoint::Unix { .. } => None,
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Inet {
                address: IpAddr::V6(a),
                port,
            } => write!(f, "[{a}]:{port}"),
            Endpoint::Inet {
                address: IpAddr::V4(a),
                port,
            } => write!(f, "{a}:{port}"),
            Endpoint::Unix { path } => write!(f, "unix:{path}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    Other(u8),
}

impl DnsRcode {
    pub fn from_code(code: u8) -> Self {
        match code {
            0 => DnsRcode::NoError,
            1 => DnsRcode::FormErr,
            2 => DnsRcode::ServFail,
            3 => DnsRcode::NxDomain,
            4 => DnsRcode::NotImp,
            5 => DnsRcode::Refused,
            n => DnsRcode::Other(n),
        }
    }

    pub fn label(&self) -> String {
        match self {
            DnsRcode::NoError => "NOERROR".into(),
            DnsRcode::FormErr => "FORMERR".into(),
            DnsRcode::ServFail => "SERVFAIL".into(),
            DnsRcode::NxDomain => "NXDOMAIN".into(),
            DnsRcode::NotImp => "NOTIMP".into(),
            DnsRcode::Refused => "REFUSED".into(),
            DnsRcode::Other(n) => format!("RCODE{n}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

/// What happened. Variants are deliberately backend-neutral.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// A new process or thread was created by `pid`.
    ProcessSpawned {
        child: u32,
        thread: bool,
    },
    /// `pid` successfully replaced its image.
    ProcessExec {
        executable: String,
        args: Vec<String>,
    },
    /// An exec attempt failed (including PATH search attempts by shells).
    ExecFailed {
        executable: String,
        args: Vec<String>,
        error: Errno,
    },
    ProcessExited {
        code: i32,
    },
    ProcessKilled {
        signal: String,
        core_dumped: bool,
    },
    SignalReceived {
        signal: String,
    },
    /// `pid` sent `signal` to `target`.
    SignalSent {
        target: i64,
        signal: String,
    },
    FileOpened {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested: Option<String>,
        access: FileAccess,
    },
    FileOpenFailed {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested: Option<String>,
        access: FileAccess,
        error: Errno,
    },
    /// A non-open path operation (stat, access, mkdir, unlink, rename, ...) failed.
    PathOpFailed {
        op: String,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested: Option<String>,
        error: Errno,
    },
    ChangedDirectory {
        path: String,
    },
    ConnectPending {
        endpoint: Endpoint,
        protocol: Protocol,
    },
    Connected {
        endpoint: Endpoint,
        protocol: Protocol,
    },
    ConnectFailed {
        endpoint: Endpoint,
        protocol: Protocol,
        error: Errno,
    },
    Bound {
        endpoint: Endpoint,
        protocol: Protocol,
    },
    BindFailed {
        endpoint: Endpoint,
        protocol: Protocol,
        error: Errno,
    },
    Listening {
        endpoint: Option<Endpoint>,
    },
    DnsQuery {
        hostname: String,
        qtype: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server: Option<Endpoint>,
    },
    DnsAnswer {
        hostname: String,
        qtype: String,
        rcode: DnsRcode,
        addresses: Vec<IpAddr>,
    },
    /// Text written to stdout/stderr (truncated by the backend).
    Output {
        stream: OutputStream,
        text: String,
    },
    WriteFailed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        error: Errno,
    },
    /// Any other failed syscall with a diagnostically interesting errno.
    SyscallFailed {
        syscall: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
        error: Errno,
    },
}

impl EventKind {
    pub fn error(&self) -> Option<&Errno> {
        match self {
            EventKind::ExecFailed { error, .. }
            | EventKind::FileOpenFailed { error, .. }
            | EventKind::PathOpFailed { error, .. }
            | EventKind::ConnectFailed { error, .. }
            | EventKind::BindFailed { error, .. }
            | EventKind::WriteFailed { error, .. }
            | EventKind::SyscallFailed { error, .. } => Some(error),
            _ => None,
        }
    }

    /// Stable short name of the variant, used by rules and diffs.
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::ProcessSpawned { .. } => "process_spawned",
            EventKind::ProcessExec { .. } => "process_exec",
            EventKind::ExecFailed { .. } => "exec_failed",
            EventKind::ProcessExited { .. } => "process_exited",
            EventKind::ProcessKilled { .. } => "process_killed",
            EventKind::SignalReceived { .. } => "signal_received",
            EventKind::SignalSent { .. } => "signal_sent",
            EventKind::FileOpened { .. } => "file_opened",
            EventKind::FileOpenFailed { .. } => "file_open_failed",
            EventKind::PathOpFailed { .. } => "path_op_failed",
            EventKind::ChangedDirectory { .. } => "changed_directory",
            EventKind::ConnectPending { .. } => "connect_pending",
            EventKind::Connected { .. } => "connected",
            EventKind::ConnectFailed { .. } => "connect_failed",
            EventKind::Bound { .. } => "bound",
            EventKind::BindFailed { .. } => "bind_failed",
            EventKind::Listening { .. } => "listening",
            EventKind::DnsQuery { .. } => "dns_query",
            EventKind::DnsAnswer { .. } => "dns_answer",
            EventKind::Output { .. } => "output",
            EventKind::WriteFailed { .. } => "write_failed",
            EventKind::SyscallFailed { .. } => "syscall_failed",
        }
    }
}

/// Counters describing how much raw data was condensed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceStats {
    pub raw_lines: u64,
    pub raw_bytes: u64,
    pub raw_events: u64,
    pub semantic_events: u64,
    pub dropped_events: u64,
    pub unparsed_lines: u64,
    pub processes: u64,
    #[serde(default)]
    pub truncated: bool,
}

/// Non-fatal problems encountered while reading a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub line: Option<u64>,
    pub message: String,
}
