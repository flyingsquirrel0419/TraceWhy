use crate::ObservationId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracewhy_event::{DnsRcode, Endpoint, Errno, FileAccess, Protocol};

/// A failure symptom observed directly in the trace.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    pub id: ObservationId,
    pub kind: ObservationKind,
    /// Process (thread group) where the symptom was observed.
    pub pid: u32,
    /// Sequence numbers of the events that make up this observation.
    pub events: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<f64>,
    pub relevance: Relevance,
}

/// How strongly an observation is tied to the command's failure.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Relevance {
    /// Score in `[0, 1]`.
    pub score: f64,
    /// Process is on the failure-propagation chain.
    pub on_failure_chain: bool,
    /// The failing program reported this specific failure on stderr.
    pub reported_on_stderr: bool,
    /// The same operation later succeeded (the failure was recovered from).
    pub recovered: bool,
    /// Looked like a search-path probe (another candidate succeeded).
    pub probe: bool,
    /// Last failure of its process before the process exited.
    pub terminal: bool,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObservationKind {
    ExecFailed {
        executable: String,
        error: Errno,
        #[serde(default)]
        attempts: Vec<String>,
    },
    FileAccessFailed {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        requested: Option<String>,
        op: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        access: Option<FileAccess>,
        error: Errno,
    },
    ConnectFailed {
        endpoint: Endpoint,
        protocol: Protocol,
        error: Errno,
    },
    BindFailed {
        endpoint: Endpoint,
        protocol: Protocol,
        error: Errno,
    },
    DnsFailed {
        hostname: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rcode: Option<DnsRcode>,
    },
    WriteFailed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<String>,
        error: Errno,
    },
    ResourceLimit {
        syscall: String,
        error: Errno,
    },
    LibraryLoadFailed {
        library: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executable: Option<String>,
        #[serde(default)]
        searched: Vec<String>,
    },
    ProcessCrashed {
        signal: String,
        core_dumped: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executable: Option<String>,
    },
    /// Runtime-specific symptom contributed by a runtime adapter.
    Runtime {
        adapter: String,
        code: String,
        subject: String,
        #[serde(default)]
        detail: BTreeMap<String, String>,
    },
}

impl ObservationKind {
    /// Stable identifier used by rule triggers.
    pub fn name(&self) -> &'static str {
        match self {
            ObservationKind::ExecFailed { .. } => "exec_failed",
            ObservationKind::FileAccessFailed { .. } => "file_access_failed",
            ObservationKind::ConnectFailed { .. } => "connect_failed",
            ObservationKind::BindFailed { .. } => "bind_failed",
            ObservationKind::DnsFailed { .. } => "dns_failed",
            ObservationKind::WriteFailed { .. } => "write_failed",
            ObservationKind::ResourceLimit { .. } => "resource_limit",
            ObservationKind::LibraryLoadFailed { .. } => "library_load_failed",
            ObservationKind::ProcessCrashed { .. } => "process_crashed",
            ObservationKind::Runtime { .. } => "runtime",
        }
    }

    /// The error code that rule triggers match against.
    pub fn error_code(&self) -> Option<String> {
        match self {
            ObservationKind::ExecFailed { error, .. }
            | ObservationKind::FileAccessFailed { error, .. }
            | ObservationKind::ConnectFailed { error, .. }
            | ObservationKind::BindFailed { error, .. }
            | ObservationKind::WriteFailed { error, .. }
            | ObservationKind::ResourceLimit { error, .. } => Some(error.0.clone()),
            ObservationKind::DnsFailed { rcode, .. } => rcode.map(|r| r.label()),
            ObservationKind::ProcessCrashed { signal, .. } => Some(signal.clone()),
            ObservationKind::Runtime { code, .. } => Some(code.clone()),
            ObservationKind::LibraryLoadFailed { .. } => None,
        }
    }

    /// Short statement of what was observed, e.g. `connect 127.0.0.1:5432 → ECONNREFUSED`.
    pub fn describe(&self) -> String {
        match self {
            ObservationKind::ExecFailed {
                executable, error, ..
            } => format!("exec {executable} → {error}"),
            ObservationKind::FileAccessFailed {
                path, op, error, ..
            } => format!("{op} {path} → {error}"),
            ObservationKind::ConnectFailed {
                endpoint, error, ..
            } => format!("connect {endpoint} → {error}"),
            ObservationKind::BindFailed {
                endpoint, error, ..
            } => format!("bind {endpoint} → {error}"),
            ObservationKind::DnsFailed { hostname, rcode } => match rcode {
                Some(r) => format!("resolve {hostname} → {}", r.label()),
                None => format!("resolve {hostname} → no answer"),
            },
            ObservationKind::WriteFailed { target, error } => match target {
                Some(t) => format!("write {t} → {error}"),
                None => format!("write → {error}"),
            },
            ObservationKind::ResourceLimit { syscall, error } => format!("{syscall} → {error}"),
            ObservationKind::LibraryLoadFailed { library, .. } => {
                format!("load {library} → not found")
            }
            ObservationKind::ProcessCrashed {
                signal,
                core_dumped,
                ..
            } => {
                if *core_dumped {
                    format!("killed by {signal} (core dumped)")
                } else {
                    format!("killed by {signal}")
                }
            }
            ObservationKind::Runtime { code, subject, .. } => format!("{code}: {subject}"),
        }
    }
}
