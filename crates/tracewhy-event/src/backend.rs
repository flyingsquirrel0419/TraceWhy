//! The trace backend abstraction. A backend runs a command under observation
//! and returns semantic events; nothing downstream depends on how.

use crate::{Diagnostic, Event, ExitStatus, TraceStats};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The command to run, exactly as the user typed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    /// Send the command's stdout to our stderr (keeps `--json` stdout clean).
    #[serde(default)]
    pub stdout_to_stderr: bool,
}

impl CommandSpec {
    pub fn argv(&self) -> Vec<String> {
        let mut v = vec![self.program.clone()];
        v.extend(self.args.iter().cloned());
        v
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    pub processes: bool,
    pub files: bool,
    pub network: bool,
    pub dns_payloads: bool,
    pub output_capture: bool,
    pub timestamps: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackendInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub capabilities: BackendCapabilities,
}

/// Everything a backend produced for one run.
#[derive(Debug, Clone)]
pub struct TraceOutput {
    pub events: Vec<Event>,
    pub stats: TraceStats,
    pub diagnostics: Vec<Diagnostic>,
    /// Exit status of the traced command (from the trace, else from wait()).
    pub exit: Option<ExitStatus>,
    pub started_at: f64,
    pub duration_ms: u64,
    pub backend: BackendInfo,
}

#[derive(Debug)]
pub enum BackendError {
    /// The backend cannot work in this environment (tool missing, ptrace denied).
    Unsupported(String),
    Io(std::io::Error),
    Failed(String),
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::Unsupported(s) => write!(f, "{s}"),
            BackendError::Io(e) => write!(f, "I/O error: {e}"),
            BackendError::Failed(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for BackendError {}

impl From<std::io::Error> for BackendError {
    fn from(e: std::io::Error) -> Self {
        BackendError::Io(e)
    }
}

pub trait TraceBackend {
    fn info(&self) -> BackendInfo;
    fn run(&self, command: &CommandSpec) -> Result<TraceOutput, BackendError>;
}
