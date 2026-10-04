use crate::{Fact, FactId, FactKind, Limits};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Instant;
use tracewhy_event::{Event, ProcessTree};

/// What an investigation should look at.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvestigationTarget {
    Port {
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<IpAddr>,
    },
    Path {
        path: String,
    },
    Executable {
        name: String,
    },
    Hostname {
        name: String,
    },
    Library {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executable: Option<String>,
    },
    Filesystem {
        path: String,
    },
    Elf {
        path: String,
    },
    /// Look for container services related to a port.
    Docker {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    ContainerLogs {
        container: String,
    },
    FdLimit,
    Network,
    /// Effective user, capabilities and privilege-related kernel settings,
    /// plus file capabilities of the executable that failed.
    Privileges {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        executable: Option<String>,
    },
}

impl InvestigationTarget {
    pub fn describe(&self) -> String {
        match self {
            InvestigationTarget::Port { port, .. } => format!("port {port}"),
            InvestigationTarget::Path { path } => path.clone(),
            InvestigationTarget::Executable { name } => format!("executable {name}"),
            InvestigationTarget::Hostname { name } => format!("hostname {name}"),
            InvestigationTarget::Library { name, .. } => format!("library {name}"),
            InvestigationTarget::Filesystem { path } => format!("filesystem of {path}"),
            InvestigationTarget::Elf { path } => format!("ELF {path}"),
            InvestigationTarget::Docker { port } => match port {
                Some(p) => format!("docker services for port {p}"),
                None => "docker services".into(),
            },
            InvestigationTarget::ContainerLogs { container } => format!("logs of {container}"),
            InvestigationTarget::FdLimit => "file descriptor limit".into(),
            InvestigationTarget::Network => "network configuration".into(),
            InvestigationTarget::Privileges { .. } => "process privileges".into(),
        }
    }
}

/// Relative cost of running an investigator.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct InvestigationCost {
    /// Rough expected runtime.
    pub expected_millis: u32,
    /// Spawns external processes (docker, etc.).
    pub external_process: bool,
}

impl InvestigationCost {
    pub const CHEAP: InvestigationCost = InvestigationCost {
        expected_millis: 2,
        external_process: false,
    };

    /// Unitless weight used when ranking investigations.
    pub fn weight(&self) -> f64 {
        let base = 1.0 + f64::from(self.expected_millis) / 50.0;
        if self.external_process {
            base * 2.0
        } else {
            base
        }
    }
}

/// Snapshot of the environment the traced command ran with.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSnapshot {
    pub vars: BTreeMap<String, String>,
}

impl EnvSnapshot {
    pub fn from_current() -> Self {
        let vars = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        EnvSnapshot { vars }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(|s| s.as_str())
    }

    pub fn path_dirs(&self) -> Vec<String> {
        self.get("PATH")
            .unwrap_or("/usr/local/bin:/usr/bin:/bin")
            .split(':')
            .map(|d| {
                if d.is_empty() {
                    ".".to_string()
                } else {
                    d.to_string()
                }
            })
            .collect()
    }
}

/// Everything an investigator may consult. Investigators must not mutate the system.
pub struct InvestigationContext<'a> {
    pub target: &'a InvestigationTarget,
    pub cwd: PathBuf,
    pub env: &'a EnvSnapshot,
    pub facts: &'a [Fact],
    pub events: &'a [Event],
    pub tree: &'a ProcessTree,
    pub limits: &'a Limits,
    pub deadline: Instant,
}

impl InvestigationContext<'_> {
    pub fn time_left(&self) -> std::time::Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvestigationError {
    /// The investigator cannot run here (e.g. Docker not installed).
    Unavailable(String),
    Failed(String),
    TimedOut,
}

impl std::fmt::Display for InvestigationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvestigationError::Unavailable(s) => write!(f, "unavailable: {s}"),
            InvestigationError::Failed(s) => write!(f, "failed: {s}"),
            InvestigationError::TimedOut => write!(f, "timed out"),
        }
    }
}

impl std::error::Error for InvestigationError {}

/// An active probe of the system that turns a question into facts.
pub trait Investigator: Send + Sync {
    /// Stable identifier, shown in reports. Rules name investigation
    /// *targets* (e.g. `hostname`); every investigator supporting a target runs.
    fn id(&self) -> &'static str;
    fn supports(&self, target: &InvestigationTarget) -> bool;
    fn cost(&self, target: &InvestigationTarget) -> InvestigationCost;
    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationStatus {
    Completed,
    Unavailable,
    Failed,
    TimedOut,
    Skipped,
}

/// Audit record of one investigator execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvestigationRecord {
    pub investigator: String,
    pub target: InvestigationTarget,
    pub round: u32,
    pub status: InvestigationStatus,
    pub duration_ms: u64,
    #[serde(default)]
    pub facts: Vec<FactId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
