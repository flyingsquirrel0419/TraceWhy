mod describe;

pub use describe::human_bytes;

use crate::FactId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::IpAddr;

/// Something known to be true about the system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    pub id: FactId,
    pub kind: FactKind,
    pub source: FactSource,
    /// Unix time (seconds) at which the fact was collected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<f64>,
    pub freshness: Freshness,
    /// How reliable the collection method is, in `[0, 1]`.
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FactSource {
    /// Derived from trace events.
    Trace { events: Vec<u64> },
    /// Collected by an investigator after the command finished.
    Investigator { id: String },
    /// Collected by a runtime adapter.
    Adapter { id: String },
    /// Collected before the command ran (e.g. resolving the executable).
    Preflight,
}

impl FactSource {
    pub fn label(&self) -> String {
        match self {
            FactSource::Trace { .. } => "trace".into(),
            FactSource::Investigator { id } => format!("investigator:{id}"),
            FactSource::Adapter { id } => format!("adapter:{id}"),
            FactSource::Preflight => "preflight".into(),
        }
    }
}

/// Whether the fact describes the moment of failure or the state afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Freshness {
    AtFailure,
    AfterRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    pub address: IpAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessCheck {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecCandidate {
    pub path: String,
    pub exists: bool,
    pub executable: bool,
    #[serde(default)]
    pub broken_symlink: bool,
    #[serde(default)]
    pub is_dir: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LibraryCandidate {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<String>,
    pub compatible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_port: Option<u16>,
    pub container_port: u16,
    #[serde(default = "default_tcp")]
    pub protocol: String,
}

fn default_tcp() -> String {
    "tcp".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComposeService {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default)]
    pub ports: Vec<PortMapping>,
    #[serde(default)]
    pub expose: Vec<u16>,
    #[serde(default)]
    pub healthcheck: bool,
}

/// Typed facts. Each variant is a self-contained statement about the system.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FactKind {
    PortListeners {
        port: u16,
        listeners: Vec<Listener>,
    },
    PathStatus {
        path: String,
        exists: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file_type: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        uid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        owner: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        symlink_target: Option<String>,
        #[serde(default)]
        broken_symlink: bool,
        /// Access as the current user (as checked by `access(2)`).
        #[serde(default)]
        access: AccessCheck,
        /// The user the access check ran as (`name (uid N)`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        checked_as: Option<String>,
    },
    NearestExistingAncestor {
        path: String,
        ancestor: String,
    },
    AncestorNotSearchable {
        path: String,
        ancestor: String,
    },
    ExecutableSearch {
        name: String,
        path_dirs: Vec<String>,
        candidates: Vec<ExecCandidate>,
        /// Usable copies found outside PATH (project-local bin dirs etc.).
        #[serde(default)]
        elsewhere: Vec<String>,
    },
    ScriptInterpreter {
        script: String,
        interpreter: String,
        interpreter_exists: bool,
    },
    ElfInfo {
        path: String,
        class: u8,
        machine: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        interpreter: Option<String>,
        #[serde(default)]
        needed: Vec<String>,
        #[serde(default)]
        runpath: Vec<String>,
    },
    NotElf {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        magic: Option<String>,
    },
    HostArchitecture {
        machine: String,
    },
    Filesystem {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mount_point: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fs_type: Option<String>,
        read_only: bool,
        #[serde(default)]
        noexec: bool,
        total_bytes: u64,
        avail_bytes: u64,
        total_inodes: u64,
        free_inodes: u64,
    },
    DnsResolution {
        hostname: String,
        addresses: Vec<IpAddr>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    ResolverConfig {
        nameservers: Vec<String>,
        search: Vec<String>,
    },
    LibrarySearch {
        library: String,
        search_dirs: Vec<String>,
        found: Vec<LibraryCandidate>,
        #[serde(default)]
        found_elsewhere: Vec<String>,
    },
    FdLimit {
        soft: u64,
        hard: u64,
    },
    DefaultRoute {
        ipv4: bool,
        ipv6: bool,
    },
    LocalAddresses {
        addresses: Vec<IpAddr>,
    },
    DockerStatus {
        cli: bool,
        daemon: bool,
        compose: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
    ComposeProject {
        file: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
        services: Vec<ComposeService>,
    },
    ContainerState {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        project: Option<String>,
        service: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container: Option<String>,
        /// running, exited, restarting, created, paused, dead or absent.
        state: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        health: Option<String>,
        #[serde(default)]
        published: Vec<PortMapping>,
        #[serde(default)]
        oom_killed: bool,
    },
    ContainerLogs {
        container: String,
        lines: Vec<String>,
    },
    OutputExcerpt {
        pid: u32,
        text: String,
    },
    RuntimeInfo {
        runtime: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<String>,
        #[serde(default)]
        details: BTreeMap<String, String>,
    },
    /// Adapter-specific fact with a stable key.
    Property {
        key: String,
        subject: String,
        value: String,
        description: String,
    },
}

impl FactKind {
    pub fn name(&self) -> &'static str {
        match self {
            FactKind::PortListeners { .. } => "port_listeners",
            FactKind::PathStatus { .. } => "path_status",
            FactKind::NearestExistingAncestor { .. } => "nearest_existing_ancestor",
            FactKind::AncestorNotSearchable { .. } => "ancestor_not_searchable",
            FactKind::ExecutableSearch { .. } => "executable_search",
            FactKind::ScriptInterpreter { .. } => "script_interpreter",
            FactKind::ElfInfo { .. } => "elf_info",
            FactKind::NotElf { .. } => "not_elf",
            FactKind::HostArchitecture { .. } => "host_architecture",
            FactKind::Filesystem { .. } => "filesystem",
            FactKind::DnsResolution { .. } => "dns_resolution",
            FactKind::ResolverConfig { .. } => "resolver_config",
            FactKind::LibrarySearch { .. } => "library_search",
            FactKind::FdLimit { .. } => "fd_limit",
            FactKind::DefaultRoute { .. } => "default_route",
            FactKind::LocalAddresses { .. } => "local_addresses",
            FactKind::DockerStatus { .. } => "docker_status",
            FactKind::ComposeProject { .. } => "compose_project",
            FactKind::ContainerState { .. } => "container_state",
            FactKind::ContainerLogs { .. } => "container_logs",
            FactKind::OutputExcerpt { .. } => "output_excerpt",
            FactKind::RuntimeInfo { .. } => "runtime_info",
            FactKind::Property { .. } => "property",
        }
    }

    /// Key identifying the subject of the fact; a newer fact with the same key
    /// supersedes an older one.
    pub fn subject_key(&self) -> String {
        let subject = match self {
            FactKind::PortListeners { port, .. } => port.to_string(),
            FactKind::PathStatus { path, .. }
            | FactKind::NearestExistingAncestor { path, .. }
            | FactKind::AncestorNotSearchable { path, .. }
            | FactKind::ElfInfo { path, .. }
            | FactKind::NotElf { path, .. }
            | FactKind::Filesystem { path, .. } => path.clone(),
            FactKind::ExecutableSearch { name, .. } => name.clone(),
            FactKind::ScriptInterpreter { script, .. } => script.clone(),
            FactKind::DnsResolution { hostname, .. } => hostname.clone(),
            FactKind::LibrarySearch { library, .. } => library.clone(),
            FactKind::ComposeProject { file, .. } => file.clone(),
            FactKind::ContainerState { service, .. } => service.clone(),
            FactKind::ContainerLogs { container, .. } => container.clone(),
            FactKind::OutputExcerpt { pid, .. } => pid.to_string(),
            FactKind::RuntimeInfo { runtime, .. } => runtime.clone(),
            FactKind::Property { key, subject, .. } => format!("{key}:{subject}"),
            _ => String::new(),
        };
        format!("{}:{}", self.name(), subject)
    }
}
