//! Human-readable statements of facts.

use super::{ExecCandidate, FactKind};
use std::net::IpAddr;

impl FactKind {
    /// Human-readable statement of the fact.
    pub fn describe(&self) -> String {
        match self {
            FactKind::PortListeners { port, listeners } => {
                if listeners.is_empty() {
                    format!("No process is listening on port {port}")
                } else {
                    let who: Vec<String> = listeners
                        .iter()
                        .map(|l| {
                            let addr = match l.address {
                                IpAddr::V6(a) => format!("[{a}]"),
                                IpAddr::V4(a) => a.to_string(),
                            };
                            match (&l.executable, l.pid) {
                                (Some(e), Some(p)) => format!(
                                    "{} (pid {p}) on {addr}",
                                    e.rsplit('/').next().unwrap_or(e)
                                ),
                                (None, Some(p)) => format!("pid {p} on {addr}"),
                                _ => format!("an unidentified process on {addr}"),
                            }
                        })
                        .collect();
                    format!("Port {port} is held by {}", who.join(", "))
                }
            }
            FactKind::PathStatus {
                path,
                exists,
                broken_symlink,
                mode,
                owner,
                access,
                file_type,
                ..
            } => {
                if *broken_symlink {
                    format!("{path} is a broken symbolic link")
                } else if !exists {
                    format!("{path} does not exist")
                } else {
                    let mut s =
                        format!("{path} exists ({}", file_type.as_deref().unwrap_or("file"));
                    if let Some(m) = mode {
                        s.push_str(&format!(", mode {:o}", m & 0o7777));
                    }
                    if let Some(o) = owner {
                        s.push_str(&format!(", owner {o}"));
                    }
                    s.push(')');
                    let mut denied = Vec::new();
                    if !access.read {
                        denied.push("read");
                    }
                    if !access.write {
                        denied.push("write");
                    }
                    if denied.len() == 2 {
                        s.push_str("; current user cannot read or write it");
                    } else if let Some(d) = denied.first() {
                        s.push_str(&format!("; current user cannot {d} it"));
                    }
                    s
                }
            }
            FactKind::NearestExistingAncestor { path, ancestor } => {
                format!("Nearest existing parent of {path} is {ancestor}")
            }
            FactKind::AncestorNotSearchable { path, ancestor } => {
                format!("Directory {ancestor} (a parent of {path}) is not searchable by the current user")
            }
            FactKind::ExecutableSearch {
                name,
                path_dirs,
                candidates,
                ..
            } => {
                let usable: Vec<&ExecCandidate> = candidates
                    .iter()
                    .filter(|c| c.exists && c.executable && !c.is_dir)
                    .collect();
                if let Some(c) = usable.first() {
                    format!("{name} resolves to {}", c.path)
                } else if let Some(c) = candidates.iter().find(|c| c.broken_symlink) {
                    format!("{} is a broken symbolic link", c.path)
                } else if let Some(c) = candidates.iter().find(|c| c.exists && !c.executable) {
                    format!("{} exists but is not executable", c.path)
                } else {
                    format!(
                        "{name} was not found in any of the {} PATH directories",
                        path_dirs.len()
                    )
                }
            }
            FactKind::ScriptInterpreter {
                script,
                interpreter,
                interpreter_exists,
            } => {
                if *interpreter_exists {
                    format!("{script} uses interpreter {interpreter}")
                } else {
                    format!("{script} requires interpreter {interpreter}, which does not exist")
                }
            }
            FactKind::ElfInfo {
                path,
                class,
                machine,
                ..
            } => format!("{path} is a {class}-bit ELF binary for {machine}"),
            FactKind::NotElf { path, .. } => format!("{path} is not an ELF executable"),
            FactKind::HostArchitecture { machine } => format!("This host is {machine}"),
            FactKind::Filesystem {
                path,
                mount_point,
                read_only,
                avail_bytes,
                total_bytes,
                free_inodes,
                total_inodes,
                ..
            } => {
                let mp = mount_point.clone().unwrap_or_else(|| path.clone());
                if *read_only {
                    format!("Filesystem {mp} is mounted read-only")
                } else if *total_inodes > 0 && *free_inodes == 0 {
                    format!("Filesystem {mp} has no free inodes")
                } else {
                    format!(
                        "Filesystem {mp} has {} free of {}",
                        human_bytes(*avail_bytes),
                        human_bytes(*total_bytes)
                    )
                }
            }
            FactKind::DnsResolution {
                hostname,
                addresses,
                error,
            } => {
                if addresses.is_empty() {
                    format!(
                        "{hostname} does not resolve now ({})",
                        error.as_deref().unwrap_or("no addresses")
                    )
                } else {
                    let a: Vec<String> = addresses.iter().map(|a| a.to_string()).collect();
                    format!("{hostname} resolves now to {}", a.join(", "))
                }
            }
            FactKind::ResolverConfig { nameservers, .. } => {
                format!("Configured nameservers: {}", nameservers.join(", "))
            }
            FactKind::LibrarySearch {
                library,
                search_dirs,
                found,
                found_elsewhere,
            } => {
                if let Some(c) = found.iter().find(|c| c.compatible) {
                    format!("{library} is available at {}", c.path)
                } else if let Some(c) = found.first() {
                    format!(
                        "{library} exists at {} but is built for {}",
                        c.path,
                        c.machine.as_deref().unwrap_or("another architecture")
                    )
                } else if let Some(p) = found_elsewhere.first() {
                    format!("{library} exists at {p}, outside the loader search path")
                } else {
                    format!(
                        "{library} was not found in {} loader search directories",
                        search_dirs.len()
                    )
                }
            }
            FactKind::FdLimit { soft, hard } => {
                format!("Open-file limit is {soft} (hard limit {hard})")
            }
            FactKind::DefaultRoute { ipv4, ipv6 } => match (ipv4, ipv6) {
                (false, false) => "No default network route is configured".into(),
                (true, false) => "An IPv4 default route exists; no IPv6 default route".into(),
                (false, true) => "An IPv6 default route exists; no IPv4 default route".into(),
                (true, true) => "IPv4 and IPv6 default routes exist".into(),
            },
            FactKind::LocalAddresses { addresses } => {
                let a: Vec<String> = addresses.iter().map(|a| a.to_string()).collect();
                format!("Local addresses: {}", a.join(", "))
            }
            FactKind::DockerStatus {
                cli,
                daemon,
                compose,
                ..
            } => match (cli, daemon) {
                (false, _) => "Docker CLI is not installed".into(),
                (true, false) => "Docker daemon is not reachable".into(),
                (true, true) => {
                    if *compose {
                        "Docker and Docker Compose are available".into()
                    } else {
                        "Docker is available (Compose plugin missing)".into()
                    }
                }
            },
            FactKind::ComposeProject { file, services, .. } => {
                let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
                format!(
                    "{} defines services: {}",
                    file.rsplit('/').next().unwrap_or(file),
                    names.join(", ")
                )
            }
            FactKind::ContainerState {
                service,
                container,
                state,
                exit_code,
                health,
                oom_killed,
                ..
            } => {
                let name = container.clone().unwrap_or_else(|| service.clone());
                match state.as_str() {
                    "absent" => format!("No container exists for service \"{service}\""),
                    "exited" | "dead" => {
                        let mut s = format!("Container \"{name}\" is {state}");
                        if let Some(c) = exit_code {
                            s.push_str(&format!(" (exit code {c})"));
                        }
                        if *oom_killed {
                            s.push_str(", killed by the OOM killer");
                        }
                        s
                    }
                    _ => match health {
                        Some(h) if h != "none" && !h.is_empty() => {
                            format!("Container \"{name}\" is {state} ({h})")
                        }
                        _ => format!("Container \"{name}\" is {state}"),
                    },
                }
            }
            FactKind::ContainerLogs { container, lines } => {
                format!("Last {} log lines of {container} collected", lines.len())
            }
            FactKind::OutputExcerpt { pid, .. } => format!("stderr of pid {pid} captured"),
            FactKind::RuntimeInfo {
                runtime, version, ..
            } => match version {
                Some(v) => format!("{runtime} {v}"),
                None => runtime.clone(),
            },
            FactKind::Property { description, .. } => description.clone(),
        }
    }
}

pub fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}
