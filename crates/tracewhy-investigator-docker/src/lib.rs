//! Docker / Compose investigator.
//!
//! Discovers Compose files near the working directory, the services they
//! define (with port mappings), and the state of their containers. Uses the
//! `docker` CLI read-only (`compose config`, `compose ps`, `ps`, `logs`,
//! `inspect`); a missing CLI or daemon is reported as a fact, never an error.

mod compose;
mod exec;

pub use compose::{parse_compose_yaml, parse_port_spec};

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracewhy_core::{
    ComposeService, FactKind, InvestigationContext, InvestigationCost, InvestigationError,
    InvestigationTarget, Investigator, PortMapping,
};

pub const COMPOSE_FILES: &[&str] = &[
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];

pub struct DockerInvestigator;

pub fn investigators() -> Vec<Box<dyn Investigator>> {
    vec![
        Box::new(DockerInvestigator),
        Box::new(ContainerLogsInvestigator),
    ]
}

/// Compose files in `cwd` and its ancestors (stopping at a repository root).
pub fn discover_compose_files(cwd: &Path, env_compose_file: Option<&str>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(list) = env_compose_file {
        for f in list.split(':').filter(|f| !f.is_empty()) {
            let p = cwd.join(f);
            if p.is_file() {
                out.push(p);
            }
        }
        if !out.is_empty() {
            return out;
        }
    }
    let mut dir = Some(cwd.to_path_buf());
    let mut depth = 0;
    while let Some(d) = dir {
        if let Some(f) = COMPOSE_FILES
            .iter()
            .map(|n| d.join(n))
            .find(|p| p.is_file())
        {
            out.push(f);
            break;
        }
        if d.join(".git").exists() || depth >= 6 {
            break;
        }
        depth += 1;
        dir = d.parent().map(|p| p.to_path_buf());
    }
    out
}

impl Investigator for DockerInvestigator {
    fn id(&self) -> &'static str {
        "docker"
    }

    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::Docker { .. })
    }

    fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
        InvestigationCost {
            expected_millis: 300,
            external_process: true,
        }
    }

    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::Docker { port } = ctx.target else {
            return Ok(Vec::new());
        };
        let budget = || ctx.time_left().min(Duration::from_secs(4));
        let files = discover_compose_files(&ctx.cwd, ctx.env.get("COMPOSE_FILE"));
        let docker = exec::find_docker();
        let mut facts = Vec::new();
        let (daemon, compose_ok, detail) = match &docker {
            None => (false, false, Some("docker CLI not found".to_string())),
            Some(d) => {
                let daemon = exec::run(d, &["info", "--format", "{{.ServerVersion}}"], budget());
                let compose = exec::run(d, &["compose", "version", "--short"], budget()).is_ok();
                match daemon {
                    Ok(_) => (true, compose, None),
                    Err(e) => (false, compose, Some(e)),
                }
            }
        };
        facts.push(FactKind::DockerStatus {
            cli: docker.is_some(),
            daemon,
            compose: compose_ok,
            detail,
        });
        if files.is_empty() && docker.is_none() {
            return Err(InvestigationError::Unavailable(
                "Docker investigator unavailable: no docker CLI and no compose file".into(),
            ));
        }

        for file in &files {
            let file_s = file.to_string_lossy().into_owned();
            let (project, services) = match docker.as_ref().filter(|_| compose_ok) {
                Some(d) => match exec::run(
                    d,
                    &["compose", "-f", &file_s, "config", "--format", "json"],
                    budget(),
                ) {
                    Ok(out) => compose::from_config_json(&out).unwrap_or_else(|| read_yaml(file)),
                    Err(_) => read_yaml(file),
                },
                None => read_yaml(file),
            };
            let relevant: Vec<&ComposeService> = services
                .iter()
                .filter(|s| {
                    port.map(|p| {
                        s.ports
                            .iter()
                            .any(|m| m.host_port == Some(p) || m.container_port == p)
                            || s.expose.contains(&p)
                    })
                    .unwrap_or(true)
                })
                .collect();
            if let (Some(d), true, true) = (&docker, daemon, compose_ok) {
                if !relevant.is_empty() {
                    match exec::run(
                        d,
                        &["compose", "-f", &file_s, "ps", "-a", "--format", "json"],
                        budget(),
                    ) {
                        Ok(out) => {
                            let rows = compose::parse_ps_json(&out);
                            for svc in &relevant {
                                facts.push(container_fact(
                                    d,
                                    project.clone(),
                                    svc,
                                    &rows,
                                    budget(),
                                ));
                            }
                        }
                        Err(e) => {
                            facts.push(FactKind::DockerStatus {
                                cli: true,
                                daemon: true,
                                compose: true,
                                detail: Some(format!("compose ps failed: {e}")),
                            });
                        }
                    }
                }
            }
            facts.push(FactKind::ComposeProject {
                file: file_s,
                project,
                services,
            });
        }

        // Standalone containers publishing the port (not managed by a compose file here).
        if let (Some(d), true, Some(p)) = (&docker, daemon, port) {
            let covered = facts.iter().any(|f| matches!(f, FactKind::ContainerState { published, .. } if published.iter().any(|m| m.host_port == Some(*p))));
            if !covered {
                if let Ok(out) = exec::run(d, &["ps", "--format", "{{json .}}"], budget()) {
                    for line in out.lines() {
                        let Ok(v) = serde_json::from_str::<Value>(line) else {
                            continue;
                        };
                        let ports = v.get("Ports").and_then(|x| x.as_str()).unwrap_or("");
                        let published = compose::parse_ps_ports(ports);
                        if published.iter().any(|m| m.host_port == Some(*p)) {
                            let name = v
                                .get("Names")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .to_string();
                            facts.push(FactKind::ContainerState {
                                project: None,
                                service: name.clone(),
                                container: Some(name),
                                state: v
                                    .get("State")
                                    .and_then(|x| x.as_str())
                                    .unwrap_or("running")
                                    .to_string(),
                                exit_code: None,
                                health: None,
                                published,
                                oom_killed: false,
                            });
                        }
                    }
                }
            }
        }
        Ok(facts)
    }
}

fn read_yaml(file: &Path) -> (Option<String>, Vec<ComposeService>) {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let project = file
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_lowercase());
    (project, parse_compose_yaml(&text))
}

fn container_fact(
    docker: &Path,
    project: Option<String>,
    svc: &ComposeService,
    rows: &[Value],
    budget: Duration,
) -> FactKind {
    let row = rows
        .iter()
        .filter(|r| r.get("Service").and_then(|s| s.as_str()) == Some(svc.name.as_str()))
        // Prefer a running replica, else the most recently listed one.
        .max_by_key(|r| r.get("State").and_then(|s| s.as_str()) == Some("running"));
    let Some(row) = row else {
        return FactKind::ContainerState {
            project,
            service: svc.name.clone(),
            container: None,
            state: "absent".into(),
            exit_code: None,
            health: None,
            published: Vec::new(),
            oom_killed: false,
        };
    };
    let name = row.get("Name").and_then(|s| s.as_str()).map(String::from);
    let state = row
        .get("State")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown")
        .to_string();
    let exit_code = row
        .get("ExitCode")
        .and_then(|c| c.as_i64())
        .map(|c| c as i32)
        .filter(|_| state != "running");
    let health = row
        .get("Health")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .map(String::from);
    let published = row
        .get("Publishers")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    let target = p.get("TargetPort")?.as_u64()? as u16;
                    let published = p
                        .get("PublishedPort")
                        .and_then(|x| x.as_u64())
                        .filter(|x| *x > 0)
                        .map(|x| x as u16);
                    Some(PortMapping {
                        host_ip: p
                            .get("URL")
                            .and_then(|x| x.as_str())
                            .filter(|s| !s.is_empty())
                            .map(String::from),
                        host_port: published,
                        container_port: target,
                        protocol: p
                            .get("Protocol")
                            .and_then(|x| x.as_str())
                            .unwrap_or("tcp")
                            .to_string(),
                    })
                })
                .filter(|m| m.host_port.is_some())
                .collect()
        })
        .unwrap_or_default();
    let oom_killed = match (&name, state.as_str()) {
        (Some(n), "exited" | "dead") => exec::run(
            docker,
            &["inspect", "--format", "{{.State.OOMKilled}}", n],
            budget,
        )
        .map(|o| o.trim() == "true")
        .unwrap_or(false),
        _ => false,
    };
    FactKind::ContainerState {
        project,
        service: svc.name.clone(),
        container: name,
        state,
        exit_code,
        health,
        published,
        oom_killed,
    }
}

/// Recent log lines of a container.
pub struct ContainerLogsInvestigator;

impl Investigator for ContainerLogsInvestigator {
    fn id(&self) -> &'static str {
        "docker_logs"
    }

    fn supports(&self, t: &InvestigationTarget) -> bool {
        matches!(t, InvestigationTarget::ContainerLogs { .. })
    }

    fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
        InvestigationCost {
            expected_millis: 400,
            external_process: true,
        }
    }

    fn investigate(
        &self,
        ctx: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        let InvestigationTarget::ContainerLogs { container } = ctx.target else {
            return Ok(Vec::new());
        };
        let docker = exec::find_docker()
            .ok_or_else(|| InvestigationError::Unavailable("docker CLI not found".into()))?;
        let out = exec::run_merged(
            &docker,
            &["logs", "--tail", "30", container],
            ctx.time_left().min(Duration::from_secs(4)),
        )
        .map_err(InvestigationError::Failed)?;
        let max = ctx.limits.max_docker_log_bytes;
        let text = if out.len() > max {
            let mut start = out.len() - max;
            while !out.is_char_boundary(start) {
                start += 1;
            }
            out[start..].to_string()
        } else {
            out
        };
        let lines: Vec<String> = text
            .lines()
            .map(|l| l.chars().take(300).collect())
            .collect();
        Ok(vec![FactKind::ContainerLogs {
            container: container.clone(),
            lines,
        }])
    }
}
