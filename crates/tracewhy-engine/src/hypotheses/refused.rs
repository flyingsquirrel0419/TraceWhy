//! Hypotheses for refused TCP connections (services, containers, interfaces).

use super::net::{compose_cmd, file_name, is_local, service_label};
use super::{shell_quote, Ctx, Eval};
use std::net::IpAddr;
use tracewhy_core::{
    well_known_service, ComposeService, FactId, FactKind, InvestigationTarget, Listener,
};
use tracewhy_event::{Endpoint, EventKind};

/// A compose service with the fact that defined it and its compose file.
type ServiceRef = (FactId, String, ComposeService);

/// State of a service's container: (fact, state, exit code, health, name, OOM-killed).
type ContainerView<'a> = (
    FactId,
    &'a str,
    Option<i32>,
    Option<&'a str>,
    Option<&'a str>,
    bool,
);

/// Compose services that publish `port` on the host, or expose it in-container.
fn services_for_port(ctx: &Ctx<'_>, port: u16) -> (Vec<ServiceRef>, Vec<ServiceRef>) {
    let mut published = Vec::new();
    let mut internal = Vec::new();
    for (id, file, s) in ctx.facts.compose_services() {
        if s.ports.iter().any(|p| p.host_port == Some(port)) {
            published.push((id, file, s.clone()));
        } else if s.ports.iter().any(|p| p.container_port == port) || s.expose.contains(&port) {
            internal.push((id, file, s.clone()));
        }
    }
    (published, internal)
}

fn container_of<'a>(ctx: &'a Ctx<'_>, svc: &str) -> Option<ContainerView<'a>> {
    let f = ctx.facts.container(svc)?;
    match &f.kind {
        FactKind::ContainerState {
            state,
            exit_code,
            health,
            container,
            oom_killed,
            ..
        } => Some((
            f.id,
            state.as_str(),
            *exit_code,
            health.as_deref(),
            container.as_deref(),
            *oom_killed,
        )),
        _ => None,
    }
}

fn last_log_error(ctx: &Ctx<'_>, container: &str) -> Option<(FactId, String)> {
    let f = ctx.facts.by_key("container_logs", container)?;
    if let FactKind::ContainerLogs { lines, .. } = &f.kind {
        let pick = lines
            .iter()
            .rev()
            .find(|l| {
                let l = l.to_ascii_lowercase();
                l.contains("error")
                    || l.contains("fatal")
                    || l.contains("panic")
                    || l.contains("failed")
            })
            .or_else(|| lines.iter().rev().find(|l| !l.trim().is_empty()))?;
        return Some((f.id, pick.trim().chars().take(160).collect()));
    }
    None
}

fn compatible(listener: &Listener, target: IpAddr) -> bool {
    let l = listener.address;
    if l == target {
        return true;
    }
    match (l, target) {
        (IpAddr::V4(a), IpAddr::V4(_)) if a.is_unspecified() => true,
        // A wildcard IPv6 socket is dual-stack by default on Linux.
        (IpAddr::V6(a), _) if a.is_unspecified() => true,
        _ => false,
    }
}

pub(super) fn refused(kind: &str, ctx: &Ctx<'_>, addr: IpAddr, port: u16) -> Option<Eval> {
    let local = is_local(ctx, addr);
    let listeners = ctx.facts.port(port);
    let no_listener = listeners.map(|(_, l)| l.is_empty());
    let port_q = || InvestigationTarget::Port {
        port,
        address: Some(addr),
    };
    let (published, internal) = services_for_port(ctx, port);
    let ep = Endpoint::Inet {
        address: addr,
        port,
    };

    match kind {
        "container_stopped" | "container_not_created" => {
            let (cf, file, svc) = published.first()?.clone();
            let label = service_label(port, Some(&svc));
            let Some((sid, state, code, _health, cname, oom)) = container_of(ctx, &svc.name) else {
                return Some(Eval::new(format!("{label} isn't running.")).unresolved(
                    0.4,
                    &format!("Is the container for service \"{}\" running?", svc.name),
                    Some(InvestigationTarget::Docker { port: Some(port) }),
                ));
            };
            let name = cname.unwrap_or(&svc.name).to_string();
            let want_absent = kind == "container_not_created";
            if want_absent != (state == "absent") {
                return None;
            }
            if state == "running" {
                return Some(Eval::new(format!("{label} isn't running.")).refuted(sid));
            }
            let mut e = Eval::new(format!("{label} isn't running."));
            if let Some((lid, _)) = no_listener.filter(|n| *n).and(listeners) {
                e = e.fact(lid, ctx).step("no listener", Some(lid));
            } else if no_listener == Some(false) {
                if let Some((lid, _)) = listeners {
                    return Some(e.refuted(lid));
                }
            }
            e = e.fact(cf, ctx).fact(sid, ctx);
            let up = compose_cmd(&file, ctx, &format!("up -d {}", shell_quote(&svc.name)));
            let score = if no_listener == Some(true) { 0.95 } else { 0.8 };
            e = match state {
                "absent" => e
                    .step(format!("no container for service \"{}\"", svc.name), Some(sid))
                    .detail(format!("{} defines service \"{}\" publishing port {port}, but no container exists for it.", file_name(&file), svc.name)),
                "restarting" => e
                    .step(format!("{name} container restarting"), Some(sid))
                    .detail(format!("Container \"{name}\" keeps restarting.")),
                _ => {
                    let code_s = code.map(|c| format!(" (exit code {c})")).unwrap_or_default();
                    e.step(format!("{name} container {state}"), Some(sid))
                        .detail(format!("Container \"{name}\" for service \"{}\" is {state}{code_s}.", svc.name))
                }
            };
            e = e.infer(format!(
                "The program connected to {ep}, which {} publishes for service \"{}\"; it appears to depend on that service.",
                file_name(&file),
                svc.name
            ));
            if oom {
                e = e.infer("The container was killed by the kernel OOM killer.");
            }
            let mut e = e.supported(score);
            if state != "absent" && state != "created" {
                if let Some((lid, line)) = last_log_error(ctx, &name) {
                    e = e.infer(format!("Its last log line suggests why: \"{line}\""));
                    e.support.push(lid);
                } else if state != "restarting" {
                    e.wants.push(InvestigationTarget::ContainerLogs {
                        container: name.clone(),
                    });
                }
            }
            let crashed = matches!(state, "exited" | "dead" | "restarting")
                && code.map(|c| c != 0).unwrap_or(state == "restarting");
            if crashed {
                // Restarting a container that fails on startup would fail again.
                let logs = compose_cmd(&file, ctx, &format!("logs {}", shell_quote(&svc.name)));
                return Some(e.next(
                    format!("The container failed on startup: fix the error in its logs, then run `{up}`"),
                    Some(logs),
                ));
            }
            Some(e.fix(format!("Start the {} service", svc.name), Some(up)))
        }
        "port_not_published" | "wrong_published_port" => {
            if no_listener != Some(true) {
                return None;
            }
            let (cf, file, svc) = internal.first()?.clone();
            let label = service_label(port, Some(&svc));
            let (sid, state, ..) = container_of(ctx, &svc.name)?;
            if state != "running" {
                return None;
            }
            let other: Option<u16> = svc
                .ports
                .iter()
                .filter(|p| p.container_port == port)
                .find_map(|p| p.host_port);
            let lid = listeners.map(|l| l.0);
            match (kind, other) {
                ("wrong_published_port", Some(q)) => {
                    let mut e = Eval::new(format!(
                        "{label} is published on host port {q}, not {port}."
                    ))
                    .fact(cf, ctx)
                    .fact(sid, ctx);
                    if let Some(l) = lid {
                        e = e.fact(l, ctx).step("no listener", Some(l));
                    }
                    Some(
                        e.step(format!("\"{}\" maps {q}→{port}", svc.name), Some(cf))
                            .infer(format!("The program expects {label} on port {port}."))
                            .supported(0.85)
                            .next(format!("Connect to port {q}, or publish the service as \"{port}:{port}\" in {}", file_name(&file)), None),
                    )
                }
                ("port_not_published", None) => {
                    let mut e = Eval::new(format!(
                        "{label} is running, but port {port} is not published to the host."
                    ))
                    .fact(cf, ctx)
                    .fact(sid, ctx);
                    if let Some(l) = lid {
                        e = e.fact(l, ctx).step("no listener", Some(l));
                    }
                    Some(
                        e.step(format!("\"{}\" does not publish {port}", svc.name), Some(cf))
                            .supported(0.85)
                            .fix(
                                format!("Add `ports: [\"{port}:{port}\"]` to service \"{}\" in {}, then recreate it", svc.name, file_name(&file)),
                                Some(compose_cmd(&file, ctx, &format!("up -d {}", shell_quote(&svc.name)))),
                            ),
                    )
                }
                _ => None,
            }
        }
        "wrong_interface" => {
            let (lid, ls) = listeners?;
            if ls.is_empty() || local == Some(false) {
                return None;
            }
            if ls.iter().any(|l| compatible(l, addr)) {
                return Some(Eval::new("listener on another interface").refuted(lid));
            }
            let bound: Vec<String> = ls.iter().map(|l| l.address.to_string()).collect();
            let label = service_label(port, None);
            Some(
                Eval::new(format!(
                    "{label} listens on {}, but the program connected to {addr}.",
                    bound.join(", ")
                ))
                .fact(lid, ctx)
                .step(format!("listening only on {}", bound.join(", ")), Some(lid))
                .infer("A hostname such as \"localhost\" may resolve to an address family the service does not listen on.")
                .supported(0.85)
                .next(format!("Connect to {} explicitly, or make the service listen on {addr}", bound[0]), None),
            )
        }
        "startup_race" => {
            // A listener that appeared later in this very trace is direct evidence.
            let later = ctx.events.iter().find(|e| {
                e.seq > ctx.obs.events.last().copied().unwrap_or(0)
                    && matches!(&e.kind, EventKind::Bound { endpoint, .. } if endpoint.port() == Some(port))
            });
            if let Some(ev) = later {
                let who = ctx
                    .tree
                    .get(ev.process())
                    .map(|p| p.display_name())
                    .unwrap_or_default();
                return Some(
                    Eval::new(format!("The program connected to port {port} before {who} started listening on it."))
                        .step(format!("{who} bound :{port} afterwards"), None)
                        .infer("Both sides were started by the traced command; the client did not wait for the server to become ready.")
                        .supported(0.88)
                        .next("Wait for the server to accept connections before starting the client (readiness check or retry).", None),
                );
            }
            let (lid, ls) = listeners?;
            if local == Some(false) {
                return None;
            }
            if !ls.iter().any(|l| compatible(l, addr)) {
                return Some(Eval::new("service was starting").refuted(lid));
            }
            let label = service_label(port, None);
            Some(
                Eval::new(format!("{label} was not accepting connections yet when the program connected (it is listening now)."))
                    .fact(lid, ctx)
                    .step("listening now", Some(lid))
                    .infer("The service started (or restarted) after the connection attempt.")
                    .supported(0.55)
                    .next("Make the program wait or retry until the service is ready (e.g. a healthcheck with depends_on: condition: service_healthy).", None),
            )
        }
        "service_not_listening" => {
            if local == Some(false) {
                return None;
            }
            let Some((lid, ls)) = listeners else {
                return Some(
                    Eval::new(format!("Nothing is listening on {ep}.")).unresolved(
                        0.35,
                        &format!("Is anything listening on port {port}?"),
                        Some(port_q()),
                    ),
                );
            };
            if !ls.is_empty() {
                return Some(Eval::new("nothing listening").refuted(lid));
            }
            let label = service_label(port, None);
            let title = if well_known_service(port).is_some() {
                format!("{label} isn't running: nothing is listening on port {port}.")
            } else {
                format!("Nothing is listening on port {port}.")
            };
            // "Nothing listens there" is itself the cause; the program's own
            // report of the refusal makes the tie to the failure direct.
            let score = if ctx.obs.relevance.reported_on_stderr {
                0.88
            } else {
                0.78
            };
            let mut e = Eval::new(title)
                .fact(lid, ctx)
                .step("no listener", Some(lid))
                .supported(score);
            if ctx.facts.first_of("docker_status").is_none() {
                e.wants
                    .push(InvestigationTarget::Docker { port: Some(port) });
            }
            if let Some(name) = well_known_service(port) {
                e = e.infer(format!("Port {port} is {name}'s default port; the program appears to expect {name} there."));
            }
            Some(e.next(
                format!("Start the service that should listen on {ep}"),
                None,
            ))
        }
        "remote_port_closed" => {
            if local != Some(false) {
                return None;
            }
            Some(
                Eval::new(format!("{addr} refused the connection on port {port}: no service is listening there, or a firewall rejects it."))
                    .inferred_step(format!("{addr} rejected port {port}"))
                    .supported(0.6)
                    .next(format!("Check that the service on {addr} is running and listening on port {port}"), None),
            )
        }
        _ => None,
    }
}
