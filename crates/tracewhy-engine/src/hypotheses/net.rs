//! Network hypotheses: refused connections, ports in use, DNS, unix sockets.

use super::refused::refused;
use super::{parent_dir, shell_quote, Ctx, Eval};
use std::net::IpAddr;
use tracewhy_core::{
    product_name_for, well_known_service, ComposeService, FactKind, InvestigationTarget,
    ObservationKind,
};
use tracewhy_event::{DnsRcode, Endpoint, EventKind};

pub fn evaluate(kind: &str, ctx: &Ctx<'_>) -> Option<Eval> {
    match &ctx.obs.kind {
        ObservationKind::ConnectFailed {
            endpoint: Endpoint::Inet { address, port },
            error,
            ..
        } => {
            if error.is("ECONNREFUSED") {
                refused(kind, ctx, *address, *port)
            } else {
                unreachable(kind, ctx, *address, *port, error.as_str())
            }
        }
        ObservationKind::ConnectFailed {
            endpoint: Endpoint::Unix { path },
            error,
            ..
        } => unix_socket(kind, ctx, path, error.as_str()),
        ObservationKind::BindFailed {
            endpoint, error, ..
        } => bind(kind, ctx, endpoint, error.as_str()),
        ObservationKind::DnsFailed { hostname, rcode } => dns(kind, ctx, hostname, *rcode),
        ObservationKind::WriteFailed { target, error } if kind == "broken_pipe" => {
            let what = target.clone().unwrap_or_else(|| "a pipe".into());
            let title = if error.is("EPIPE") {
                format!("The reader of {what} went away before the program finished writing.")
            } else {
                format!("The peer reset the connection while writing to {what}.")
            };
            Some(Eval::new(title).supported(0.5).next(
                "Check why the receiving side exited or closed the connection early.",
                None,
            ))
        }
        _ => None,
    }
}

pub(super) fn is_local(ctx: &Ctx<'_>, a: IpAddr) -> Option<bool> {
    if a.is_loopback() || a.is_unspecified() {
        return Some(true);
    }
    ctx.facts
        .first_of("local_addresses")
        .and_then(|f| match &f.kind {
            FactKind::LocalAddresses { addresses } => Some(addresses.contains(&a)),
            _ => None,
        })
}

pub(super) fn service_label(port: u16, svc: Option<&ComposeService>) -> String {
    svc.and_then(|s| {
        s.image
            .as_deref()
            .and_then(product_name_for)
            .or_else(|| product_name_for(&s.name))
    })
    .or_else(|| well_known_service(port))
    .map(|s| s.to_string())
    .unwrap_or_else(|| match svc {
        Some(s) => format!("Service \"{}\"", s.name),
        None => format!("The service on port {port}"),
    })
}

pub(super) fn compose_cmd(file: &str, ctx: &Ctx<'_>, rest: &str) -> String {
    let dir = parent_dir(file);
    let cwd = ctx.cwd.to_string_lossy();
    if dir == cwd {
        format!("docker compose {rest}")
    } else {
        format!("docker compose -f {} {rest}", shell_quote(file))
    }
}

pub(super) fn file_name(f: &str) -> &str {
    f.rsplit('/').next().unwrap_or(f)
}

fn unreachable(kind: &str, ctx: &Ctx<'_>, addr: IpAddr, port: u16, err: &str) -> Option<Eval> {
    let route = ctx.facts.first_of("default_route");
    match (kind, err) {
        ("network_unreachable", "ENETUNREACH") => {
            let mut e = Eval::new(format!("The network for {addr} is unreachable from this host."));
            if let Some(f) = route {
                if let FactKind::DefaultRoute { ipv4, ipv6 } = &f.kind {
                    let has = if addr.is_ipv4() { *ipv4 } else { *ipv6 };
                    if !has {
                        let fam = if addr.is_ipv4() { "IPv4" } else { "IPv6" };
                        return Some(
                            e.fact(f.id, ctx)
                                .step(format!("no {fam} default route"), Some(f.id))
                                .supported(0.9)
                                .next(format!("Configure {fam} networking, or connect via an address family that is routed"), None),
                        );
                    }
                    e = e.fact(f.id, ctx);
                }
            }
            Some(e.supported(0.6).next("Check network configuration and routes (`ip route`)", Some("ip route".into())))
        }
        ("host_unreachable", "EHOSTUNREACH") => Some(
            Eval::new(format!("Host {addr} is unreachable (no route, or it is down)."))
                .supported(0.6)
                .next(format!("Check that {addr} is up and reachable from this host"), None),
        ),
        ("connect_timeout", "ETIMEDOUT") => Some(
            Eval::new(format!("Connecting to {addr}:{port} timed out (host down, or packets silently dropped by a firewall)."))
                .supported(0.55)
                .next(format!("Check firewalls and that {addr}:{port} is reachable"), None),
        ),
        ("no_source_address", "EADDRNOTAVAIL") => Some(
            Eval::new(format!("No usable local address to reach {addr}:{port} (exhausted ephemeral ports or a missing interface address)."))
                .supported(0.55)
                .next("Check local interfaces and ephemeral port usage", None),
        ),
        _ => None,
    }
}

fn unix_socket(kind: &str, ctx: &Ctx<'_>, path: &str, err: &str) -> Option<Eval> {
    let pf = ctx.facts.path(path);
    let (exists, writable) = match pf.map(|f| &f.kind) {
        Some(FactKind::PathStatus { exists, access, .. }) => (Some(*exists), Some(access.write)),
        _ => (None, None),
    };
    let what = if path.contains("docker.sock") {
        "The Docker daemon".to_string()
    } else {
        format!("The server for {path}")
    };
    match (kind, err) {
        ("socket_missing", "ENOENT") => {
            let e = Eval::new(format!(
                "{what} is not running: socket {path} does not exist."
            ));
            match (exists, pf) {
                (Some(false), Some(f)) => Some(
                    e.fact(f.id, ctx)
                        .step("socket file missing", Some(f.id))
                        .supported(0.88)
                        .next(format!("Start the service that creates {path}"), None),
                ),
                (Some(true), Some(f)) => Some(e.refuted(f.id)),
                _ => Some(e.unresolved(
                    0.5,
                    "Does the socket exist?",
                    Some(InvestigationTarget::Path { path: path.into() }),
                )),
            }
        }
        ("socket_stale", "ECONNREFUSED") => {
            let e = Eval::new(format!(
                "{what} is not running: {path} exists but nothing accepts connections on it."
            ));
            match pf {
                Some(f) if exists == Some(true) => Some(
                    e.fact(f.id, ctx)
                        .step("stale socket file", Some(f.id))
                        .supported(0.85)
                        .next(
                            format!("Start (or restart) the service that owns {path}"),
                            None,
                        ),
                ),
                _ => Some(e.supported(0.6)),
            }
        }
        ("socket_permission", "EACCES") => {
            let e = Eval::new(format!("The current user may not connect to {path}."));
            match pf {
                Some(f) if writable == Some(false) => Some(
                    e.fact(f.id, ctx)
                        .step("no write permission on socket", Some(f.id))
                        .supported(0.9)
                        .next(
                            if path.contains("docker.sock") {
                                "Add your user to the docker group (then log in again), or use rootless Docker".to_string()
                            } else {
                                format!("Grant the current user write access to {path}")
                            },
                            None,
                        ),
                ),
                _ => Some(e.supported(0.65)),
            }
        }
        _ => None,
    }
}

fn bind(kind: &str, ctx: &Ctx<'_>, endpoint: &Endpoint, err: &str) -> Option<Eval> {
    let port = endpoint.port()?;
    let listeners = ctx.facts.port(port);
    match (kind, err) {
        ("port_held_by_traced_process", "EADDRINUSE") => {
            let obs_seq = ctx.obs.events.first().copied().unwrap_or(0);
            let earlier = ctx.events.iter().find(|e| {
                e.seq < obs_seq
                    && matches!(&e.kind, EventKind::Bound { endpoint, .. } if endpoint.port() == Some(port))
            })?;
            let who = ctx
                .tree
                .get(earlier.process())
                .map(|p| p.display_name())
                .unwrap_or_default();
            Some(
                Eval::new(format!(
                    "Port {port} was already bound earlier in this same run by {who} (pid {}).",
                    earlier.process()
                ))
                .step(format!("{who} bound :{port} first"), None)
                .infer("The command starts two listeners on the same port.")
                .supported(0.9)
                .next(
                    "Give each server its own port, or start only one instance",
                    None,
                ),
            )
        }
        ("port_held_by_container", "EADDRINUSE") => {
            // Docker's own view is authoritative; it works even when the
            // root-owned docker-proxy is invisible to an unprivileged user.
            if let Some((cid, service, name)) = container_publishing(ctx, port) {
                let compose = ctx.facts.compose_services().into_iter().find(|(_, _, s)| {
                    s.name == service && s.ports.iter().any(|p| p.host_port == Some(port))
                });
                let mut e = Eval::new(format!(
                    "Port {port} is already published by Docker container \"{name}\"."
                ))
                .fact(cid, ctx)
                .step(format!("container {name} publishes :{port}"), Some(cid))
                .supported(0.92);
                if let Some((lid, _)) = listeners {
                    e = e.fact(lid, ctx);
                }
                return Some(match compose {
                    Some((cf, file, s)) => e.fact(cf, ctx).next(
                        "Stop the container (or change its published port) before starting this program",
                        Some(compose_cmd(&file, ctx, &format!("stop {}", shell_quote(&s.name)))),
                    ),
                    None => e.next(
                        "Stop the container publishing this port, or use another port",
                        Some(format!("docker stop {}", shell_quote(&name))),
                    ),
                });
            }
            if let Some((lid, ls)) = listeners {
                if let Some(l) = ls.iter().find(|l| {
                    l.executable
                        .as_deref()
                        .map(|e| e.ends_with("docker-proxy"))
                        .unwrap_or(false)
                }) {
                    let svc = ctx
                        .facts
                        .compose_services()
                        .into_iter()
                        .find(|(_, _, s)| s.ports.iter().any(|p| p.host_port == Some(port)));
                    let mut e = Eval::new(match &svc {
                        Some((_, _, s)) => format!(
                            "Port {port} is already published by Docker for service \"{}\".",
                            s.name
                        ),
                        None => format!("Port {port} is already published by a Docker container."),
                    })
                    .fact(lid, ctx)
                    .step(
                        format!("docker-proxy (pid {}) holds :{port}", l.pid.unwrap_or(0)),
                        Some(lid),
                    )
                    .supported(0.9);
                    if let Some((cf, file, s)) = svc {
                        e = e.fact(cf, ctx);
                        return Some(e.next(
                            "Stop the container (or change its published port) before starting this program".to_string(),
                            Some(compose_cmd(&file, ctx, &format!("stop {}", shell_quote(&s.name)))),
                        ));
                    }
                    return Some(e.next("Stop the container publishing this port (`docker ps` shows it), or use another port", None));
                }
            }
            None
        }
        ("port_held_by_process", "EADDRINUSE") => {
            let Some((lid, ls)) = listeners else {
                return Some(
                    Eval::new(format!("Port {port} is in use by another process.")).unresolved(
                        0.45,
                        &format!("Which process listens on port {port}?"),
                        Some(InvestigationTarget::Port {
                            port,
                            address: endpoint.address(),
                        }),
                    ),
                );
            };
            let l = ls.iter().find(|l| {
                l.pid.is_some()
                    && !l
                        .executable
                        .as_deref()
                        .unwrap_or("")
                        .ends_with("docker-proxy")
            })?;
            let exe = l
                .executable
                .as_deref()
                .map(|e| e.rsplit('/').next().unwrap_or(e))
                .unwrap_or("unknown");
            let pid = l.pid.unwrap_or(0);
            let mut e = Eval::new(format!(
                "Port {port} is already in use by {exe} (pid {pid})."
            ))
            .fact(lid, ctx)
            .step(format!("{exe} (pid {pid}) listens on :{port}"), Some(lid));
            if let Some(c) = &l.cmdline {
                e = e.infer(format!("The process holding the port was started as: {c}"));
            }
            Some(e.supported(0.92).next(
                format!("Stop the process using port {port} or choose a different port"),
                Some(format!("kill {pid}")),
            ))
        }
        ("port_held_by_unknown", "EADDRINUSE") => {
            if container_publishing(ctx, port).is_some() {
                return None;
            }
            let (lid, ls) = listeners?;
            if ls.is_empty() || ls.iter().any(|l| l.pid.is_some()) {
                return None;
            }
            Some(
                Eval::new(format!("Port {port} is in use by a process this user cannot inspect (another user or root)."))
                    .fact(lid, ctx)
                    .step(format!("another user's process listens on :{port}"), Some(lid))
                    .supported(0.8)
                    .next(format!("Find the owner with `sudo ss -ltnp 'sport = :{port}'` and stop it, or use another port"), None),
            )
        }
        ("port_released", "EADDRINUSE") => {
            let (lid, ls) = listeners?;
            if !ls.is_empty() {
                return Some(Eval::new("released").refuted(lid));
            }
            Some(
                Eval::new(format!(
                    "Port {port} was in use when the program started; it is free now."
                ))
                .fact(lid, ctx)
                .inferred_step("the holder has since exited")
                .supported(0.45)
                .next(
                    "Retry; if it recurs, look for another instance starting at the same time",
                    None,
                ),
            )
        }
        ("privileged_port", "EACCES" | "EPERM") => {
            let prop = |key: &str| {
                ctx.facts
                    .by_key("property", &format!("{key}:current"))
                    .and_then(|f| match &f.kind {
                        FactKind::Property { value, .. } => Some((f.id, value.clone())),
                        _ => None,
                    })
            };
            let start: u16 = prop("privileges.unprivileged_port_start")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(1024);
            if port >= start {
                return None;
            }
            let mut e = Eval::new(format!(
                "Binding port {port} requires root or CAP_NET_BIND_SERVICE (ports below {start} are privileged)."
            ))
            .inferred_step(format!("port {port} < {start}"));
            let Some((cid, cap)) = prop("privileges.cap_net_bind_service") else {
                return Some(e.unresolved(
                    0.6,
                    "Does the process have CAP_NET_BIND_SERVICE?",
                    Some(InvestigationTarget::Privileges { executable: None }),
                ));
            };
            if cap == "true" {
                return Some(e.refuted(cid));
            }
            // A setcap'd binary loses its file capabilities while traced by an
            // unprivileged tracer, so the failure may exist only under `why`.
            if let Some((fid, exe)) = prop("privileges.file_capabilities") {
                return Some(
                    Eval::new(format!(
                        "{exe} has file capabilities, which Linux ignores while it is traced; binding port {port} failed only because it ran under TraceWhy."
                    ))
                    .fact(fid, ctx)
                    .step("file capabilities suppressed by tracing", Some(fid))
                    .supported(0.6)
                    .next("Run the command without why (or run why as root) to confirm", None),
                );
            }
            e = e.fact(cid, ctx).step("no CAP_NET_BIND_SERVICE", Some(cid));
            if let Some((sid, _)) = prop("privileges.unprivileged_port_start") {
                e = e.fact(sid, ctx);
            }
            if let Some((uid, _)) = prop("privileges.user") {
                e = e.fact(uid, ctx);
            }
            Some(e.supported(0.92).fix(
                format!("Use a port ≥ {start}, or grant the binary the capability"),
                Some("sudo setcap 'cap_net_bind_service=+ep' <binary>".into()),
            ))
        }
        ("address_not_local", "EADDRNOTAVAIL") => {
            let addr = endpoint.address()?;
            let f = ctx.facts.first_of("local_addresses")?;
            if let FactKind::LocalAddresses { addresses } = &f.kind {
                if addresses.contains(&addr) {
                    return Some(Eval::new("address local").refuted(f.id));
                }
            }
            Some(
                Eval::new(format!(
                    "Address {addr} is not assigned to any interface on this host."
                ))
                .fact(f.id, ctx)
                .step(format!("{addr} is not a local address"), Some(f.id))
                .supported(0.9)
                .fix("Bind to an address this host owns, or 0.0.0.0", None),
            )
        }
        _ => None,
    }
}

fn dns(kind: &str, ctx: &Ctx<'_>, host: &str, rcode: Option<DnsRcode>) -> Option<Eval> {
    let now = ctx.facts.by_key("dns_resolution", host);
    let resolves_now = now.and_then(|f| match &f.kind {
        FactKind::DnsResolution { addresses, .. } => Some(!addresses.is_empty()),
        _ => None,
    });
    let q = || InvestigationTarget::Hostname {
        name: host.to_string(),
    };
    match kind {
        "hostname_not_found" => {
            if rcode != Some(DnsRcode::NxDomain) {
                return None;
            }
            let e = Eval::new(format!(
                "Hostname \"{host}\" does not exist in DNS (NXDOMAIN)."
            ));
            match (resolves_now, now) {
                (Some(true), Some(f)) => Some(e.refuted(f.id)),
                (Some(false), Some(f)) => Some(
                    e.fact(f.id, ctx)
                        .step(format!("{host} does not resolve"), Some(f.id))
                        .supported(0.92)
                        .next(format!("Check the hostname \"{host}\" in the program's configuration, or add it to DNS / /etc/hosts"), None),
                ),
                _ => Some(e.unresolved(0.6, &format!("Does {host} resolve now?"), Some(q()))),
            }
        }
        "dns_server_failure" => {
            if matches!(rcode, Some(DnsRcode::NxDomain)) {
                return None;
            }
            let what = rcode
                .map(|r| r.label())
                .unwrap_or_else(|| "no answer".into());
            let mut e = Eval::new(format!(
                "The DNS server could not answer for \"{host}\" ({what})."
            ));
            if let Some(f) = ctx.facts.first_of("resolver_config") {
                e = e.fact(f.id, ctx);
            }
            Some(e.supported(0.65).next(
                "Check the resolver configuration (/etc/resolv.conf) and DNS server health",
                None,
            ))
        }
        "transient_dns_failure" => {
            let f = now?;
            if resolves_now != Some(true) {
                return None;
            }
            Some(
                Eval::new(format!(
                    "Resolving \"{host}\" failed while the program ran, but it resolves now."
                ))
                .fact(f.id, ctx)
                .supported(0.5)
                .next(
                    "Retry; if it recurs, check DNS reliability or caching",
                    None,
                ),
            )
        }
        _ => None,
    }
}

/// A running container that publishes `port` on the host: (fact, service, container name).
fn container_publishing(
    ctx: &Ctx<'_>,
    port: u16,
) -> Option<(tracewhy_core::FactId, String, String)> {
    ctx.facts
        .of_type("container_state")
        .into_iter()
        .find_map(|f| match &f.kind {
            FactKind::ContainerState {
                service,
                container,
                state,
                published,
                ..
            } if state == "running" && published.iter().any(|m| m.host_port == Some(port)) => {
                Some((
                    f.id,
                    service.clone(),
                    container.clone().unwrap_or_else(|| service.clone()),
                ))
            }
            _ => None,
        })
}
