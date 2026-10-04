//! Engine behavior with mock investigators: hypothesis ranking, competing
//! explanations, investigation budgets, determinism and scaling.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracewhy_core::*;
use tracewhy_engine::{AnalysisInput, Engine};
use tracewhy_event::*;

/// Returns canned facts for one target kind and counts its invocations.
struct Mock {
    id: &'static str,
    facts: Vec<FactKind>,
    calls: Arc<AtomicU32>,
    matches: fn(&InvestigationTarget) -> bool,
}

impl Investigator for Mock {
    fn id(&self) -> &'static str {
        self.id
    }
    fn supports(&self, t: &InvestigationTarget) -> bool {
        (self.matches)(t)
    }
    fn cost(&self, _t: &InvestigationTarget) -> InvestigationCost {
        InvestigationCost::CHEAP
    }
    fn investigate(
        &self,
        _c: &InvestigationContext<'_>,
    ) -> Result<Vec<FactKind>, InvestigationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.facts.clone())
    }
}

fn mock(
    id: &'static str,
    matches: fn(&InvestigationTarget) -> bool,
    facts: Vec<FactKind>,
) -> (Box<dyn Investigator>, Arc<AtomicU32>) {
    let calls = Arc::new(AtomicU32::new(0));
    (
        Box::new(Mock {
            id,
            facts,
            calls: calls.clone(),
            matches,
        }),
        calls,
    )
}

fn ev(seq: u64, pid: u32, kind: EventKind) -> Event {
    Event {
        seq,
        ts: None,
        pid,
        tgid: None,
        source: None,
        kind,
    }
}

/// `node server.js` connects to `addr:5432`, is refused, reports it, exits 1.
fn refused_events(addr: &str) -> Vec<Event> {
    let ep = Endpoint::Inet {
        address: addr.parse().unwrap(),
        port: 5432,
    };
    vec![
        ev(
            0,
            10,
            EventKind::ProcessExec {
                executable: "/usr/bin/node".into(),
                args: vec!["node".into(), "server.js".into()],
            },
        ),
        ev(
            1,
            10,
            EventKind::ConnectFailed {
                endpoint: ep,
                protocol: Protocol::Tcp,
                error: Errno::new("ECONNREFUSED"),
            },
        ),
        ev(
            2,
            10,
            EventKind::Output {
                stream: OutputStream::Stderr,
                text: format!("Error: connect ECONNREFUSED {addr}:5432\n"),
            },
        ),
        ev(3, 10, EventKind::ProcessExited { code: 1 }),
    ]
}

fn is_port(t: &InvestigationTarget) -> bool {
    matches!(t, InvestigationTarget::Port { .. })
}
fn is_docker(t: &InvestigationTarget) -> bool {
    matches!(t, InvestigationTarget::Docker { .. })
}
fn is_network(t: &InvestigationTarget) -> bool {
    matches!(t, InvestigationTarget::Network)
}

fn analyze(engine: &Engine, events: &[Event], investigate: bool) -> tracewhy_engine::Analysis {
    let tree = ProcessTree::build(events);
    let env = EnvSnapshot::default();
    engine.analyze(AnalysisInput {
        command: vec!["node".into(), "server.js".into()],
        events,
        exit: tree.root_exit().cloned(),
        tree: &tree,
        cwd: "/app".into(),
        env: &env,
        preflight: Vec::new(),
        prior_facts: Vec::new(),
        investigate,
    })
}

fn listener(addr: &str) -> Listener {
    Listener {
        address: addr.parse().unwrap(),
        pid: Some(77),
        executable: Some("/usr/bin/postgres".into()),
        cmdline: None,
    }
}

fn compose(port: u16) -> FactKind {
    FactKind::ComposeProject {
        file: "/app/compose.yaml".into(),
        project: Some("app".into()),
        services: vec![ComposeService {
            name: "postgres".into(),
            image: Some("postgres:16".into()),
            ports: vec![PortMapping {
                host_ip: None,
                host_port: Some(port),
                container_port: 5432,
                protocol: "tcp".into(),
            }],
            expose: vec![],
            healthcheck: false,
        }],
    }
}

fn container(state: &str, code: Option<i32>) -> FactKind {
    FactKind::ContainerState {
        project: Some("app".into()),
        service: "postgres".into(),
        container: Some("app-postgres-1".into()),
        state: state.into(),
        exit_code: code,
        health: None,
        published: vec![],
        oom_killed: false,
    }
}

#[test]
fn stopped_container_beats_generic_explanation() {
    let (p, _) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![],
        }],
    );
    let (d, _) = mock(
        "docker",
        is_docker,
        vec![compose(5432), container("exited", Some(0))],
    );
    let engine = Engine::new(vec![p, d], vec![]);
    let a = analyze(&engine, &refused_events("127.0.0.1"), true);
    let rc = a.conclusion.root_cause.as_ref().unwrap();
    assert_eq!(rc.kind, "container_stopped");
    assert_eq!(a.conclusion.confidence, Some(Confidence::High));
    assert_eq!(
        a.conclusion.suggestions[0].command.as_deref(),
        Some("docker compose up -d postgres")
    );
    let labels: Vec<&str> = a
        .conclusion
        .chain
        .iter()
        .map(|s| s.label.as_str())
        .collect();
    assert_eq!(labels.first(), Some(&"node server.js"));
    assert!(labels.contains(&"ECONNREFUSED"));
    assert!(labels.iter().any(|l| l.contains("container exited")));
    // Evidence and inference stay separate.
    assert!(a
        .conclusion
        .evidence
        .iter()
        .any(|e| e.text.contains("refused")));
    assert!(a
        .conclusion
        .inferences
        .iter()
        .any(|i| i.contains("appears to depend")));
}

#[test]
fn crashed_container_is_not_just_restarted() {
    let (p, _) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![],
        }],
    );
    let (d, _) = mock(
        "docker",
        is_docker,
        vec![compose(5432), container("exited", Some(1))],
    );
    let engine = Engine::new(vec![p, d], vec![]);
    let a = analyze(&engine, &refused_events("127.0.0.1"), true);
    let s = &a.conclusion.suggestions[0];
    assert_eq!(s.kind, SuggestionKind::NextStep);
    assert!(s.command.as_deref().unwrap().contains("logs"));
}

#[test]
fn listener_present_now_is_only_a_startup_race() {
    let (p, _) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![listener("0.0.0.0")],
        }],
    );
    let engine = Engine::new(vec![p], vec![]);
    let a = analyze(&engine, &refused_events("127.0.0.1"), true);
    assert_eq!(
        a.conclusion.root_cause.as_ref().unwrap().kind,
        "startup_race"
    );
    assert_ne!(
        a.conclusion.confidence,
        Some(Confidence::High),
        "a race cannot be proven after the fact"
    );
}

#[test]
fn listener_on_other_family_is_wrong_interface() {
    let (p, _) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![listener("127.0.0.1")],
        }],
    );
    let engine = Engine::new(vec![p], vec![]);
    let a = analyze(&engine, &refused_events("::1"), true);
    assert_eq!(
        a.conclusion.root_cause.as_ref().unwrap().kind,
        "wrong_interface"
    );
}

#[test]
fn remote_refusal_is_not_blamed_on_local_state() {
    let (p, _) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![],
        }],
    );
    let (n, _) = mock(
        "network",
        is_network,
        vec![FactKind::LocalAddresses {
            addresses: vec!["127.0.0.1".parse().unwrap()],
        }],
    );
    let engine = Engine::new(vec![p, n], vec![]);
    let a = analyze(&engine, &refused_events("10.9.8.7"), true);
    assert_eq!(
        a.conclusion.root_cause.as_ref().unwrap().kind,
        "remote_port_closed"
    );
}

#[test]
fn without_investigation_confidence_is_not_high() {
    let (p, calls) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![],
        }],
    );
    let engine = Engine::new(vec![p], vec![]);
    let a = analyze(&engine, &refused_events("127.0.0.1"), false);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_ne!(a.conclusion.confidence, Some(Confidence::High));
}

#[test]
fn investigation_budget_is_enforced() {
    let (p, pc) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![],
        }],
    );
    let (d, dc) = mock("docker", is_docker, vec![]);
    let (n, nc) = mock("network", is_network, vec![]);
    let mut engine = Engine::new(vec![p, d, n], vec![]);
    engine.limits.max_investigations = 1;
    let a = analyze(&engine, &refused_events("127.0.0.1"), true);
    let total = pc.load(Ordering::SeqCst) + dc.load(Ordering::SeqCst) + nc.load(Ordering::SeqCst);
    assert_eq!(total, 1);
    assert!(a
        .investigations
        .iter()
        .any(|r| r.status == InvestigationStatus::Skipped));
    // The cheapest, most valuable probe (the port) runs first.
    assert_eq!(pc.load(Ordering::SeqCst), 1);
}

#[test]
fn each_investigation_runs_once() {
    let (p, pc) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 5432,
            listeners: vec![],
        }],
    );
    let engine = Engine::new(vec![p], vec![]);
    analyze(&engine, &refused_events("127.0.0.1"), true);
    assert_eq!(pc.load(Ordering::SeqCst), 1);
}

#[test]
fn analysis_is_deterministic() {
    let mk = || {
        let (p, _) = mock(
            "port",
            is_port,
            vec![FactKind::PortListeners {
                port: 5432,
                listeners: vec![],
            }],
        );
        let (d, _) = mock(
            "docker",
            is_docker,
            vec![compose(5432), container("exited", Some(0))],
        );
        Engine::new(vec![p, d], vec![])
    };
    let strip = |a: &tracewhy_engine::Analysis| {
        let mut c = serde_json::to_value(&a.conclusion).unwrap();
        c.as_object_mut().unwrap().remove("stderr_excerpt");
        (c, serde_json::to_value(&a.hypotheses).unwrap())
    };
    let a1 = analyze(&mk(), &refused_events("127.0.0.1"), true);
    let a2 = analyze(&mk(), &refused_events("127.0.0.1"), true);
    assert_eq!(strip(&a1), strip(&a2));
}

#[test]
fn success_is_never_explained_as_failure() {
    let mut events = refused_events("127.0.0.1");
    events[3] = ev(3, 10, EventKind::ProcessExited { code: 0 });
    let (p, pc) = mock("port", is_port, vec![]);
    let engine = Engine::new(vec![p], vec![]);
    let a = analyze(&engine, &events, true);
    assert_eq!(a.conclusion.status, ConclusionStatus::Succeeded);
    assert!(a.conclusion.root_cause.is_none());
    assert_eq!(
        pc.load(Ordering::SeqCst),
        0,
        "no investigation for a successful run"
    );
}

#[test]
fn unexplained_failure_is_undetermined() {
    let events = vec![
        ev(
            0,
            1,
            EventKind::ProcessExec {
                executable: "/bin/app".into(),
                args: vec!["app".into()],
            },
        ),
        ev(
            1,
            1,
            EventKind::FileOpenFailed {
                path: "/etc/app/optional.conf".into(),
                requested: None,
                access: FileAccess::Read,
                error: Errno::new("ENOENT"),
            },
        ),
        ev(
            2,
            1,
            EventKind::FileOpened {
                path: "/etc/app/default.conf".into(),
                requested: None,
                access: FileAccess::Read,
            },
        ),
        ev(
            3,
            1,
            EventKind::Output {
                stream: OutputStream::Stderr,
                text: "assertion failed: x > 0\n".into(),
            },
        ),
        ev(4, 1, EventKind::ProcessExited { code: 2 }),
    ];
    let engine = Engine::new(vec![], vec![]);
    let a = analyze(&engine, &events, true);
    assert_eq!(a.conclusion.status, ConclusionStatus::Undetermined);
}

#[test]
fn large_event_streams_analyze_quickly() {
    let mut events = vec![ev(
        0,
        1,
        EventKind::ProcessExec {
            executable: "/bin/app".into(),
            args: vec!["app".into()],
        },
    )];
    let mut seq = 1;
    for i in 0..150_000u64 {
        let kind = if i % 5 == 0 {
            EventKind::FileOpenFailed {
                path: format!("/lib/probe{}/libx.so", i % 400),
                requested: None,
                access: FileAccess::Read,
                error: Errno::new("ENOENT"),
            }
        } else if i % 5 == 1 {
            EventKind::PathOpFailed {
                op: "stat".into(),
                path: format!("/cache/{i}"),
                requested: None,
                error: Errno::new("ENOENT"),
            }
        } else {
            EventKind::FileOpened {
                path: format!("/data/{}", i % 1000),
                requested: None,
                access: FileAccess::Read,
            }
        };
        events.push(ev(seq, 1, kind));
        seq += 1;
    }
    events.push(ev(seq, 1, EventKind::ProcessExited { code: 1 }));
    let engine = Engine::new(vec![], vec![]);
    let start = std::time::Instant::now();
    let a = analyze(&engine, &events, false);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 30,
        "analysis of 150k events took {elapsed:?}"
    );
    assert!(a.graph.nodes.len() <= engine.limits.max_graph_nodes);
}

#[test]
fn port_held_by_container_without_visible_pid() {
    // Unprivileged users cannot see the root-owned docker-proxy; Docker's view decides.
    let ep = Endpoint::Inet {
        address: "0.0.0.0".parse().unwrap(),
        port: 8080,
    };
    let events = vec![
        ev(
            0,
            10,
            EventKind::ProcessExec {
                executable: "/usr/bin/python3".into(),
                args: vec!["python3".into()],
            },
        ),
        ev(
            1,
            10,
            EventKind::BindFailed {
                endpoint: ep,
                protocol: Protocol::Tcp,
                error: Errno::new("EADDRINUSE"),
            },
        ),
        ev(
            2,
            10,
            EventKind::Output {
                stream: OutputStream::Stderr,
                text: "OSError: [Errno 98] Address already in use\n".into(),
            },
        ),
        ev(3, 10, EventKind::ProcessExited { code: 1 }),
    ];
    let hidden = Listener {
        address: "0.0.0.0".parse().unwrap(),
        pid: None,
        executable: None,
        cmdline: None,
    };
    let (p, _) = mock(
        "port",
        is_port,
        vec![FactKind::PortListeners {
            port: 8080,
            listeners: vec![hidden],
        }],
    );
    let (d, _) = mock(
        "docker",
        is_docker,
        vec![FactKind::ContainerState {
            project: None,
            service: "web".into(),
            container: Some("web".into()),
            state: "running".into(),
            exit_code: None,
            health: None,
            published: vec![PortMapping {
                host_ip: Some("0.0.0.0".into()),
                host_port: Some(8080),
                container_port: 80,
                protocol: "tcp".into(),
            }],
            oom_killed: false,
        }],
    );
    let engine = Engine::new(vec![p, d], vec![]);
    let a = analyze(&engine, &events, true);
    assert_eq!(
        a.conclusion.root_cause.as_ref().unwrap().kind,
        "port_held_by_container"
    );
    assert_eq!(a.conclusion.confidence, Some(Confidence::High));
}
