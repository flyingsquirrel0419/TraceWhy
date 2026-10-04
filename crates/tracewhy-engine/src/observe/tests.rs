use super::*;
use tracewhy_event::FileAccess;
use tracewhy_event::{DnsRcode, Endpoint, Errno, EventKind, Protocol};

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

fn exec(seq: u64, pid: u32, exe: &str) -> Event {
    ev(
        seq,
        pid,
        EventKind::ProcessExec {
            executable: exe.into(),
            args: vec![exe.into()],
        },
    )
}

fn open_fail(seq: u64, pid: u32, path: &str) -> Event {
    ev(
        seq,
        pid,
        EventKind::FileOpenFailed {
            path: path.into(),
            requested: None,
            access: FileAccess::Read,
            error: Errno::new("ENOENT"),
        },
    )
}

fn stderr(seq: u64, pid: u32, text: &str) -> Event {
    ev(
        seq,
        pid,
        EventKind::Output {
            stream: tracewhy_event::OutputStream::Stderr,
            text: text.into(),
        },
    )
}

#[test]
fn optional_missing_file_in_successful_run_is_not_relevant() {
    let events = vec![
        exec(0, 1, "/usr/bin/node"),
        open_fail(1, 1, "/app/.env"),
        ev(2, 1, EventKind::ProcessExited { code: 0 }),
    ];
    let tree = ProcessTree::build(&events);
    let set = extract(&events, &tree);
    assert!(set
        .observations
        .iter()
        .all(|o| o.relevance.score < CANDIDATE_THRESHOLD));
}

#[test]
fn reported_missing_file_is_relevant() {
    let events = vec![
        exec(0, 1, "/usr/bin/cat"),
        open_fail(1, 1, "/locale/x"),
        open_fail(2, 1, "/nonexistent"),
        stderr(3, 1, "cat: /nonexistent: No such file or directory\n"),
        ev(4, 1, EventKind::ProcessExited { code: 1 }),
    ];
    let tree = ProcessTree::build(&events);
    let set = extract(&events, &tree);
    let top = &set.observations[0];
    assert!(
        matches!(&top.kind, ObservationKind::FileAccessFailed { path, .. } if path == "/nonexistent")
    );
    assert!(top.relevance.reported_on_stderr);
    assert!(top.relevance.score >= CANDIDATE_THRESHOLD);
    let other = set.observations.iter().find(|o| o.id != top.id).unwrap();
    assert!(other.relevance.score < CANDIDATE_THRESHOLD);
}

#[test]
fn library_probe_found_elsewhere_is_not_missing() {
    let events = vec![
        exec(0, 1, "/usr/bin/app"),
        open_fail(1, 1, "/opt/lib/libfoo.so.1"),
        ev(
            2,
            1,
            EventKind::FileOpened {
                path: "/usr/lib/libfoo.so.1".into(),
                requested: None,
                access: FileAccess::Read,
            },
        ),
        ev(3, 1, EventKind::ProcessExited { code: 127 }),
    ];
    let tree = ProcessTree::build(&events);
    let set = extract(&events, &tree);
    assert!(!set
        .observations
        .iter()
        .any(|o| matches!(o.kind, ObservationKind::LibraryLoadFailed { .. })));
}

#[test]
fn retried_connection_that_succeeds_is_recovered() {
    let ep = Endpoint::Inet {
        address: "127.0.0.1".parse().unwrap(),
        port: 5432,
    };
    let events = vec![
        exec(0, 1, "/usr/bin/app"),
        ev(
            1,
            1,
            EventKind::ConnectFailed {
                endpoint: ep.clone(),
                protocol: Protocol::Tcp,
                error: Errno::new("ECONNREFUSED"),
            },
        ),
        ev(
            2,
            1,
            EventKind::Connected {
                endpoint: ep,
                protocol: Protocol::Tcp,
            },
        ),
        ev(3, 1, EventKind::ProcessExited { code: 1 }),
    ];
    let tree = ProcessTree::build(&events);
    let set = extract(&events, &tree);
    assert!(set.observations[0].relevance.recovered);
    assert!(set.observations[0].relevance.score < CANDIDATE_THRESHOLD);
}

#[test]
fn dns_search_domains_group_under_requested_name() {
    let events = vec![
        exec(0, 1, "/usr/bin/app"),
        ev(
            1,
            1,
            EventKind::DnsQuery {
                hostname: "db.internal".into(),
                qtype: "A".into(),
                server: None,
            },
        ),
        ev(
            2,
            1,
            EventKind::DnsAnswer {
                hostname: "db.internal".into(),
                qtype: "A".into(),
                rcode: DnsRcode::NxDomain,
                addresses: vec![],
            },
        ),
        ev(
            3,
            1,
            EventKind::DnsQuery {
                hostname: "db.internal.corp.example".into(),
                qtype: "A".into(),
                server: None,
            },
        ),
        ev(
            4,
            1,
            EventKind::DnsAnswer {
                hostname: "db.internal.corp.example".into(),
                qtype: "A".into(),
                rcode: DnsRcode::NxDomain,
                addresses: vec![],
            },
        ),
        stderr(5, 1, "getaddrinfo ENOTFOUND db.internal\n"),
        ev(6, 1, EventKind::ProcessExited { code: 1 }),
    ];
    let tree = ProcessTree::build(&events);
    let set = extract(&events, &tree);
    let dns: Vec<_> = set
        .observations
        .iter()
        .filter(|o| matches!(o.kind, ObservationKind::DnsFailed { .. }))
        .collect();
    assert_eq!(dns.len(), 1);
    assert!(
        matches!(&dns[0].kind, ObservationKind::DnsFailed { hostname, rcode: Some(DnsRcode::NxDomain) } if hostname == "db.internal")
    );
    assert!(dns[0].relevance.score >= CANDIDATE_THRESHOLD);
}

#[test]
fn shell_command_not_found() {
    let stat = |seq, p: &str| {
        ev(
            seq,
            1,
            EventKind::PathOpFailed {
                op: "stat".into(),
                path: p.into(),
                requested: None,
                error: Errno::new("ENOENT"),
            },
        )
    };
    let events = vec![
        exec(0, 1, "/bin/sh"),
        stat(1, "/usr/local/bin/nosuch"),
        stat(2, "/usr/bin/nosuch"),
        stat(3, "/bin/nosuch"),
        stderr(4, 1, "sh: 1: nosuch: not found\n"),
        ev(5, 1, EventKind::ProcessExited { code: 127 }),
    ];
    let tree = ProcessTree::build(&events);
    let set = extract(&events, &tree);
    let top = &set.observations[0];
    assert!(
        matches!(&top.kind, ObservationKind::ExecFailed { executable, .. } if executable == "nosuch"),
        "{:?}",
        top
    );
    assert!(top.relevance.score >= CANDIDATE_THRESHOLD);
}

#[test]
fn token_matching() {
    assert!(contains_token(
        "connect ECONNREFUSED 127.0.0.1:5432",
        ":5432"
    ));
    assert!(!contains_token("port 54321", "port 5432"));
    assert!(contains_token("x port 5432.", "port 5432"));
    assert!(!contains_token("", "x"));
    assert!(contains_token("héllo :80 wörld", ":80"));
}
