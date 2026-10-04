//! Real strace captures (paths sanitized) normalized end to end.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tracewhy_event::{EventKind, ExitStatus, ProcessTree};
use tracewhy_tracer_strace::{normalize_str, NormalizeLimits, NormalizedTrace};

fn load(name: &str) -> NormalizedTrace {
    let path = format!("{}/tests/corpus/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(path).unwrap();
    normalize_str(&text, NormalizeLimits::default())
}

#[test]
fn shell_with_missing_file_and_unknown_command() {
    let t = load("sh-cat-missing-and-not-found.strace");
    assert_eq!(t.stats.unparsed_lines, 0, "{:?}", t.diagnostics);
    let tree = ProcessTree::build(&t.events);
    assert_eq!(tree.root_exit(), Some(&ExitStatus::Exited { code: 3 }));
    assert_eq!(tree.process_count(), 2);
    assert!(t.events.iter().any(|e| matches!(&e.kind,
        EventKind::FileOpenFailed { path, error, .. } if path == "/nonexistent" && error.as_str() == "ENOENT")));
    assert!(t.events.iter().any(|e| matches!(&e.kind,
        EventKind::PathOpFailed { path, .. } if path == "/usr/bin/nosuchcmd")));
    let stderr: String = t
        .events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::Output { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert!(stderr.contains("nosuchcmd: not found"));
}

#[test]
fn python_blocking_connect_refused() {
    let t = load("python-connect-refused.strace");
    assert_eq!(t.stats.unparsed_lines, 0, "{:?}", t.diagnostics);
    assert!(t.events.iter().any(|e| matches!(&e.kind,
        EventKind::ConnectFailed { endpoint, error, .. } if endpoint.port() == Some(5999) && error.as_str() == "ECONNREFUSED")));
}

#[test]
fn node_nonblocking_connect_refused() {
    let t = load("node-connect-refused.strace");
    assert_eq!(t.stats.unparsed_lines, 0, "{:?}", t.diagnostics);
    let tree = ProcessTree::build(&t.events);
    assert_eq!(tree.root_exit(), Some(&ExitStatus::Exited { code: 1 }));
    let refused: Vec<_> = t
        .events
        .iter()
        .filter(|e| {
            matches!(&e.kind,
        EventKind::ConnectFailed { error, .. } if error.as_str() == "ECONNREFUSED")
        })
        .collect();
    assert_eq!(refused.len(), 1);
    // node is multi-threaded: threads must fold into one process.
    assert_eq!(tree.process_count(), 1);
}

#[test]
fn python_dns_nxdomain() {
    let t = load("python-dns-nxdomain.strace");
    assert!(t.events.iter().any(|e| matches!(&e.kind,
        EventKind::DnsAnswer { hostname, rcode: tracewhy_event::DnsRcode::NxDomain, .. } if hostname == "db.invalid")));
}
