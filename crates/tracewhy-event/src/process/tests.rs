use super::*;

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

fn exec(exe: &str) -> EventKind {
    EventKind::ProcessExec {
        executable: exe.into(),
        args: vec![exe.into()],
    }
}

#[test]
fn builds_tree_and_failure_chain() {
    let events = vec![
        ev(0, 10, exec("/usr/bin/npm")),
        ev(
            1,
            10,
            EventKind::ProcessSpawned {
                child: 11,
                thread: true,
            },
        ),
        ev(
            2,
            10,
            EventKind::ProcessSpawned {
                child: 20,
                thread: false,
            },
        ),
        ev(3, 20, exec("/bin/sh")),
        ev(
            4,
            20,
            EventKind::ProcessSpawned {
                child: 30,
                thread: false,
            },
        ),
        ev(5, 30, exec("/usr/bin/node")),
        ev(6, 30, EventKind::ProcessExited { code: 1 }),
        ev(7, 20, EventKind::ProcessExited { code: 1 }),
        ev(8, 11, EventKind::ProcessExited { code: 0 }),
        ev(9, 10, EventKind::ProcessExited { code: 1 }),
    ];
    let tree = ProcessTree::build(&events);
    assert_eq!(tree.root, Some(10));
    assert_eq!(tree.failure_chain(), vec![10, 20, 30]);
    assert_eq!(tree.group_of(11), 10);
    assert_eq!(tree.lineage(30), vec![10, 20, 30]);
    assert_eq!(tree.process_count(), 3);
}

#[test]
fn success_has_trivial_chain() {
    let events = vec![
        ev(0, 1, exec("/bin/true")),
        ev(1, 1, EventKind::ProcessExited { code: 0 }),
    ];
    let tree = ProcessTree::build(&events);
    assert_eq!(tree.failure_chain(), vec![1]);
}

#[test]
fn killed_child_maps_to_shell_code() {
    let events = vec![
        ev(0, 1, exec("/bin/sh")),
        ev(
            1,
            1,
            EventKind::ProcessSpawned {
                child: 2,
                thread: false,
            },
        ),
        ev(2, 2, EventKind::ProcessExited { code: 2 }),
        ev(
            3,
            1,
            EventKind::ProcessSpawned {
                child: 3,
                thread: false,
            },
        ),
        ev(
            4,
            3,
            EventKind::ProcessKilled {
                signal: "SIGSEGV".into(),
                core_dumped: true,
            },
        ),
        ev(5, 1, EventKind::ProcessExited { code: 139 }),
    ];
    let tree = ProcessTree::build(&events);
    assert_eq!(tree.failure_chain(), vec![1, 3]);
}
