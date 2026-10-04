use super::*;
use tracewhy_event::{FileAccess, OutputStream};

fn norm(text: &str) -> Vec<EventKind> {
    normalize_str(text, NormalizeLimits::default())
        .events
        .into_iter()
        .map(|e| e.kind)
        .collect()
}

#[test]
fn lexical() {
    assert_eq!(lexical_normalize("/a/b/../c/./d"), "/a/c/d");
    assert_eq!(lexical_normalize("/.."), "/");
    assert_eq!(lexical_normalize("a/../../b"), "../b");
}

#[test]
fn relative_open_uses_dirfd_annotation() {
    let ev = norm(
        r#"1 1.0 openat(AT_FDCWD</srv/app>, ".env", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
    );
    assert_eq!(
        ev[0],
        EventKind::FileOpenFailed {
            path: "/srv/app/.env".into(),
            requested: Some(".env".into()),
            access: FileAccess::Read,
            error: Errno::new("ENOENT"),
        }
    );
}

#[test]
fn nonblocking_connect_resolved_by_getsockopt() {
    let ev = norm(concat!(
        "1 1.0 socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, IPPROTO_IP) = 21<TCP:[1]>\n",
        "1 1.1 connect(21<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr(\"127.0.0.1\")}, 16) = -1 EINPROGRESS (Operation now in progress)\n",
        "1 1.2 getsockopt(21<TCP:[1]>, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0\n",
    ));
    assert!(matches!(&ev[0], EventKind::ConnectPending { .. }));
    match &ev[1] {
        EventKind::ConnectFailed {
            endpoint,
            protocol,
            error,
        } => {
            assert_eq!(endpoint.port(), Some(5432));
            assert_eq!(*protocol, Protocol::Tcp);
            assert_eq!(error.as_str(), "ECONNREFUSED");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn threads_share_fd_table() {
    let ev = normalize_str(
        concat!(
            "1 1.0 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, child_tid=0x1}, 88) = 2\n",
            "1 1.1 socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 5<TCP:[1]>\n",
            "1 1.2 connect(5<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr(\"10.0.0.1\")}, 16) = -1 EINPROGRESS (x)\n",
            "2 1.3 getsockopt(5<TCP:[1]>, SOL_SOCKET, SO_ERROR, [0], [4]) = 0\n",
        ),
        NormalizeLimits::default(),
    );
    assert_eq!(
        ev.events[0].kind,
        EventKind::ProcessSpawned {
            child: 2,
            thread: true
        }
    );
    assert!(matches!(
        ev.events.last().map(|e| &e.kind),
        Some(EventKind::Connected { .. })
    ));
    assert_eq!(ev.events.last().map(|e| e.process()), Some(1));
}

#[test]
fn dns_from_connected_udp() {
    let ev = norm(concat!(
        "1 1.0 connect(3<UDP:[9]>, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr(\"127.0.0.53\")}, 16) = 0\n",
        r#"1 1.1 sendmmsg(3<UDP:[127.0.0.1:48344->127.0.0.53:53]>, [{msg_hdr={msg_name=NULL, msg_namelen=0, msg_iov=[{iov_base="\366\301\1 \0\1\0\0\0\0\0\1\2db\7invalid\0\0\1\0\1\0\0)\4\260\0\0\0\0\0\0", iov_len=39}], msg_iovlen=1, msg_controllen=0, msg_flags=0}, msg_len=39}], 1, MSG_NOSIGNAL) = 1"#, "\n",
        r#"1 1.2 recvfrom(3<UDP:[127.0.0.1:48344->127.0.0.53:53]>, "\366\301\205\243\0\1\0\0\0\0\0\1\2db\7invalid\0\0\1\0\1\0\0)\377\326\0\0\0\0\0\0", 2048, 0, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, [28 => 16]) = 39"#, "\n",
    ));
    assert!(ev
        .iter()
        .any(|e| matches!(e, EventKind::DnsQuery { hostname, .. } if hostname == "db.invalid")));
    assert!(ev.iter().any(|e| matches!(e, EventKind::DnsAnswer { hostname, rcode: tracewhy_event::DnsRcode::NxDomain, .. } if hostname == "db.invalid")));
}

#[test]
fn stderr_output_and_write_failure() {
    let ev = norm(concat!(
        "1 1.0 write(2</dev/pts/1>, \"oops\\n\", 5) = 5\n",
        "1 1.1 writev(2</dev/pts/1>, [{iov_base=\"a\", iov_len=1}, {iov_base=\"b\", iov_len=1}], 2) = 2\n",
        "1 1.2 write(3</data/out.bin>, \"x\"..., 4096) = -1 ENOSPC (No space left on device)\n",
        "1 1.3 write(1</data/out.bin>, \"data\", 4) = 4\n",
        "1 1.4 write(2</dev/pts/0<char 136:0>>, \"\\0\\0\\0\\0\\0\", 5) = 5\n",
    ));
    assert_eq!(
        ev.len(),
        3,
        "file-redirected stdout and binary output are not program output"
    );
    assert_eq!(
        ev[0],
        EventKind::Output {
            stream: OutputStream::Stderr,
            text: "oops\n".into()
        }
    );
    assert_eq!(
        ev[1],
        EventKind::Output {
            stream: OutputStream::Stderr,
            text: "ab".into()
        }
    );
    assert_eq!(
        ev[2],
        EventKind::WriteFailed {
            target: Some("/data/out.bin".into()),
            error: Errno::new("ENOSPC")
        }
    );
}

#[test]
fn output_budget_keeps_tail() {
    let mut text = String::new();
    for i in 0..100 {
        text.push_str(&format!(
            "1 1.0 write(2, \"line{i:03} {}\\n\", 100) = 100\n",
            "x".repeat(90)
        ));
    }
    let t = normalize_str(
        &text,
        NormalizeLimits {
            max_output_bytes_per_process: 1000,
            ..Default::default()
        },
    );
    let outs: Vec<_> = t
        .events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::Output { .. }))
        .collect();
    assert!(outs.len() <= 11);
    assert!(
        matches!(&outs.last().unwrap().kind, EventKind::Output { text, .. } if text.contains("line099"))
    );
}

#[test]
fn bind_and_exec_failures() {
    let ev = norm(concat!(
        "1 1.0 bind(3<TCP:[1]>, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr(\"0.0.0.0\")}, 16) = -1 EADDRINUSE (Address already in use)\n",
        "1 1.1 execve(\"/usr/local/bin/foo\", [\"foo\", \"x\"], 0x1 /* 3 vars */) = -1 ENOENT (No such file or directory)\n",
        "1 1.2 newfstatat(AT_FDCWD</w>, \"/usr/bin/foo\", 0x7f, 0) = -1 ENOENT (No such file or directory)\n",
    ));
    assert!(
        matches!(&ev[0], EventKind::BindFailed { error, .. } if error.as_str() == "EADDRINUSE")
    );
    assert!(
        matches!(&ev[1], EventKind::ExecFailed { executable, args, .. } if executable == "/usr/local/bin/foo" && args.len() == 2)
    );
    assert!(
        matches!(&ev[2], EventKind::PathOpFailed { op, path, .. } if op == "stat" && path == "/usr/bin/foo")
    );
}

#[test]
fn event_limit_keeps_failures() {
    let mut text = String::new();
    for _ in 0..50 {
        text.push_str("1 1.0 openat(AT_FDCWD</>, \"/ok\", O_RDONLY) = 3</ok>\n");
    }
    text.push_str("1 1.0 openat(AT_FDCWD</>, \"/missing\", O_RDONLY) = -1 ENOENT (x)\n");
    let t = normalize_str(
        &text,
        NormalizeLimits {
            max_events: 10,
            ..Default::default()
        },
    );
    assert!(t.stats.truncated);
    assert!(t.events.iter().any(|e| e.is_failure()));
    assert!(t.events.len() <= 11);
}
