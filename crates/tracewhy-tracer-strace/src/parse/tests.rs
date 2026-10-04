use super::*;

fn rec(p: &mut LineParser, l: &str) -> RawRecord {
    match p.parse_line(1, l) {
        LineResult::Record(r) => r,
        other => panic!("expected record for {l:?}, got {other:?}"),
    }
}

#[test]
fn parses_basic_syscall() {
    let mut p = LineParser::new();
    let r = rec(
        &mut p,
        r#"355805 1791087545.226838 openat(AT_FDCWD</tmp/s>, "/nonexistent", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
    );
    assert_eq!(r.pid, Some(355805));
    assert!(r.ts.is_some());
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!(sc.name, "openat");
    assert_eq!(sc.args, r#"AT_FDCWD</tmp/s>, "/nonexistent", O_RDONLY"#);
    assert_eq!(sc.ret.value, Some(-1));
    assert_eq!(sc.ret.errno.as_deref(), Some("ENOENT"));
}

#[test]
fn parses_fd_annotation_return() {
    let mut p = LineParser::new();
    let r = rec(
        &mut p,
        r#"1 2.5 openat(AT_FDCWD</x>, "/etc/hosts", O_RDONLY|O_CLOEXEC) = 3</etc/hosts>"#,
    );
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!(sc.ret.value, Some(3));
    assert_eq!(sc.ret.annotation.as_deref(), Some("/etc/hosts"));
    assert!(sc.ret.ok());
}

#[test]
fn stitches_unfinished_and_resumed() {
    let mut p = LineParser::new();
    assert_eq!(
        p.parse_line(1, "10 1.0 read(3,  <unfinished ...>"),
        LineResult::Pending
    );
    let r = rec(&mut p, r#"10 1.1 <... read resumed>"abc", 10) = 3"#);
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!(sc.name, "read");
    assert_eq!(sc.args, r#"3, "abc", 10"#);
    assert_eq!(sc.ret.value, Some(3));
    assert_eq!(p.pending_count(), 0);
}

#[test]
fn interleaved_pids_unfinished() {
    let mut p = LineParser::new();
    p.parse_line(1, "1 1.0 vfork( <unfinished ...>");
    p.parse_line(
        2,
        r#"2 1.1 execve("/bin/cat", ["cat"], 0x1 /* 5 vars */ <unfinished ...>"#,
    );
    let r = rec(&mut p, "1 1.2 <... vfork resumed>) = 2");
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!((sc.name.as_str(), sc.ret.value), ("vfork", Some(2)));
    let r = rec(&mut p, "2 1.3 <... execve resumed>) = 0");
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!(sc.name, "execve");
    assert!(sc.args.contains("/bin/cat"));
}

#[test]
fn parses_exit_and_signals() {
    let mut p = LineParser::new();
    assert_eq!(
        rec(&mut p, "5 1.0 +++ exited with 7 +++").kind,
        RawKind::Exited { code: 7 }
    );
    assert_eq!(
        rec(&mut p, "5 1.0 +++ killed by SIGSEGV (core dumped) +++").kind,
        RawKind::Killed {
            signal: "SIGSEGV".into(),
            core_dumped: true
        }
    );
    assert_eq!(
        rec(
            &mut p,
            "5 1.0 --- SIGPIPE {si_signo=SIGPIPE, si_code=SI_USER} ---"
        )
        .kind,
        RawKind::Signal {
            name: "SIGPIPE".into()
        }
    );
}

#[test]
fn handles_parens_and_quotes_in_strings() {
    let mut p = LineParser::new();
    let r = rec(
        &mut p,
        r#"1 write(2</dev/pts/0>, "error: (x) = \"y\" )", 19) = 19"#,
    );
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!(sc.name, "write");
    assert_eq!(sc.ret.value, Some(19));
}

#[test]
fn exit_group_unknown_return() {
    let mut p = LineParser::new();
    let r = rec(&mut p, "1 1.0 exit_group(1)                     = ?");
    let RawKind::Syscall(sc) = r.kind else {
        panic!()
    };
    assert_eq!(sc.ret.value, None);
}

#[test]
fn tolerates_garbage() {
    let mut p = LineParser::new();
    for l in [
        "",
        "garbage",
        "1 2 3",
        "(((",
        "<... resumed>",
        "123 <... foo resumed>",
        "x(\"unterminated",
        "1 1.0 +++ +++",
        "--- ---",
        "\u{0}\u{1}",
    ] {
        let _ = p.parse_line(1, l);
    }
}

#[test]
fn without_pid_prefix_and_tt_time() {
    let mut p = LineParser::new();
    let r = rec(&mut p, r#"12:00:01.500000 close(3) = 0"#);
    assert_eq!(r.pid, None);
    assert_eq!(r.ts, Some(43201.5));
    let r = rec(
        &mut p,
        r#"[pid  42] connect(3, {sa_family=AF_UNIX, sun_path="/x"}, 110) = -1 ENOENT (No such file or directory)"#,
    );
    assert_eq!(r.pid, Some(42));
}

#[test]
fn ret_with_flags_text() {
    let r = parse_ret("0 (Timeout)");
    assert_eq!(r.value, Some(0));
    let r = parse_ret("? ERESTARTSYS (To be restarted if SA_RESTART is set)");
    assert_eq!(r.errno.as_deref(), Some("ERESTARTSYS"));
    let r = parse_ret("21<TCP:[127.0.0.1:1->127.0.0.1:2]>");
    assert_eq!(
        r.annotation.as_deref(),
        Some("TCP:[127.0.0.1:1->127.0.0.1:2]")
    );
    let r = parse_ret("0x7f12 ");
    assert_eq!(r.value, Some(0x7f12));
}
