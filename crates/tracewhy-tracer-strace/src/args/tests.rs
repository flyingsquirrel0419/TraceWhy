use super::*;

#[test]
fn splits_nested() {
    let v = split_args(r#"3, {sa_family=AF_INET, sin_port=htons(80)}, "a,b", [1, 2]"#);
    assert_eq!(v.len(), 4);
    assert_eq!(v[2], r#""a,b""#);
    assert!(split_args("").is_empty());
}

#[test]
fn unescapes() {
    assert_eq!(unescape(r#"a\nb\t\"c\\"#), b"a\nb\t\"c\\".to_vec());
    assert_eq!(unescape(r"\366\1 \0"), vec![0o366, 1, b' ', 0]);
    assert_eq!(unescape(r"\x41\x4a"), b"AJ".to_vec());
    assert_eq!(unescape("trailing\\"), b"trailing\\".to_vec());
}

#[test]
fn strings_and_arrays() {
    assert_eq!(parse_string(r#""hello"..."#).as_deref(), Some("hello"));
    assert_eq!(parse_string_bytes(r#""hello"..."#).map(|x| x.1), Some(true));
    assert_eq!(
        parse_string_array(r#"["sh", "-c", "echo \"hi\", there"]"#),
        vec!["sh", "-c", "echo \"hi\", there"]
    );
    assert_eq!(
        all_strings(r#"[{iov_base="ab", iov_len=2}, {iov_base="c"}]"#).len(),
        2
    );
}

#[test]
fn fds() {
    assert_eq!(
        parse_fd("AT_FDCWD</tmp/x>"),
        Some(FdArg {
            fd: None,
            annotation: Some("/tmp/x".into())
        })
    );
    assert_eq!(
        parse_fd("21<TCP:[3576829]>"),
        Some(FdArg {
            fd: Some(21),
            annotation: Some("TCP:[3576829]".into())
        })
    );
    assert_eq!(
        parse_fd("7"),
        Some(FdArg {
            fd: Some(7),
            annotation: None
        })
    );
    assert_eq!(parse_fd("O_RDONLY"), None);
}

#[test]
fn sockaddrs() {
    assert_eq!(
        parse_sockaddr(
            r#"{sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}"#
        ),
        Some(Endpoint::Inet {
            address: "127.0.0.1".parse().unwrap(),
            port: 5432
        })
    );
    assert_eq!(
        parse_sockaddr(
            r#"{sa_family=AF_INET6, sin6_port=htons(5432), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}"#
        ),
        Some(Endpoint::Inet {
            address: "::1".parse().unwrap(),
            port: 5432
        })
    );
    assert_eq!(
        parse_sockaddr(
            r#"{sa_family=AF_INET6, sin6_port=htons(80), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::ffff:10.0.0.1", &sin6_addr), sin6_scope_id=0}"#
        ),
        Some(Endpoint::Inet {
            address: "10.0.0.1".parse().unwrap(),
            port: 80
        })
    );
    assert_eq!(
        parse_sockaddr(r#"{sa_family=AF_UNIX, sun_path="/run/x.sock"}"#),
        Some(Endpoint::Unix {
            path: "/run/x.sock".into()
        })
    );
    assert_eq!(
        parse_sockaddr(r#"{sa_family=AF_NETLINK, nl_pid=0, nl_groups=00000000}"#),
        None
    );
}

#[test]
fn socket_annotations() {
    assert_eq!(
        parse_socket_annotation("UDP:[127.0.0.1:48344->127.0.0.53:53]"),
        Some((
            "UDP".into(),
            Some("127.0.0.1:48344".into()),
            Some("127.0.0.53:53".into())
        ))
    );
    assert_eq!(
        parse_socket_annotation("TCP:[3576829]"),
        Some(("TCP".into(), None, None))
    );
    assert_eq!(port_of("127.0.0.53:53"), Some(53));
    assert_eq!(port_of("[::1]:53"), Some(53));
}
