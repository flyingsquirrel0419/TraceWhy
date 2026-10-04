use super::*;

#[test]
fn port_specs() {
    let p = parse_port_spec("5432:5432");
    assert_eq!((p[0].host_port, p[0].container_port), (Some(5432), 5432));
    let p = parse_port_spec("\"127.0.0.1:5433:5432/tcp\"");
    assert_eq!(
        (p[0].host_ip.as_deref(), p[0].host_port, p[0].container_port),
        (Some("127.0.0.1"), Some(5433), 5432)
    );
    let p = parse_port_spec("6379");
    assert_eq!((p[0].host_port, p[0].container_port), (None, 6379));
    assert_eq!(parse_port_spec("8000-8002:9000-9002").len(), 3);
    assert_eq!(
        parse_port_spec("[::1]:80:8080")[0].host_ip.as_deref(),
        Some("::1")
    );
    assert!(parse_port_spec("garbage:x").is_empty());
}

#[test]
fn yaml_subset() {
    let y = r#"
# comment
name: demo
services:
  postgres:
    image: "postgres:16-alpine"
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD", "pg_isready"]
  web:
    image: node:18
    ports: ["3000:3000", "9229"]
    expose:
      - 8080
  cache:
    image: redis
    ports:
      - target: 6379
        published: 6380
volumes:
  data:
"#;
    let s = parse_compose_yaml(y);
    assert_eq!(s.len(), 3);
    assert_eq!(s[0].name, "postgres");
    assert_eq!(s[0].image.as_deref(), Some("postgres:16-alpine"));
    assert_eq!(s[0].ports[0].host_port, Some(5432));
    assert!(s[0].healthcheck);
    assert_eq!(s[1].ports.len(), 2);
    assert_eq!(s[1].expose, vec![8080]);
    assert_eq!(
        (s[2].ports[0].host_port, s[2].ports[0].container_port),
        (Some(6380), 6379)
    );
}

#[test]
fn config_json_and_ps() {
    let j = r#"{"name":"demo","services":{"postgres":{"image":"postgres:16","ports":[{"mode":"ingress","target":5432,"published":"5432","protocol":"tcp"}]}}}"#;
    let (p, s) = from_config_json(j).unwrap();
    assert_eq!(p.as_deref(), Some("demo"));
    assert_eq!(s[0].ports[0].host_port, Some(5432));
    let rows = parse_ps_json(
        "{\"Service\":\"postgres\",\"State\":\"exited\",\"ExitCode\":1}\n{\"Service\":\"web\"}\n",
    );
    assert_eq!(rows.len(), 2);
    assert_eq!(parse_ps_json("[{\"Service\":\"x\"}]").len(), 1);
    let m = parse_ps_ports("0.0.0.0:5432->5432/tcp, :::5432->5432/tcp");
    assert_eq!(m.len(), 1);
    assert_eq!(m[0].host_port, Some(5432));
}

#[test]
fn hostile_yaml_and_port_specs_never_panic() {
    let mut x: u64 = 0x1234_5678_9abc_def0;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let pieces = [
        "services:\n",
        "  a:\n",
        "    ports:\n",
        "      - ",
        "\"80:80\"",
        "target: ",
        "published: ",
        "[",
        "]",
        ",",
        ":",
        "-",
        "\n",
        "    ",
        "expose:",
        "65535",
        "99999",
        "[::1]:",
        "image: x\n",
        "é",
        "#",
    ];
    for _ in 0..5000 {
        let mut s = String::new();
        for _ in 0..(next() % 30) {
            s.push_str(pieces[(next() % pieces.len() as u64) as usize]);
        }
        let _ = parse_compose_yaml(&s);
        let _ = parse_port_spec(&s);
    }
}
