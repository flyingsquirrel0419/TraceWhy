use super::*;

fn r() -> Redactor {
    Redactor::with_home(Some("/home/alice".into()))
}

#[test]
fn rules_all_compile() {
    assert_eq!(r().rule_count(), RULE_COUNT);
}

#[test]
fn redacts_known_tokens() {
    let r = r();
    // Fake tokens are assembled at runtime so the source contains nothing that
    // secret scanners (e.g. GitHub push protection) mistake for a credential.
    let tok = |prefix: &str, body: &str| format!("{prefix}{body}");
    let cases = [
        tok("sk-", "abcdefghijklmnopqrstuvwx123456"),
        tok("ghp_", "0123456789abcdefghijABCDEFGHIJ0123456789"),
        tok("AKIA", "IOSFODNN7EXAMPLE"),
        tok("xoxb-", "1234567890-abcdefghij"),
        tok("sk_li", "ve_4eC39HqLyjWDarjtT1zdp7dc"),
        tok(
            "eyJhbGciOiJIUzI1NiJ9.",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ),
        tok("sk-ant-", "api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
    ];
    for secret in &cases {
        let input = format!("value {secret} used");
        let out = r.redact(&input);
        assert!(!out.contains(secret.as_str()), "{input} -> {out}");
        assert!(out.contains(REDACTED), "{input} -> {out}");
    }
}

#[test]
fn redacts_structured_secrets() {
    let r = r();
    assert_eq!(
        r.redact("Authorization: Bearer abc.def.ghi123"),
        "Authorization: <redacted>"
    );
    assert_eq!(
        r.redact("curl -H 'bearer abcdefgh12345'"),
        "curl -H 'bearer <redacted>'"
    );
    assert_eq!(
        r.redact("postgres://app:hunter22@db:5432/x"),
        "postgres://app:<redacted>@db:5432/x"
    );
    assert_eq!(
        r.redact("https://x.io/cb?code=abc123&state=ok"),
        "https://x.io/cb?code=<redacted>&state=ok"
    );
    assert_eq!(
        r.redact("DB_PASSWORD=hunter22 node app"),
        "DB_PASSWORD=<redacted> node app"
    );
    assert_eq!(
        r.redact("mysql --password=hunter22 -u root"),
        "mysql --password=<redacted> -u root"
    );
    assert_eq!(
        r.redact("app --token s3cr3tvalue"),
        "app --token <redacted>"
    );
    assert_eq!(
        r.redact("curl -u admin:hunter22 https://x"),
        "curl -u admin:<redacted> https://x"
    );
    // `-u root` without a password is left alone.
    assert_eq!(r.redact("mysql -u root"), "mysql -u root");
    assert_eq!(
        r.redact(r#"{"api_key": "abcd1234"}"#),
        r#"{"api_key": "<redacted>"}"#
    );
    let k = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
    assert_eq!(r.redact(k), REDACTED);
}

#[test]
fn home_paths() {
    let r = r();
    assert_eq!(r.redact("/home/alice/project/.env"), "~/project/.env");
    assert_eq!(r.redact("/home/alicex/f"), "/home/<user>/f");
    assert_eq!(r.redact("cd /home/bob/x"), "cd /home/<user>/x");
    assert_eq!(r.redact("/var/home/alice"), "/var/home/alice");
}

#[test]
fn avoids_false_positives() {
    let r = r();
    for s in [
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "connect ECONNREFUSED 127.0.0.1:5432",
        "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "commit 3f2a9c1d8e7b6a5f4e3d2c1b0a9f8e7d6c5b4a39",
        "550e8400-e29b-41d4-a716-446655440000",
        "node_modules/.pnpm/@babel+core@7.24.0_supports-color@5.5.0/node_modules",
        "ERR_MODULE_NOT_FOUND_WHILE_RESOLVING_IMPORT_SPECIFIER",
        "The tokenizer reported keyword arguments",
        "ModuleNotFoundError: No module named 'requests'",
        "password authentication failed for user",
        "key_value pairs",
    ] {
        assert_eq!(r.redact(s), s, "false positive on {s}");
    }
}

#[test]
fn high_entropy_generic() {
    let r = r();
    let out = r.redact("export X=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MEFCQ0RFRkdISUpL");
    assert!(out.contains(REDACTED), "{out}");
    assert!(r.info().counts.values().sum::<u64>() >= 1);
}

#[test]
fn json_values() {
    let r = r();
    let mut v = serde_json::json!({"args": ["--password=x1y2z3", "/home/alice/a"], "n": 1});
    r.redact_value(&mut v);
    assert_eq!(v["args"][0], "--password=<redacted>");
    assert_eq!(v["args"][1], "~/a");
}
