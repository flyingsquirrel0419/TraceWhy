use super::*;

fn p(s: &[&str]) -> Parsed {
    parse(&s.iter().map(|x| x.to_string()).collect::<Vec<_>>()).unwrap()
}

fn argv(s: &[&str]) -> Vec<String> {
    s.iter().map(|x| x.to_string()).collect()
}

#[test]
fn passes_commands_through_verbatim() {
    assert_eq!(
        p(&["npm", "run", "dev", "--", "--port", "3000"]).cmd,
        Cmd::Run {
            argv: argv(&["npm", "run", "dev", "--", "--port", "3000"])
        }
    );
    assert_eq!(
        p(&["python", "app.py", "hello world"]).cmd,
        Cmd::Run {
            argv: argv(&["python", "app.py", "hello world"])
        }
    );
    assert_eq!(
        p(&["bash", "-c", "echo foo"]).cmd,
        Cmd::Run {
            argv: argv(&["bash", "-c", "echo foo"])
        }
    );
    assert_eq!(
        p(&["env", "DEBUG=1", "node", "server.js"]).cmd,
        Cmd::Run {
            argv: argv(&["env", "DEBUG=1", "node", "server.js"])
        }
    );
    assert_eq!(
        p(&["ls", "-la", "--json"]).cmd,
        Cmd::Run {
            argv: argv(&["ls", "-la", "--json"])
        }
    );
}

#[test]
fn options_before_command() {
    let r = p(&["--verbose", "--json", "-o", "x.whytrace", "make"]);
    assert!(r.opts.verbose && r.opts.json);
    assert_eq!(r.opts.output.as_deref(), Some("x.whytrace"));
    assert_eq!(
        r.cmd,
        Cmd::Run {
            argv: argv(&["make"])
        }
    );
}

#[test]
fn double_dash_forces_command() {
    assert_eq!(
        p(&["--", "show", "x"]).cmd,
        Cmd::Run {
            argv: argv(&["show", "x"])
        }
    );
    assert_eq!(
        p(&["--", "-weird"]).cmd,
        Cmd::Run {
            argv: argv(&["-weird"])
        }
    );
}

#[test]
fn subcommands() {
    assert_eq!(
        p(&["show", "a.whytrace"]).cmd,
        Cmd::Show {
            file: "a.whytrace".into()
        }
    );
    assert_eq!(
        p(&["diff", "a", "b"]).cmd,
        Cmd::Diff {
            good: "a".into(),
            bad: "b".into()
        }
    );
    let r = p(&["record", "-o", "run.whytrace", "cargo", "run", "-o", "x"]);
    assert_eq!(r.opts.output.as_deref(), Some("run.whytrace"));
    assert_eq!(
        r.cmd,
        Cmd::Record {
            argv: argv(&["cargo", "run", "-o", "x"])
        }
    );
    assert_eq!(p(&["doctor"]).cmd, Cmd::Doctor);
    assert_eq!(p(&[]).cmd, Cmd::Help);
    assert!(p(&["explain", "--json", "f"]).opts.json);
}

#[test]
fn errors() {
    let e = |s: &[&str]| parse(&argv(s)).is_err();
    assert!(e(&["--bogus", "ls"]));
    assert!(e(&["diff", "only-one"]));
    assert!(e(&["show"]));
    assert!(e(&["--color", "purple", "ls"]));
    assert!(e(&["record"]));
}
