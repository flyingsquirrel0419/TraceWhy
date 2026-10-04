use super::*;
use tracewhy_core::{Conclusion, ConclusionStatus};
use tracewhy_event::{EventKind, OutputStream};

pub fn sample() -> WhyTrace {
    let events = vec![
        Event {
            seq: 0,
            ts: Some(1.0),
            pid: 1,
            tgid: None,
            source: None,
            kind: EventKind::ProcessExec {
                executable: "/bin/app".into(),
                args: vec!["app".into(), "--token".into(), "s3cr3t-value".into()],
            },
        },
        Event {
            seq: 1,
            ts: Some(1.1),
            pid: 1,
            tgid: None,
            source: None,
            kind: EventKind::Output {
                stream: OutputStream::Stderr,
                text: "using sk-abcdefghijklmnopqrstuvwxyz0123 at /home/alice/p".into(),
            },
        },
        Event {
            seq: 2,
            ts: Some(1.2),
            pid: 1,
            tgid: None,
            source: None,
            kind: EventKind::ProcessExited { code: 1 },
        },
    ];
    let tree = ProcessTree::build(&events);
    let mut c = Conclusion::succeeded(Some(ExitStatus::Exited { code: 1 }));
    c.status = ConclusionStatus::Undetermined;
    WhyTrace {
        format: FORMAT_NAME.into(),
        format_version: FORMAT_VERSION,
        tracewhy_version: "1.0.0".into(),
        run: RunInfo {
            command: vec!["app".into(), "--token".into(), "s3cr3t-value".into()],
            cwd: "/home/alice/p".into(),
            platform: "linux".into(),
            arch: "x86_64".into(),
            kernel: None,
            started_at: 1.0,
            duration_ms: 200,
            exit: Some(ExitStatus::Exited { code: 1 }),
            backend: None,
        },
        environment: EnvFingerprint::default(),
        process_tree: tree,
        events,
        observations: Vec::new(),
        facts: Vec::new(),
        graph: CauseGraph::new(),
        investigations: Vec::new(),
        hypotheses: Vec::new(),
        conclusion: c,
        stats: TraceStats::default(),
        redactions: RedactionInfo::default(),
        diagnostics: Vec::new(),
    }
}

#[test]
fn roundtrip_unredacted() {
    let t = sample();
    let json = t.to_json(None).unwrap();
    let back = WhyTrace::from_json("x", &json).unwrap();
    assert_eq!(back.events, t.events);
    assert_eq!(back.run, t.run);
    assert!(!back.redactions.applied);
}

#[test]
fn redacted_export_has_no_secrets() {
    let t = sample();
    let r = Redactor::with_home(Some("/home/alice".into()));
    let json = t.to_json(Some(&r)).unwrap();
    assert!(!json.contains("s3cr3t-value"));
    assert!(!json.contains("sk-abcdefghijklmnopqrstuvwxyz0123"));
    assert!(!json.contains("/home/alice"));
    let back = WhyTrace::from_json("x", &json).unwrap();
    assert!(back.redactions.applied);
    assert!(back.redactions.counts.values().sum::<u64>() >= 3);
}

#[test]
fn rejects_bad_files() {
    assert!(matches!(
        WhyTrace::from_json("x", "{}"),
        Err(FormatError::Invalid(..))
    ));
    assert!(matches!(
        WhyTrace::from_json("x", "not json"),
        Err(FormatError::Invalid(..))
    ));
    assert!(matches!(
        WhyTrace::from_json("x", r#"{"format":"whytrace","format_version":99}"#),
        Err(FormatError::UnsupportedVersion(_, 99))
    ));
    assert!(WhyTrace::from_json("x", r#"{"format":"whytrace","format_version":1}"#).is_err());
}

#[test]
fn tolerates_unknown_fields() {
    let json = sample().to_json(None).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["future_field"] = serde_json::json!({"x": 1});
    assert!(WhyTrace::from_json("x", &v.to_string()).is_ok());
}

#[test]
fn file_write_and_read() {
    let dir = std::env::temp_dir().join(format!("tw-fmt-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("t.whytrace");
    sample().write(&p, None).unwrap();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(WhyTrace::read(&p).unwrap().run.duration_ms, 200);
    let _ = std::fs::remove_dir_all(dir);
}
