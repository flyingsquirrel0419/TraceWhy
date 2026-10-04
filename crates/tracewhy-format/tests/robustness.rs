//! The .whytrace loader and the redactor must never panic on hostile input.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tracewhy_format::WhyTrace;
use tracewhy_redact::Redactor;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const SAMPLE: &str = r#"{"format":"whytrace","format_version":1,"tracewhy_version":"1.0.0",
"run":{"command":["cat","x"],"cwd":"/w","platform":"linux","arch":"x86_64","started_at":1.0,"duration_ms":3,"exit":{"type":"exited","code":1}},
"events":[{"seq":0,"pid":1,"kind":{"type":"file_open_failed","path":"/w/x","access":"read","error":"ENOENT"}},
{"seq":1,"pid":1,"kind":{"type":"process_exited","code":1}}],
"graph":{"nodes":[{"id":0,"kind":"command","key":"command","label":"cat x"}],"edges":[{"from":0,"to":7,"kind":"spawned"}]},
"conclusion":{"status":"undetermined"}}"#;

#[test]
fn minimal_handwritten_trace_loads() {
    let t = WhyTrace::from_json("sample", SAMPLE).unwrap();
    assert_eq!(t.events.len(), 2);
    // Dangling edge targets must not break graph queries.
    assert!(t
        .graph
        .path(0, 7, &[tracewhy_graph::EdgeKind::Spawned])
        .is_some());
}

#[test]
fn mutated_traces_never_panic() {
    let mut rng = Rng(7);
    let bytes = SAMPLE.as_bytes();
    for _ in 0..5000 {
        let mut b = bytes.to_vec();
        for _ in 0..rng.below(6) + 1 {
            if b.is_empty() {
                break;
            }
            let i = rng.below(b.len());
            match rng.below(4) {
                0 => b[i] = rng.next() as u8,
                1 => {
                    b.remove(i);
                }
                2 => {
                    let alphabet = b"{}[]\":,0-9e";
                    b.insert(i, alphabet[rng.below(alphabet.len())]);
                }
                _ => b.truncate(i),
            }
        }
        let text = String::from_utf8_lossy(&b);
        let _ = WhyTrace::from_json("fuzz", &text);
    }
}

#[test]
fn redactor_never_panics_and_is_idempotent() {
    let r = Redactor::with_home(Some("/home/alice".into()));
    let mut rng = Rng(99);
    let pieces = [
        "token=",
        "sk-",
        "ghp_",
        "Bearer ",
        "https://u:p@h/",
        "?key=",
        "/home/alice",
        "é",
        "\u{0}",
        "AKIA",
        "-----BEGIN RSA PRIVATE KEY-----",
        "--password",
        " ",
        "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7",
    ];
    for _ in 0..3000 {
        let mut s = String::new();
        for _ in 0..rng.below(8) {
            s.push_str(pieces[rng.below(pieces.len())]);
            if rng.below(2) == 0 {
                s.push_str(&format!("{:x}", rng.next()));
            }
        }
        let once = r.redact(&s).into_owned();
        let twice = r.redact(&once).into_owned();
        assert_eq!(once, twice, "redaction must be idempotent for {s:?}");
    }
}
