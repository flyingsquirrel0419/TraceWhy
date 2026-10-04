//! Program output handling and mention matching.

use std::collections::HashMap;
use tracewhy_core::ObservationKind;
use tracewhy_event::{Endpoint, Event, EventKind};

pub(crate) struct Output {
    pub seq: u64,
    pub pid: u32,
    pub text: String,
}

/// Program output merged into whole lines per process (programs often
/// write a message in several chunks), tagged with the first chunk's seq.
pub(super) fn merged_outputs(events: &[Event]) -> Vec<Output> {
    let mut out: Vec<Output> = Vec::new();
    let mut open: HashMap<u32, usize> = HashMap::new();
    for e in events {
        let EventKind::Output { text, .. } = &e.kind else {
            continue;
        };
        let pid = e.process();
        match open.get(&pid).copied() {
            Some(i) if out[i].text.len() < 4096 => out[i].text.push_str(text),
            _ => {
                open.insert(pid, out.len());
                out.push(Output {
                    seq: e.seq,
                    pid,
                    text: text.clone(),
                });
            }
        }
        if text.ends_with('\n') {
            open.remove(&pid);
        }
    }
    out
}

/// Output lines (merged per process) that were written after `seq`.
pub fn output_lines_after(events: &[Event], seq: Option<u64>) -> Vec<String> {
    merged_outputs(events)
        .into_iter()
        .filter(|o| seq.map(|s| o.seq > s).unwrap_or(true))
        .flat_map(|o| o.text.lines().map(|l| l.to_string()).collect::<Vec<_>>())
        .collect()
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

pub(super) fn tail_lines(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(n);
    let mut out = lines[start..]
        .iter()
        .map(|l| {
            if l.chars().count() > 200 {
                l.chars().take(197).collect::<String>() + "..."
            } else {
                l.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    if out.len() > 2000 {
        out = out.chars().take(2000).collect();
    }
    out
}

/// True when `token` occurs in `text` not embedded in a longer word/number.
pub fn contains_token(text: &str, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let tb = token.as_bytes();
    let first_alnum = tb
        .first()
        .map(|b| b.is_ascii_alphanumeric())
        .unwrap_or(false);
    let last_alnum = tb
        .last()
        .map(|b| b.is_ascii_alphanumeric())
        .unwrap_or(false);
    let bytes = text.as_bytes();
    let mut start = 0;
    while let Some(pos) = text[start..].find(token) {
        let i = start + pos;
        let j = i + token.len();
        let before_ok = i == 0 || !first_alnum || !is_word(bytes[i - 1]);
        let after_ok = j >= bytes.len() || !last_alnum || !is_word(bytes[j]);
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
        while start < text.len() && !text.is_char_boundary(start) {
            start += 1;
        }
        if start >= text.len() {
            break;
        }
    }
    false
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Tokens whose presence in later output ties it to this observation.
/// `strong` names the specific resource; `weak` only the error class.
pub(super) fn mention_tokens(kind: &ObservationKind) -> (Vec<String>, Vec<String>) {
    let mut strong = Vec::new();
    let mut weak = Vec::new();
    match kind {
        ObservationKind::ExecFailed {
            executable, error, ..
        } => {
            strong.push(format!("{}: not found", basename(executable)));
            strong.push(format!("{}: command not found", basename(executable)));
            strong.push(format!("{}: No such file", basename(executable)));
            strong.push(format!("{}: Permission denied", basename(executable)));
            if executable.contains('/') {
                strong.push(executable.clone());
            }
            weak.push(error.describe().to_string());
            weak.push(error.0.clone());
            weak.push("not found".into());
        }
        ObservationKind::FileAccessFailed {
            path,
            requested,
            error,
            ..
        } => {
            strong.push(path.clone());
            // A bare relative name ("makefile") is too word-like to count as a
            // mention; relative paths ("./config.json", "data/x") are fine.
            if let Some(r) = requested {
                if r.len() >= 3 && (r.contains('/') || r.contains('.')) {
                    strong.push(r.clone());
                }
            }
            let b = basename(path);
            if b.len() >= 5 && b.contains('.') {
                strong.push(b.to_string());
            }
            weak.push(error.describe().to_string());
            weak.push(error.0.clone());
        }
        ObservationKind::ConnectFailed {
            endpoint, error, ..
        } => {
            match endpoint {
                Endpoint::Inet { address, port } => {
                    strong.push(format!(":{port}"));
                    strong.push(format!("{address}:{port}"));
                    strong.push(format!("port {port}"));
                    strong.push(format!("{port} failed"));
                }
                Endpoint::Unix { path } => strong.push(path.clone()),
            }
            weak.push(error.0.clone());
            weak.push(error.describe().to_string());
            weak.push(error.describe().to_lowercase());
        }
        ObservationKind::BindFailed {
            endpoint, error, ..
        } => {
            if let Some(p) = endpoint.port() {
                strong.push(format!(":{p}"));
                strong.push(format!("port {p}"));
            }
            strong.push(error.0.clone());
            weak.push(error.describe().to_string());
            weak.push(error.describe().to_lowercase());
        }
        ObservationKind::DnsFailed { hostname, .. } => {
            strong.push(hostname.clone());
            weak.extend(
                [
                    "ENOTFOUND",
                    "Name or service not known",
                    "getaddrinfo",
                    "Temporary failure in name resolution",
                    "nodename nor servname",
                ]
                .iter()
                .map(|s| s.to_string()),
            );
        }
        ObservationKind::WriteFailed { target, error } => {
            if let Some(t) = target {
                if t.starts_with('/') {
                    strong.push(t.clone());
                }
            }
            strong.push(error.describe().to_string());
            strong.push(error.0.clone());
        }
        ObservationKind::ResourceLimit { error, .. } => {
            strong.push(error.describe().to_string());
            strong.push(error.0.clone());
        }
        ObservationKind::LibraryLoadFailed { library, .. } => {
            strong.push(library.clone());
            weak.push("error while loading shared libraries".into());
        }
        ObservationKind::ProcessCrashed { signal, .. } => {
            weak.push(signal.clone());
            weak.push("Segmentation fault".into());
            weak.push("core dumped".into());
        }
        ObservationKind::Runtime { subject, .. } => strong.push(subject.clone()),
    }
    (strong, weak)
}
