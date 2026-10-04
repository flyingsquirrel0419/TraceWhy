//! Small classification helpers for the normalizer.

use tracewhy_event::{EventKind, Protocol};

/// fd 1/2 count as program output only when they are a terminal, pipe,
/// socket or /dev/null — not when redirected to a regular file (`dd of=`).
pub(super) fn is_console_like(annotation: Option<&str>) -> bool {
    match annotation {
        None => true,
        Some(a) => {
            a.starts_with("/dev/")
                || a.starts_with("pipe:")
                || a.starts_with("socket:")
                || a.starts_with("UNIX")
                || a.starts_with("TCP")
                || a.contains("<char ")
        }
    }
}

/// Mostly printable text (program messages), not binary payloads.
pub(super) fn looks_textual(b: &[u8]) -> bool {
    let bad = b
        .iter()
        .filter(|c| (**c < 0x20 && !matches!(**c, b'\n' | b'\r' | b'\t' | 0x1b)) || **c == 0x7f)
        .count();
    bad * 10 <= b.len()
}

/// Events that must survive event-limit truncation.
pub(super) fn is_essential(kind: &EventKind) -> bool {
    kind.error().is_some()
        || matches!(
            kind,
            EventKind::ProcessSpawned { .. }
                | EventKind::ProcessExec { .. }
                | EventKind::ProcessExited { .. }
                | EventKind::ProcessKilled { .. }
                | EventKind::SignalReceived { .. }
                | EventKind::DnsAnswer { .. }
        )
}

pub(super) fn protocol_from(annotation: &str, socket_args: &str) -> Protocol {
    let a = annotation;
    if a.starts_with("TCP")
        || socket_args.contains("SOCK_STREAM") && socket_args.contains("AF_INET")
    {
        Protocol::Tcp
    } else if a.starts_with("UDP")
        || socket_args.contains("SOCK_DGRAM") && socket_args.contains("AF_INET")
    {
        Protocol::Udp
    } else if a.starts_with("UNIX") || socket_args.contains("AF_UNIX") {
        Protocol::Unix
    } else {
        Protocol::Other
    }
}
