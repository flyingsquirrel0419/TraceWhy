//! Collapsing a run into semantic operations, and noise weighting.

use std::collections::BTreeMap;
use tracewhy_core::ObservationKind;
use tracewhy_event::{DnsRcode, Event, EventKind};
use tracewhy_format::WhyTrace;

/// Aggregated outcome of one semantic operation across a run.
#[derive(Debug, Clone)]
pub(crate) struct Op {
    pub outcome: String,
    pub ok: bool,
    pub first_seq: u64,
}

const NOISE_PREFIXES: &[&str] = &[
    "/proc/",
    "/sys/",
    "/dev/",
    "/tmp/",
    "/var/tmp/",
    "/run/user/",
    "/usr/lib/locale",
    "/usr/share/locale",
    "/usr/lib/x86_64-linux-gnu/gconv",
    "/usr/lib/aarch64-linux-gnu/gconv",
    "/etc/ld.so",
    "/usr/share/zoneinfo",
];

pub(crate) fn noise_weight(key: &str) -> f64 {
    let path = key.split_once(':').map(|x| x.1).unwrap_or(key);
    if NOISE_PREFIXES.iter().any(|p| path.starts_with(p))
        || path.contains("/__pycache__/")
        || path.contains("/.cache/")
        || path.ends_with(".pyc")
        || path.contains("/node_modules/.cache")
    {
        0.1
    } else if key.starts_with("dns:")
        || key.starts_with("connect:")
        || key.starts_with("bind:")
        || key.starts_with("exit:")
    {
        1.0
    } else if key.starts_with("exec:") {
        0.9
    } else {
        0.6
    }
}

pub(crate) fn normalize_path(p: &str) -> String {
    // /proc/1234/... → /proc/<pid>/...
    if let Some(rest) = p.strip_prefix("/proc/") {
        let mut it = rest.splitn(2, '/');
        let first = it.next().unwrap_or("");
        if !first.is_empty() && first.bytes().all(|b| b.is_ascii_digit()) {
            return format!("/proc/<pid>/{}", it.next().unwrap_or(""));
        }
    }
    p.to_string()
}

pub(crate) fn base(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// Collapse a run into `key → outcome` for every semantic operation.
pub(crate) fn operations(events: &[Event], t: &WhyTrace) -> BTreeMap<String, Op> {
    let mut ops: BTreeMap<String, Op> = BTreeMap::new();
    let mut put = |key: String, outcome: String, ok: bool, seq: u64| {
        ops.entry(key)
            .and_modify(|o| {
                // A success anywhere wins (retries, PATH search, fallbacks).
                if ok && !o.ok {
                    o.ok = true;
                    o.outcome = outcome.clone();
                } else if !o.ok && !ok {
                    o.outcome = outcome.clone();
                }
            })
            .or_insert(Op {
                outcome,
                ok,
                first_seq: seq,
            });
    };
    for e in events {
        match &e.kind {
            EventKind::ProcessExec { executable, .. } => put(
                format!("exec:{}", base(executable)),
                "ok".into(),
                true,
                e.seq,
            ),
            EventKind::ExecFailed {
                executable, error, ..
            } => put(
                format!("exec:{}", base(executable)),
                error.0.clone(),
                false,
                e.seq,
            ),
            EventKind::FileOpened { path, .. } => put(
                format!("file:{}", normalize_path(path)),
                "ok".into(),
                true,
                e.seq,
            ),
            EventKind::FileOpenFailed { path, error, .. }
            | EventKind::PathOpFailed { path, error, .. } => put(
                format!("file:{}", normalize_path(path)),
                error.0.clone(),
                false,
                e.seq,
            ),
            EventKind::Connected { endpoint, protocol }
                if *protocol != tracewhy_event::Protocol::Udp =>
            {
                put(
                    format!("connect:{endpoint}"),
                    "connected".into(),
                    true,
                    e.seq,
                )
            }
            EventKind::ConnectFailed {
                endpoint, error, ..
            } => put(format!("connect:{endpoint}"), error.0.clone(), false, e.seq),
            EventKind::Bound { endpoint, .. } => {
                put(format!("bind:{endpoint}"), "bound".into(), true, e.seq)
            }
            EventKind::BindFailed {
                endpoint, error, ..
            } => put(format!("bind:{endpoint}"), error.0.clone(), false, e.seq),
            EventKind::DnsAnswer {
                hostname,
                rcode,
                addresses,
                ..
            } => {
                if *rcode == DnsRcode::NoError && addresses.is_empty() {
                    continue;
                }
                let ok = !addresses.is_empty();
                let outcome = if ok {
                    let mut a: Vec<String> = addresses.iter().map(|a| a.to_string()).collect();
                    a.sort();
                    a.dedup();
                    a.join(", ")
                } else {
                    rcode.label()
                };
                // Search-domain expansions roll up into the requested name.
                let host = requested_host(events, hostname);
                put(format!("dns:{host}"), outcome, ok, e.seq);
            }
            EventKind::WriteFailed { target, error } => put(
                format!("write:{}", target.clone().unwrap_or_default()),
                error.0.clone(),
                false,
                e.seq,
            ),
            _ => {}
        }
    }
    for p in t
        .process_tree
        .processes
        .values()
        .filter(|p| p.thread_of.is_none())
    {
        if let (Some(exe), Some(st)) = (&p.executable, &p.exit) {
            put(
                format!("exit:{}", base(exe)),
                st.describe(),
                st.success(),
                p.exit_seq.unwrap_or(p.last_seq),
            );
        }
    }
    ops
}

pub(crate) fn requested_host(events: &[Event], answered: &str) -> String {
    events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::DnsQuery { hostname, .. }
                if answered == hostname || answered.starts_with(&format!("{hostname}.")) =>
            {
                Some(hostname.as_str())
            }
            _ => None,
        })
        .min_by_key(|h| h.len())
        .unwrap_or(answered)
        .to_string()
}

pub(crate) fn raw_key(e: &Event) -> String {
    format!("{}:{}:{:?}", e.pid, e.kind.name(), e.kind)
}

/// Key of the broken run's root-cause observation, if it maps to an operation.
pub(crate) fn cause_key(t: &WhyTrace) -> Option<String> {
    let id = t.conclusion.root_cause.as_ref()?.observation;
    let o = t.observations.iter().find(|o| o.id == id)?;
    Some(match &o.kind {
        ObservationKind::ConnectFailed { endpoint, .. } => format!("connect:{endpoint}"),
        ObservationKind::BindFailed { endpoint, .. } => format!("bind:{endpoint}"),
        ObservationKind::DnsFailed { hostname, .. } => format!("dns:{hostname}"),
        ObservationKind::FileAccessFailed { path, .. } => format!("file:{}", normalize_path(path)),
        ObservationKind::ExecFailed { executable, .. } => format!("exec:{}", base(executable)),
        ObservationKind::WriteFailed { target, .. } => {
            format!("write:{}", target.clone().unwrap_or_default())
        }
        _ => return None,
    })
}
