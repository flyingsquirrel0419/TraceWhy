//! DNS failure grouping.

use super::index::SuccessIndex;
use super::RawObs;
use std::collections::HashMap;
use tracewhy_core::ObservationKind;
use tracewhy_event::{Event, EventKind};

/// DNS: group failed answers under the name the program asked for (the
/// shortest queried prefix, before resolver search-domain expansion).
pub(super) fn dns_failures(
    events: &[Event],
    failures: Vec<&Event>,
    index: &SuccessIndex,
    raw: &mut Vec<RawObs>,
) {
    let queried: Vec<&str> = events
        .iter()
        .filter_map(|e| match &e.kind {
            EventKind::DnsQuery { hostname, .. } => Some(hostname.as_str()),
            _ => None,
        })
        .collect();
    let mut dns_groups: HashMap<(u32, String), Vec<&Event>> = HashMap::new();
    for e in failures {
        if let EventKind::DnsAnswer { hostname, .. } = &e.kind {
            let base = queried
                .iter()
                .filter(|q| hostname == *q || hostname.starts_with(&format!("{q}.")))
                .min_by_key(|q| q.len())
                .map(|q| q.to_string())
                .unwrap_or_else(|| hostname.clone());
            dns_groups.entry((e.process(), base)).or_default().push(e);
        }
    }
    for ((pid, host), evs) in dns_groups {
        if index.resolved(&host) {
            continue;
        }
        let rcode = evs.iter().find_map(|e| match &e.kind {
            EventKind::DnsAnswer {
                hostname, rcode, ..
            } if *hostname == host => Some(*rcode),
            _ => None,
        });
        let rcode = rcode.or_else(|| {
            evs.first().and_then(|e| match &e.kind {
                EventKind::DnsAnswer { rcode, .. } => Some(*rcode),
                _ => None,
            })
        });
        raw.push((
            ObservationKind::DnsFailed {
                hostname: host,
                rcode,
            },
            pid,
            evs.iter().map(|e| e.seq).collect(),
            evs.last().and_then(|e| e.ts),
            0.4,
        ));
    }
}
