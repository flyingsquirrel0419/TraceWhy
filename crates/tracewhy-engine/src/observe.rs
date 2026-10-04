//! Observation extraction: from semantic events to failure symptoms, each
//! scored for how strongly it is tied to the command's failure.
//!
//! Most failed syscalls are harmless (search-path probes, optional config
//! files, fallbacks). Relevance scoring is where false positives are
//! prevented: a symptom only becomes a root-cause candidate when it was not
//! recovered from and is tied to the failure by position, process lineage,
//! or the program's own error output.

mod detect;
mod dns;
mod index;
mod score;
mod text;

pub use text::{basename, contains_token, output_lines_after};

use index::SuccessIndex;
use std::collections::HashSet;
use text::{merged_outputs, tail_lines};
use tracewhy_core::{Observation, ObservationKind};
use tracewhy_event::{Event, ProcessTree};

/// Score above which an observation can be a root-cause candidate.
pub const CANDIDATE_THRESHOLD: f64 = 0.5;

/// glibc and friends probe these on every run; failures are never meaningful.
pub(crate) const BENIGN_PATHS: &[&str] = &[
    "/var/run/nscd/socket",
    "/run/nscd/socket",
    "/etc/ld.so.preload",
    "/etc/suid-debug",
];

/// An observation before relevance scoring: (kind, pid, event seqs, ts, base score).
pub(crate) type RawObs = (ObservationKind, u32, Vec<u64>, Option<f64>, f64);

pub struct ObservationSet {
    pub observations: Vec<Observation>,
    pub failure_chain: Vec<u32>,
    /// Captured stderr/stdout tail of the failing process.
    pub stderr_excerpt: Option<String>,
}

pub fn extract(events: &[Event], tree: &ProcessTree) -> ObservationSet {
    let chain = tree.failure_chain();
    let culprit = chain.last().copied();
    let chain_set: HashSet<u32> = chain.iter().copied().collect();
    let outputs = merged_outputs(events);
    let index = SuccessIndex::build(events, tree);

    let mut raw: Vec<RawObs> = Vec::new();
    let exec_attempts = detect::exec_failures(events, &index, &mut raw);
    detect::shell_not_found(events, tree, &index, &outputs, &exec_attempts, &mut raw);
    detect::library_failures(events, tree, &index, &outputs, &mut raw);
    let dns = detect::event_symptoms(events, tree, &mut raw);
    dns::dns_failures(events, dns, &index, &mut raw);

    let observations = score::score(raw, tree, &index, &outputs, &chain_set, culprit);

    let stderr_excerpt = culprit.and_then(|c| {
        let mut pids: Vec<u32> = vec![c];
        pids.extend(chain.iter().rev().skip(1).copied());
        pids.into_iter().find_map(|p| {
            let text: String = outputs
                .iter()
                .filter(|o| o.pid == p)
                .map(|o| o.text.as_str())
                .collect();
            let tail = tail_lines(&text, 6);
            (!tail.trim().is_empty()).then_some(tail)
        })
    });

    ObservationSet {
        observations,
        failure_chain: chain,
        stderr_excerpt,
    }
}

#[cfg(test)]
mod tests;
