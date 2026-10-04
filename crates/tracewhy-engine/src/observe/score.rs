//! Relevance scoring: how strongly each symptom is tied to the failure.

use super::index::SuccessIndex;
use super::text::{contains_token, mention_tokens, Output};
use super::RawObs;
use std::collections::{HashMap, HashSet};
use tracewhy_core::{Observation, ObservationKind, Relevance};
use tracewhy_event::ProcessTree;

pub(super) fn score(
    raw: Vec<RawObs>,
    tree: &ProcessTree,
    index: &SuccessIndex,
    outputs: &[Output],
    chain_set: &HashSet<u32>,
    culprit: Option<u32>,
) -> Vec<Observation> {
    // Deduplicate repeated identical symptoms (retry loops) keeping the last.
    let mut dedup: HashMap<(u32, String), usize> = HashMap::new();
    let mut merged: Vec<RawObs> = Vec::new();
    for item in raw {
        let key = (item.1, format!("{:?}", item.0));
        if let Some(&i) = dedup.get(&key) {
            if let Some(m) = merged.get_mut(i) {
                m.2.extend(item.2);
                m.3 = item.3.or(m.3);
            }
        } else {
            dedup.insert(key, merged.len());
            merged.push(item);
        }
    }

    // Last failing event per process, for "terminal" detection.
    let mut last_failure: HashMap<u32, u64> = HashMap::new();
    for item in &merged {
        if let Some(&s) = item.2.iter().max() {
            let e = last_failure.entry(item.1).or_insert(0);
            *e = (*e).max(s);
        }
    }

    // Which observations the program's later output mentions, by resource
    // (strong) or only by error class (weak).
    let mentions: Vec<(bool, bool)> = merged
        .iter()
        .map(|(kind, pid, seqs, _, _)| {
            let last_seq = seqs.iter().max().copied().unwrap_or(0);
            let (strong, weak) = mention_tokens(kind);
            let mut weak_hit = false;
            for o in outputs
                .iter()
                .filter(|o| o.seq > last_seq && (chain_set.contains(&o.pid) || o.pid == *pid))
            {
                let hit = if matches!(kind, ObservationKind::FileAccessFailed { .. }) {
                    // A path mentioned in passing (build artifacts, logs) is not
                    // a report of this failure: the same line must read as an error.
                    o.text.lines().any(|l| {
                        if !strong.iter().any(|t| contains_token(l, t)) {
                            return false;
                        }
                        // Judge the wording around the path, not the path itself.
                        let mut rest = l.to_string();
                        for t in &strong {
                            rest = rest.replace(t.as_str(), " ");
                        }
                        reads_as_error(&rest, kind)
                    })
                } else {
                    strong.iter().any(|t| contains_token(&o.text, t))
                };
                if hit {
                    return (true, false);
                }
                if weak.iter().any(|t| o.text.contains(t.as_str())) {
                    weak_hit = true;
                }
            }
            (false, weak_hit)
        })
        .collect();
    // An error-class-only mention ("Connection refused") is unambiguous when
    // it is the only failure of that class in the process.
    let mut class_count: HashMap<(u32, &'static str, Option<String>), usize> = HashMap::new();
    for (kind, pid, ..) in &merged {
        *class_count
            .entry((*pid, kind.name(), kind.error_code()))
            .or_insert(0) += 1;
    }
    let mentions: Vec<(bool, bool)> = merged
        .iter()
        .zip(mentions)
        .map(|((kind, pid, ..), (strong, weak))| {
            let unique = class_count
                .get(&(*pid, kind.name(), kind.error_code()))
                .copied()
                == Some(1);
            let specific = matches!(
                kind,
                ObservationKind::ConnectFailed { .. }
                    | ObservationKind::BindFailed { .. }
                    | ObservationKind::DnsFailed { .. }
                    | ObservationKind::WriteFailed { .. }
                    | ObservationKind::ResourceLimit { .. }
            );
            if weak && unique && specific {
                (true, false)
            } else {
                (strong, weak)
            }
        })
        .collect();
    // An error-class-only mention is ambiguous when another failure of the
    // same process was named explicitly.
    let strong_pids: HashSet<u32> = merged
        .iter()
        .zip(&mentions)
        .filter(|(_, m)| m.0)
        .map(|(item, _)| item.1)
        .collect();

    // Paths a process failed to create for a reason other than ENOENT; a later
    // ENOENT on the same path is a consequence, not a separate cause.
    let failed_creates: HashSet<(u32, String)> = merged
        .iter()
        .filter_map(|(kind, pid, ..)| match kind {
            ObservationKind::WriteFailed {
                target: Some(t), ..
            } => Some((*pid, t.clone())),
            ObservationKind::FileAccessFailed {
                path,
                error,
                access:
                    Some(tracewhy_event::FileAccess::Write | tracewhy_event::FileAccess::ReadWrite),
                ..
            } if !error.is("ENOENT") => Some((*pid, path.clone())),
            _ => None,
        })
        .collect();

    let mut observations = Vec::with_capacity(merged.len());
    for ((kind, pid, mut seqs, ts, base), (strong_hit, weak_hit)) in
        merged.into_iter().zip(mentions)
    {
        seqs.sort_unstable();
        let last_seq = seqs.last().copied().unwrap_or(0);
        let mut rel = Relevance {
            score: base,
            ..Relevance::default()
        };
        let mut reasons = Vec::new();
        rel.recovered = index.recovered(&kind, pid, last_seq);
        rel.probe = index.probe(&kind, pid, last_seq);
        let consequence = matches!(&kind, ObservationKind::FileAccessFailed { path, error, .. }
            if error.is("ENOENT") && failed_creates.contains(&(pid, path.clone())));
        rel.on_failure_chain = chain_set.contains(&pid);
        rel.terminal = !rel.recovered
            && !rel.probe
            && last_failure.get(&pid) == Some(&last_seq)
            && tree
                .get(pid)
                .map(|p| p.exit.as_ref().map(|s| !s.success()).unwrap_or(false))
                .unwrap_or(false);
        rel.reported_on_stderr = strong_hit;
        let weak_hit = weak_hit && !strong_pids.contains(&pid);
        if rel.on_failure_chain {
            rel.score += 0.1;
            reasons.push("process is on the failure path".to_string());
            if Some(pid) == culprit {
                rel.score += 0.05;
            }
        }
        if rel.reported_on_stderr {
            rel.score += 0.35;
            reasons.push("the program reported this failure".to_string());
        } else if weak_hit {
            rel.score += 0.15;
            reasons.push("the program reported an error of this kind".to_string());
        }
        if rel.terminal {
            rel.score += 0.1;
            reasons.push("last failure before the process exited".to_string());
        }
        if rel.recovered {
            rel.score *= 0.1;
            reasons.push("the operation later succeeded".to_string());
        }
        if rel.probe {
            rel.score *= 0.1;
            reasons.push("search-path probe; another candidate was used".to_string());
        }
        if consequence {
            rel.score *= 0.3;
            reasons.push("follows an earlier failure to create the same path".to_string());
        }
        // A failure in a process that exited successfully did not cause anything.
        let proc_ok = tree
            .get(pid)
            .and_then(|p| p.exit.as_ref())
            .map(|s| s.success())
            .unwrap_or(false);
        if proc_ok && !rel.reported_on_stderr {
            rel.score *= 0.3;
            reasons.push("its process exited successfully".to_string());
        }
        rel.score = rel.score.clamp(0.0, 1.0);
        rel.reasons = reasons;
        observations.push(Observation {
            id: 0,
            kind,
            pid,
            events: seqs,
            ts,
            relevance: rel,
        });
    }
    observations.sort_by(|a, b| {
        b.relevance
            .score
            .partial_cmp(&a.relevance.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.events.last().cmp(&a.events.last()))
    });
    for (i, o) in observations.iter_mut().enumerate() {
        o.id = i as u32;
    }
    observations
}

/// Whether an output line describes a failure (for the observation's error).
fn reads_as_error(line: &str, kind: &ObservationKind) -> bool {
    let l = line.to_ascii_lowercase();
    if let Some(code) = kind.error_code() {
        if line.contains(code.as_str()) {
            return true;
        }
        let describe = tracewhy_event::Errno::new(code)
            .describe()
            .to_ascii_lowercase();
        if !describe.is_empty() && l.contains(&describe) {
            return true;
        }
    }
    [
        "not found",
        "no such",
        "missing",
        "does not exist",
        "doesn't exist",
        "cannot",
        "can't",
        "could not",
        "couldn't",
        "unable",
        "denied",
        "failed",
        "error",
        "not permitted",
    ]
    .iter()
    .any(|w| l.contains(w))
}
