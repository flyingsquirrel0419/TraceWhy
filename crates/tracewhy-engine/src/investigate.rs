//! The investigation loop.
//!
//! Each round evaluates every hypothesis, collects the investigations that
//! would answer open questions, ranks them by expected information gain per
//! unit of cost, and runs them within the depth, count and time budgets.

use crate::hypotheses::Eval;
use crate::store::FactStore;
use crate::{evaluate_candidate, AnalysisInput, Candidate, Engine};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tracewhy_core::{
    FactSource, Freshness, HypothesisStatus, InvestigationContext, InvestigationError,
    InvestigationRecord, InvestigationStatus, InvestigationTarget, Observation, ObservationKind,
};
use tracewhy_event::Endpoint;

pub(crate) fn run(
    engine: &Engine,
    input: &AnalysisInput<'_>,
    observations: &[Observation],
    candidates: &mut Vec<Candidate>,
    store: &mut FactStore,
) -> Vec<InvestigationRecord> {
    let limits = &engine.limits;
    let start = Instant::now();
    let deadline = start + Duration::from_millis(limits.max_investigation_millis);
    let mut records: Vec<InvestigationRecord> = Vec::new();
    let mut done: HashSet<(String, InvestigationTarget)> = HashSet::new();
    let mut executions = 0u32;

    // Targets named by rules for each candidate observation.
    let mut rule_targets: Vec<(InvestigationTarget, f64)> = Vec::new();
    let mut seen_obs = HashSet::new();
    for c in candidates.iter() {
        if !seen_obs.insert(c.obs) {
            continue;
        }
        let obs = &observations[c.obs];
        for rule in engine.rules.matching(obs) {
            for t in &rule.investigate {
                for target in targets_for(t, obs, input) {
                    if !rule_targets.iter().any(|(x, _)| *x == target) {
                        rule_targets.push((target, obs.relevance.score));
                    }
                }
            }
        }
    }

    let mut round = 0u32;
    loop {
        evaluate_all(engine, input, observations, candidates, store);
        if !input.investigate || round >= limits.max_investigation_depth {
            break;
        }
        // Value of each wanted target = Σ (observation relevance × hypothesis
        // uncertainty) over the hypotheses that want it.
        let mut wanted: Vec<(InvestigationTarget, f64)> = Vec::new();
        let mut add =
            |t: InvestigationTarget, v: f64| match wanted.iter_mut().find(|(x, _)| *x == t) {
                Some(w) => w.1 += v,
                None => wanted.push((t, v)),
            };
        if round == 0 {
            for (t, v) in &rule_targets {
                add(t.clone(), *v);
            }
        }
        for c in candidates.iter() {
            let Some(e) = &c.eval else { continue };
            if e.status == HypothesisStatus::Refuted {
                continue;
            }
            let rel = observations[c.obs].relevance.score;
            let uncertainty = if e.status == HypothesisStatus::Unresolved {
                1.0
            } else {
                0.5
            };
            for t in &e.wants {
                add(t.clone(), rel * uncertainty * e.score.max(0.2));
            }
        }
        let mut runnable: Vec<(f64, usize, InvestigationTarget)> = Vec::new();
        for (t, value) in wanted {
            for (i, inv) in engine.investigators.iter().enumerate() {
                if inv.supports(&t) && !done.contains(&(inv.id().to_string(), t.clone())) {
                    runnable.push((value / inv.cost(&t).weight(), i, t.clone()));
                }
            }
        }
        if runnable.is_empty() {
            break;
        }
        runnable.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
        let mut progressed = false;
        for (_, i, target) in runnable {
            let inv = &engine.investigators[i];
            done.insert((inv.id().to_string(), target.clone()));
            if executions >= limits.max_investigations || Instant::now() >= deadline {
                records.push(InvestigationRecord {
                    investigator: inv.id().into(),
                    target,
                    round,
                    status: InvestigationStatus::Skipped,
                    duration_ms: 0,
                    facts: Vec::new(),
                    message: Some("investigation budget exhausted".into()),
                });
                continue;
            }
            executions += 1;
            let t0 = Instant::now();
            let snapshot = store.all().to_vec();
            let ctx = InvestigationContext {
                target: &target,
                cwd: input.cwd.clone(),
                env: input.env,
                facts: &snapshot,
                events: input.events,
                tree: input.tree,
                limits,
                deadline,
            };
            let result = inv.investigate(&ctx);
            let duration_ms = t0.elapsed().as_millis() as u64;
            let (status, facts, message) = match result {
                Ok(kinds) => {
                    let ids: Vec<u32> = kinds
                        .into_iter()
                        .map(|k| {
                            store.add(
                                k,
                                FactSource::Investigator {
                                    id: inv.id().into(),
                                },
                                Freshness::AfterRun,
                            )
                        })
                        .collect();
                    progressed |= !ids.is_empty();
                    (InvestigationStatus::Completed, ids, None)
                }
                Err(InvestigationError::Unavailable(m)) => {
                    (InvestigationStatus::Unavailable, Vec::new(), Some(m))
                }
                Err(InvestigationError::TimedOut) => {
                    (InvestigationStatus::TimedOut, Vec::new(), None)
                }
                Err(InvestigationError::Failed(m)) => {
                    (InvestigationStatus::Failed, Vec::new(), Some(m))
                }
            };
            records.push(InvestigationRecord {
                investigator: inv.id().into(),
                target,
                round,
                status,
                duration_ms,
                facts,
                message,
            });
        }
        round += 1;
        if !progressed {
            evaluate_all(engine, input, observations, candidates, store);
            break;
        }
    }
    records
}

/// (Re-)evaluate all candidates. Adapter placeholders expand into one
/// candidate per adapter-proposed hypothesis.
fn evaluate_all(
    engine: &Engine,
    input: &AnalysisInput<'_>,
    observations: &[Observation],
    candidates: &mut Vec<Candidate>,
    store: &FactStore,
) {
    let mut expanded: Vec<Candidate> = Vec::new();
    let mut adapter_done: HashSet<usize> = HashSet::new();
    for c in candidates.drain(..) {
        let obs = &observations[c.obs];
        if c.adapter.is_some() {
            if !adapter_done.insert(c.obs) {
                continue;
            }
            for (kind, eval) in evaluate_candidate(engine, input, obs, "adapter", store, c.adapter)
            {
                expanded.push(Candidate {
                    obs: c.obs,
                    kind,
                    rule: c.rule.clone(),
                    adapter: c.adapter,
                    eval: Some(eval),
                });
            }
            if !expanded.iter().any(|x| x.obs == c.obs) {
                // Keep a placeholder so the adapter is asked again next round.
                expanded.push(Candidate { eval: None, ..c });
            }
            continue;
        }
        let eval: Option<Eval> = evaluate_candidate(engine, input, obs, &c.kind, store, None)
            .into_iter()
            .next()
            .map(|(_, e)| e);
        expanded.push(Candidate { eval, ..c });
    }
    *candidates = expanded;
}

/// Map a rule's investigation target name to concrete targets for an observation.
pub(crate) fn targets_for(
    name: &str,
    obs: &Observation,
    input: &AnalysisInput<'_>,
) -> Vec<InvestigationTarget> {
    let cwd = input.cwd.to_string_lossy().into_owned();
    let mut out = Vec::new();
    match (name, &obs.kind) {
        (
            "port",
            ObservationKind::ConnectFailed {
                endpoint: Endpoint::Inet { address, port },
                ..
            },
        )
        | (
            "port",
            ObservationKind::BindFailed {
                endpoint: Endpoint::Inet { address, port },
                ..
            },
        ) => out.push(InvestigationTarget::Port {
            port: *port,
            address: Some(*address),
        }),
        ("docker", ObservationKind::ConnectFailed { endpoint, .. })
        | ("docker", ObservationKind::BindFailed { endpoint, .. }) => {
            out.push(InvestigationTarget::Docker {
                port: endpoint.port(),
            })
        }
        ("local_addresses" | "network", _) => out.push(InvestigationTarget::Network),
        ("privileges", _) => out.push(InvestigationTarget::Privileges {
            executable: input.tree.get(obs.pid).and_then(|p| p.executable.clone()),
        }),
        ("path", ObservationKind::FileAccessFailed { path, .. }) => {
            out.push(InvestigationTarget::Path { path: path.clone() })
        }
        (
            "path",
            ObservationKind::ConnectFailed {
                endpoint: Endpoint::Unix { path },
                ..
            },
        ) => out.push(InvestigationTarget::Path { path: path.clone() }),
        ("path" | "elf", ObservationKind::ExecFailed { executable, .. })
            if executable.contains('/') =>
        {
            out.push(if name == "path" {
                InvestigationTarget::Path {
                    path: executable.clone(),
                }
            } else {
                InvestigationTarget::Elf {
                    path: executable.clone(),
                }
            })
        }
        ("executable", ObservationKind::ExecFailed { executable, .. }) => {
            out.push(InvestigationTarget::Executable {
                name: executable
                    .rsplit('/')
                    .next()
                    .unwrap_or(executable)
                    .to_string(),
            })
        }
        ("filesystem", ObservationKind::FileAccessFailed { path, .. }) => {
            out.push(InvestigationTarget::Filesystem { path: path.clone() })
        }
        ("filesystem", ObservationKind::ExecFailed { executable, .. })
            if executable.contains('/') =>
        {
            out.push(InvestigationTarget::Filesystem {
                path: executable.clone(),
            })
        }
        ("filesystem", ObservationKind::WriteFailed { target, .. }) => {
            out.push(InvestigationTarget::Filesystem {
                path: target.clone().filter(|t| t.starts_with('/')).unwrap_or(cwd),
            })
        }
        (
            "library",
            ObservationKind::LibraryLoadFailed {
                library,
                executable,
                ..
            },
        ) => out.push(InvestigationTarget::Library {
            name: library.clone(),
            executable: executable.clone(),
        }),
        ("hostname", ObservationKind::DnsFailed { hostname, .. }) => {
            out.push(InvestigationTarget::Hostname {
                name: hostname.clone(),
            })
        }
        ("fd_limit", ObservationKind::ResourceLimit { .. }) => {
            out.push(InvestigationTarget::FdLimit)
        }
        _ => {}
    }
    out
}
