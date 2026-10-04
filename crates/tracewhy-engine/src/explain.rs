//! From ranked hypotheses to the user-facing conclusion and the cause graph.

use crate::hypotheses::Eval;
mod wording;

use crate::store::FactStore;
use crate::{AnalysisInput, Candidate};
use tracewhy_core::{
    Alternative, ChainStep, ChainStepKind, Conclusion, ConclusionStatus, Confidence, EvidenceLine,
    EvidenceRef, FactSource, Hypothesis, HypothesisStatus, Observation, RootCause, SuggestionKind,
};
use tracewhy_graph::{CauseGraph, EdgeKind, NodeId, NodeKind};
use wording::{
    add_observation, build_process_graph, failure_label, observed_statement, reported_line,
};

/// Minimum combined score for naming a root cause at all.
const MIN_CAUSE_SCORE: f64 = 0.4;

fn combined(obs: &Observation, e: &Eval) -> f64 {
    e.score * (0.5 + 0.5 * obs.relevance.score)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn conclude(
    input: &AnalysisInput<'_>,
    observations: &[Observation],
    candidates: &[Candidate],
    hypotheses: &[Hypothesis],
    store: &FactStore,
    chain_pids: &[u32],
    stderr_excerpt: Option<String>,
    max_nodes: usize,
) -> (Conclusion, CauseGraph) {
    let mut graph = CauseGraph::with_limit(max_nodes);
    let cmd_node = build_process_graph(&mut graph, input);

    let exit = input.exit.clone();
    if exit.as_ref().map(|e| e.success()).unwrap_or(false) {
        let mut c = Conclusion::succeeded(exit);
        // Non-fatal failures are not causes; mention only clearly notable ones.
        for o in observations
            .iter()
            .filter(|o| o.relevance.score >= 0.3 && !o.relevance.recovered)
            .take(3)
        {
            c.contributing
                .push(format!("Non-fatal: {}", o.kind.describe()));
        }
        return (c, graph);
    }

    // Rank (observation, hypothesis) pairs.
    let mut ranked: Vec<(f64, usize)> = candidates
        .iter()
        .enumerate()
        .filter_map(|(i, c)| {
            let e = c.eval.as_ref()?;
            if e.status != HypothesisStatus::Supported {
                return None;
            }
            Some((combined(&observations[c.obs], e), i))
        })
        .collect();
    ranked.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });

    // Graph: observations, facts and hypotheses.
    let obs_nodes: Vec<Option<NodeId>> = observations
        .iter()
        .map(|o| {
            if o.relevance.score < 0.3 {
                return None;
            }
            add_observation(&mut graph, o, input)
        })
        .collect();
    for f in store.all() {
        graph.node(
            NodeKind::Fact,
            format!("fact:{}", f.id),
            f.kind.describe(),
            vec![EvidenceRef::Fact { id: f.id }],
        );
    }
    for h in hypotheses {
        let Some(hn) = graph.node(
            NodeKind::Hypothesis,
            format!("hyp:{}", h.id),
            h.title.clone(),
            Vec::new(),
        ) else {
            continue;
        };
        if let Some(Some(on)) = obs_nodes.get(h.observation as usize) {
            graph.edge(hn, *on, EdgeKind::Explains, Vec::new());
        }
        for r in &h.evidence_for {
            if let EvidenceRef::Fact { id } = r {
                if let Some(fnode) = graph.find(&format!("fact:{id}")).map(|n| n.id) {
                    graph.edge(fnode, hn, EdgeKind::Corroborates, vec![r.clone()]);
                }
            }
        }
        for r in &h.evidence_against {
            if let EvidenceRef::Fact { id } = r {
                if let Some(fnode) = graph.find(&format!("fact:{id}")).map(|n| n.id) {
                    graph.edge(fnode, hn, EdgeKind::Contradicts, vec![r.clone()]);
                }
            }
        }
    }

    let failing = chain_pids.last().copied();
    let Some(&(best_score, best_i)) = ranked.first().filter(|(s, _)| *s >= MIN_CAUSE_SCORE) else {
        let mut c = Conclusion::succeeded(exit);
        c.status = ConclusionStatus::Undetermined;
        c.failing_process = failing;
        c.stderr_excerpt = stderr_excerpt;
        for o in observations
            .iter()
            .filter(|o| o.relevance.score >= 0.3 && !o.relevance.recovered && !o.relevance.probe)
            .take(3)
        {
            c.contributing.push(format!(
                "Possible contributing factor: {}",
                o.kind.describe()
            ));
        }
        if let Some(p) = failing.and_then(|p| input.tree.get(p)) {
            c.evidence.push(EvidenceLine {
                text: format!(
                    "{} {}",
                    p.display_name(),
                    p.exit.as_ref().map(|e| e.describe()).unwrap_or_default()
                ),
                refs: Vec::new(),
            });
        }
        return (c, graph);
    };
    let best = &candidates[best_i];
    let Some(eval) = best.eval.as_ref() else {
        let mut c = Conclusion::succeeded(exit);
        c.status = ConclusionStatus::Undetermined;
        return (c, graph);
    };
    let obs = &observations[best.obs];

    // Competing explanations: the best supported alternative of a different kind.
    // A less specific hypothesis whose evidence the winner fully contains is a
    // refinement, not a rival.
    let subsumed = |i: usize| {
        let c = &candidates[i];
        c.obs == best.obs
            && c.eval
                .as_ref()
                .map(|e| {
                    !e.support.is_empty() && e.support.iter().all(|f| eval.support.contains(f))
                })
                .unwrap_or(false)
    };
    let competitor = ranked
        .iter()
        .skip(1)
        .find(|(_, i)| {
            candidates[*i]
                .eval
                .as_ref()
                .map(|e| e.title != eval.title)
                .unwrap_or(false)
                && !subsumed(*i)
        })
        .map(|(s, _)| *s)
        .unwrap_or(0.0);
    let confidence = confidence(obs, eval, best_score, competitor, store);

    // Causal chain, recorded in the graph and read back from it.
    let pid = if obs.pid == 0 {
        input.tree.root.unwrap_or(0)
    } else {
        obs.pid
    };
    let proc_node = graph
        .find(&format!("proc:{pid}"))
        .map(|n| n.id)
        .or(cmd_node);
    let cause_node = graph.node(
        NodeKind::Cause,
        "cause",
        eval.title.clone(),
        eval.support
            .iter()
            .map(|id| EvidenceRef::Fact { id: *id })
            .collect(),
    );
    let mut chain: Vec<ChainStep> = Vec::new();
    if let (Some(pn), Some(cn), Some(Some(on))) = (proc_node, cause_node, obs_nodes.get(best.obs)) {
        let failure_label = failure_label(obs);
        let fnode = graph.node(
            NodeKind::Failure,
            format!("failure:{}", obs.id),
            failure_label,
            obs.events
                .iter()
                .map(|s| EvidenceRef::Event { seq: *s })
                .collect(),
        );
        let mut prev = *on;
        if let Some(f) = fnode {
            graph.edge(*on, f, EdgeKind::FailedWith, Vec::new());
            prev = f;
        }
        for (i, item) in eval.chain.iter().enumerate() {
            if let Some(n) = graph.node(
                NodeKind::EnvironmentFact,
                format!("step:{i}"),
                item.label.clone(),
                item.evidence.clone(),
            ) {
                graph.edge(prev, n, EdgeKind::UnavailableBecause, item.evidence.clone());
                for r in &item.evidence {
                    if let EvidenceRef::Fact { id } = r {
                        if let Some(fact_node) = graph.find(&format!("fact:{id}")).map(|x| x.id) {
                            graph.edge(n, fact_node, EdgeKind::AssociatedWith, Vec::new());
                        }
                    }
                }
                prev = n;
            }
        }
        graph.edge(prev, cn, EdgeKind::Caused, Vec::new());
        if let Some(path) = graph.path(
            pn,
            cn,
            &[
                EdgeKind::Attempted,
                EdgeKind::FailedWith,
                EdgeKind::UnavailableBecause,
                EdgeKind::Caused,
            ],
        ) {
            let inferred: Vec<bool> = std::iter::once(false)
                .chain(std::iter::once(false))
                .chain(std::iter::once(false))
                .chain(eval.chain.iter().map(|c| c.inferred))
                .collect();
            for (i, id) in path.iter().enumerate() {
                let Some(n) = graph.get(*id) else { continue };
                if n.kind == NodeKind::Cause {
                    continue;
                }
                let kind = match n.kind {
                    NodeKind::Process | NodeKind::Command => ChainStepKind::Process,
                    NodeKind::Observation => ChainStepKind::Action,
                    NodeKind::Failure => ChainStepKind::Failure,
                    _ => ChainStepKind::Fact,
                };
                chain.push(ChainStep {
                    kind,
                    label: n.label.clone(),
                    evidence: graph.evidence_for(*id),
                    inferred: inferred.get(i).copied().unwrap_or(false),
                });
            }
        }
    }

    let mut evidence = vec![EvidenceLine {
        text: observed_statement(obs),
        refs: obs
            .events
            .iter()
            .map(|s| EvidenceRef::Event { seq: *s })
            .chain([EvidenceRef::Observation { id: obs.id }])
            .collect(),
    }];
    if obs.relevance.reported_on_stderr {
        if let Some(line) = reported_line(input, obs) {
            evidence.push(EvidenceLine {
                text: format!("The program reported: \"{line}\""),
                refs: Vec::new(),
            });
        }
    }
    for l in &eval.observed {
        if !evidence.iter().any(|e| e.text == l.text) {
            evidence.push(l.clone());
        }
    }

    let mut inferences = eval.inferences.clone();
    if !obs.relevance.reported_on_stderr && obs.relevance.terminal {
        if let Some(p) = input.tree.get(obs.pid) {
            inferences.push(format!(
                "This was the last failure before {} {}.",
                p.display_name(),
                p.exit
                    .as_ref()
                    .map(|e| e.describe())
                    .unwrap_or_else(|| "exited".into())
            ));
        }
    }
    if chain_pids.len() > 1 && chain_pids.last() == Some(&obs.pid) {
        let names: Vec<String> = chain_pids
            .iter()
            .filter_map(|p| input.tree.get(*p))
            .map(|p| p.display_name())
            .collect();
        inferences.push(format!("The failure propagated: {}.", names.join(" → ")));
    }

    let mut suggestions = Vec::new();
    if let Some(mut s) = eval.suggestion.clone() {
        if confidence != Confidence::High {
            s.kind = SuggestionKind::NextStep;
        }
        suggestions.push(s);
    }

    let mut alternatives = Vec::new();
    for (score, i) in ranked.iter().skip(1) {
        let c = &candidates[*i];
        let Some(e) = &c.eval else { continue };
        if e.title == eval.title
            || alternatives
                .iter()
                .any(|a: &Alternative| a.title == e.title)
            || *score < 0.3
        {
            continue;
        }
        // A less specific statement of the same evidence is not an alternative.
        if c.obs == best.obs
            && !e.support.is_empty()
            && e.support.iter().all(|f| eval.support.contains(f))
        {
            continue;
        }
        let conf = if *score >= 0.6 {
            Confidence::Medium
        } else {
            Confidence::Low
        };
        alternatives.push(Alternative {
            kind: c.kind.clone(),
            title: e.title.clone(),
            confidence: conf.min(confidence),
        });
        if alternatives.len() >= 3 {
            break;
        }
    }
    let mut contributing = Vec::new();
    for o in observations.iter() {
        if o.id == obs.id || o.relevance.score < 0.4 || o.relevance.recovered || o.relevance.probe {
            continue;
        }
        if candidates.iter().any(|c| {
            c.obs as u32 == o.id
                && c.eval
                    .as_ref()
                    .map(|e| e.title == eval.title)
                    .unwrap_or(false)
        }) {
            continue;
        }
        contributing.push(format!(
            "Possible contributing factor: {}",
            o.kind.describe()
        ));
        if contributing.len() >= 2 {
            break;
        }
    }

    let hyp_id = hypotheses
        .iter()
        .find(|h| h.observation == obs.id && h.kind == best.kind)
        .map(|h| h.id)
        .unwrap_or(best_i as u32);
    let conclusion = Conclusion {
        status: ConclusionStatus::RootCause,
        exit,
        root_cause: Some(RootCause {
            kind: best.kind.clone(),
            title: eval.title.clone(),
            detail: eval.detail.clone(),
            hypothesis: hyp_id,
            observation: obs.id,
        }),
        confidence: Some(confidence),
        failing_process: failing,
        chain,
        evidence,
        inferences,
        suggestions,
        alternatives,
        contributing,
        stderr_excerpt,
    };
    (conclusion, graph)
}

/// HIGH requires direct evidence, a strong tie to the failure, independent
/// corroboration from an investigation, no contradiction and no close rival.
fn confidence(
    obs: &Observation,
    e: &Eval,
    score: f64,
    competitor: f64,
    store: &FactStore,
) -> Confidence {
    let investigated = e
        .support
        .iter()
        .filter(|id| {
            store
                .get(**id)
                .map(|f| !matches!(f.source, FactSource::Trace { .. }))
                .unwrap_or(false)
        })
        .count();
    let corroborations = investigated
        + usize::from(obs.relevance.reported_on_stderr)
        + usize::from(obs.relevance.terminal);
    let gap = score - competitor;
    if e.score >= 0.85
        && obs.relevance.score >= 0.7
        && investigated >= 1
        && corroborations >= 2
        && e.against.is_empty()
        && gap >= 0.15
    {
        Confidence::High
    } else if e.score >= 0.55 && obs.relevance.score >= 0.5 && gap >= 0.05 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}
