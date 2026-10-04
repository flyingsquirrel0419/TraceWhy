//! TraceWhy's root-cause engine.
//!
//! ```text
//! events → observations → hypotheses ⇄ investigations → ranked hypotheses
//!        → root cause + confidence → conclusion + cause graph
//! ```
//!
//! The engine is deterministic and offline: given the same events and facts
//! it always reaches the same conclusion.

mod explain;
pub mod hypotheses;
mod investigate;
pub mod observe;
pub mod rules;
pub mod store;

pub use observe::CANDIDATE_THRESHOLD;
pub use rules::{Rule, RuleSet};
pub use store::FactStore;

use hypotheses::{Ctx, Eval};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tracewhy_core::{
    AdapterContext, Conclusion, EnvSnapshot, Fact, FactKind, FactSource, Freshness, Hypothesis,
    HypothesisStatus, InvestigationRecord, Investigator, Limits, Observation, ObservationKind,
    Relevance, RuntimeAdapter,
};
use tracewhy_event::{Event, ExitStatus, ProcessTree};
use tracewhy_graph::CauseGraph;

pub struct Engine {
    pub rules: RuleSet,
    pub investigators: Vec<Box<dyn Investigator>>,
    pub adapters: Vec<Box<dyn RuntimeAdapter>>,
    pub limits: Limits,
}

/// A symptom established before tracing (e.g. the command is not on PATH).
#[derive(Debug, Clone)]
pub struct PreflightObservation {
    pub kind: ObservationKind,
    pub facts: Vec<FactKind>,
}

pub struct AnalysisInput<'a> {
    /// The command line as the user typed it (for labels only).
    pub command: Vec<String>,
    pub events: &'a [Event],
    pub tree: &'a ProcessTree,
    pub exit: Option<ExitStatus>,
    pub cwd: PathBuf,
    pub env: &'a EnvSnapshot,
    pub preflight: Vec<PreflightObservation>,
    /// Facts carried over from a recorded trace (used by `why explain`).
    pub prior_facts: Vec<Fact>,
    /// Run active investigators (false = reason only from existing facts).
    pub investigate: bool,
}

#[derive(Debug, Clone)]
pub struct Analysis {
    pub observations: Vec<Observation>,
    pub facts: Vec<Fact>,
    pub hypotheses: Vec<Hypothesis>,
    pub investigations: Vec<InvestigationRecord>,
    pub conclusion: Conclusion,
    pub graph: CauseGraph,
    pub failure_chain: Vec<u32>,
    pub warnings: Vec<String>,
}

/// A hypothesis under evaluation, with its latest evaluation.
pub(crate) struct Candidate {
    pub obs: usize,
    pub kind: String,
    pub rule: Option<String>,
    /// Index of the runtime adapter that owns this hypothesis.
    pub adapter: Option<usize>,
    pub eval: Option<Eval>,
}

impl Engine {
    pub fn new(
        investigators: Vec<Box<dyn Investigator>>,
        adapters: Vec<Box<dyn RuntimeAdapter>>,
    ) -> Self {
        Engine {
            rules: RuleSet::with_user_rules(),
            investigators,
            adapters,
            limits: Limits::default(),
        }
    }

    pub fn analyze(&self, input: AnalysisInput<'_>) -> Analysis {
        let set = observe::extract(input.events, input.tree);
        let mut observations = set.observations;
        let failure_chain = set.failure_chain;
        let mut store = FactStore::from_facts(input.prior_facts.clone());
        let mut warnings = self.rules.warnings.clone();

        // Preflight symptoms are certain and come first.
        if !input.preflight.is_empty() {
            let mut pre = Vec::new();
            for p in &input.preflight {
                for f in &p.facts {
                    store.add(f.clone(), FactSource::Preflight, Freshness::AtFailure);
                }
                pre.push(Observation {
                    id: 0,
                    kind: p.kind.clone(),
                    pid: input.tree.root.unwrap_or(0),
                    events: Vec::new(),
                    ts: None,
                    relevance: Relevance {
                        score: 1.0,
                        on_failure_chain: true,
                        terminal: true,
                        reasons: vec!["established before running the command".into()],
                        ..Relevance::default()
                    },
                });
            }
            pre.append(&mut observations);
            observations = pre;
        }

        // Runtime adapters: project facts and runtime-specific observations.
        let mut adapter_of: BTreeMap<usize, usize> = BTreeMap::new();
        {
            let facts_snapshot = store.all().to_vec();
            let actx = AdapterContext {
                cwd: input.cwd.clone(),
                env: input.env,
                events: input.events,
                tree: input.tree,
                failure_chain: &failure_chain,
                facts: &facts_snapshot,
            };
            for (ai, a) in self.adapters.iter().enumerate() {
                if !a.detect(&actx) {
                    continue;
                }
                // Adapter facts read the live project; `why explain` without
                // --investigate must rely on recorded facts only.
                let collected = if input.investigate {
                    a.collect(&actx)
                } else {
                    Vec::new()
                };
                for f in collected {
                    store.add(
                        f,
                        FactSource::Adapter { id: a.id().into() },
                        Freshness::AfterRun,
                    );
                }
                for (kind, pid, seqs) in a.observations(&actx) {
                    if !matches!(kind, ObservationKind::Runtime { .. }) {
                        warnings.push(format!(
                            "adapter {} produced a non-runtime observation; ignored",
                            a.id()
                        ));
                        continue;
                    }
                    let on_chain = failure_chain.contains(&pid);
                    adapter_of.insert(observations.len(), ai);
                    observations.push(Observation {
                        id: 0,
                        kind,
                        pid,
                        ts: seqs
                            .last()
                            .and_then(|s| input.events.iter().find(|e| e.seq == *s))
                            .and_then(|e| e.ts),
                        events: seqs,
                        relevance: Relevance {
                            score: if on_chain { 0.85 } else { 0.6 },
                            on_failure_chain: on_chain,
                            reported_on_stderr: true,
                            terminal: true,
                            reasons: vec![
                                "runtime adapter matched the program's error and trace evidence"
                                    .into(),
                            ],
                            ..Relevance::default()
                        },
                    });
                }
            }
        }
        // Stable ids: sort by relevance, keep adapter mapping.
        let mut order: Vec<usize> = (0..observations.len()).collect();
        order.sort_by(|&a, &b| {
            observations[b]
                .relevance
                .score
                .partial_cmp(&observations[a].relevance.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then(a.cmp(&b))
        });
        let mut sorted = Vec::with_capacity(observations.len());
        let mut adapter_by_obs: BTreeMap<usize, usize> = BTreeMap::new();
        for (new, &old) in order.iter().enumerate() {
            let mut o = observations[old].clone();
            o.id = new as u32;
            if let Some(a) = adapter_of.get(&old) {
                adapter_by_obs.insert(new, *a);
            }
            sorted.push(o);
        }
        let observations = sorted;

        if let Some(culprit) = failure_chain.last() {
            if let Some(text) = &set.stderr_excerpt {
                store.add(
                    FactKind::OutputExcerpt {
                        pid: *culprit,
                        text: text.clone(),
                    },
                    FactSource::Trace { events: Vec::new() },
                    Freshness::AtFailure,
                );
            }
        }

        let succeeded = input.exit.as_ref().map(|e| e.success()).unwrap_or(false);
        let mut investigations = Vec::new();
        let mut candidates: Vec<Candidate> = Vec::new();

        if !succeeded {
            let picked: Vec<usize> = observations
                .iter()
                .enumerate()
                .filter(|(_, o)| o.relevance.score >= CANDIDATE_THRESHOLD)
                .map(|(i, _)| i)
                .take(3)
                .collect();
            for &oi in &picked {
                let obs = &observations[oi];
                if adapter_by_obs.contains_key(&oi) {
                    candidates.push(Candidate {
                        obs: oi,
                        kind: "adapter".into(),
                        rule: Some("runtime.adapter".into()),
                        adapter: adapter_by_obs.get(&oi).copied(),
                        eval: None,
                    });
                    continue;
                }
                for rule in self.rules.matching(obs) {
                    for h in &rule.hypotheses {
                        if !candidates.iter().any(|c| c.obs == oi && &c.kind == h) {
                            candidates.push(Candidate {
                                obs: oi,
                                kind: h.clone(),
                                rule: Some(rule.id.clone()),
                                adapter: None,
                                eval: None,
                            });
                        }
                    }
                }
            }
            investigations =
                investigate::run(self, &input, &observations, &mut candidates, &mut store);
        }

        let facts_vec = store.all().to_vec();
        let mut hypotheses = Vec::new();
        for (i, c) in candidates.iter().enumerate() {
            let Some(e) = &c.eval else { continue };
            hypotheses.push(Hypothesis {
                id: i as u32,
                kind: c.kind.clone(),
                observation: observations[c.obs].id,
                rule: c.rule.clone(),
                status: e.status,
                score: (e.score * 1000.0).round() / 1000.0,
                title: e.title.clone(),
                evidence_for: e
                    .support
                    .iter()
                    .map(|id| tracewhy_core::EvidenceRef::Fact { id: *id })
                    .collect(),
                evidence_against: e
                    .against
                    .iter()
                    .map(|id| tracewhy_core::EvidenceRef::Fact { id: *id })
                    .collect(),
                unresolved_questions: e.questions.clone(),
            });
        }

        let (conclusion, graph) = explain::conclude(
            &input,
            &observations,
            &candidates,
            &hypotheses,
            &store,
            &failure_chain,
            set.stderr_excerpt.clone(),
            self.limits.max_graph_nodes,
        );

        Analysis {
            observations,
            facts: facts_vec,
            hypotheses,
            investigations,
            conclusion,
            graph,
            failure_chain,
            warnings,
        }
    }
}

/// Evaluate one candidate against the current facts.
pub(crate) fn evaluate_candidate(
    engine: &Engine,
    input: &AnalysisInput<'_>,
    obs: &Observation,
    kind: &str,
    store: &FactStore,
    adapter: Option<usize>,
) -> Vec<(String, Eval)> {
    if kind == "adapter" {
        let Some(a) = adapter.and_then(|i| engine.adapters.get(i)) else {
            return Vec::new();
        };
        return a
            .evaluate(obs, store.all())
            .into_iter()
            .map(|rh| {
                let mut e = Eval::new(rh.title);
                e.score = rh.score.clamp(0.0, 1.0);
                e.status = if !rh.against.is_empty() && rh.support.is_empty() {
                    HypothesisStatus::Refuted
                } else if rh.score >= 0.5 {
                    HypothesisStatus::Supported
                } else {
                    HypothesisStatus::Unresolved
                };
                for id in &rh.support {
                    if let Some(f) = store.get(*id) {
                        e.observed.push(tracewhy_core::EvidenceLine {
                            text: f.kind.describe(),
                            refs: vec![tracewhy_core::EvidenceRef::Fact { id: *id }],
                        });
                        e.chain.push(hypotheses::ChainItem {
                            kind: tracewhy_core::ChainStepKind::Fact,
                            label: short_label(&f.kind.describe()),
                            evidence: vec![tracewhy_core::EvidenceRef::Fact { id: *id }],
                            inferred: false,
                        });
                    }
                }
                e.support = rh.support;
                e.against = rh.against;
                for o in rh.observed {
                    e.observed.push(tracewhy_core::EvidenceLine {
                        text: o,
                        refs: Vec::new(),
                    });
                }
                if let Some(i) = rh.inference {
                    e.inferences.push(i);
                }
                e.suggestion = rh.suggestion;
                (rh.kind, e)
            })
            .collect();
    }
    let ctx = Ctx {
        obs,
        facts: store,
        events: input.events,
        tree: input.tree,
        cwd: &input.cwd,
    };
    hypotheses::evaluate(kind, &ctx)
        .map(|e| vec![(kind.to_string(), e)])
        .unwrap_or_default()
}

fn short_label(s: &str) -> String {
    let s = s.trim_end_matches('.');
    if s.chars().count() > 60 {
        s.chars().take(57).collect::<String>() + "..."
    } else {
        s.to_string()
    }
}
