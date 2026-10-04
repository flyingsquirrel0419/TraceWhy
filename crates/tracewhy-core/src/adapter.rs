use crate::{EnvSnapshot, Fact, FactId, FactKind, Observation, ObservationKind, Suggestion};
use std::path::PathBuf;
use tracewhy_event::{Event, ProcessTree};

/// Inputs available to a runtime adapter.
pub struct AdapterContext<'a> {
    pub cwd: PathBuf,
    pub env: &'a EnvSnapshot,
    pub events: &'a [Event],
    pub tree: &'a ProcessTree,
    /// Processes on the failure-propagation chain (root first).
    pub failure_chain: &'a [u32],
    pub facts: &'a [Fact],
}

/// A runtime-specific explanation proposed by an adapter.
#[derive(Debug, Clone, PartialEq)]
pub struct RuntimeHypothesis {
    pub kind: String,
    pub title: String,
    /// Score in `[0, 1]`.
    pub score: f64,
    pub support: Vec<FactId>,
    pub against: Vec<FactId>,
    pub observed: Vec<String>,
    pub inference: Option<String>,
    pub suggestion: Option<Suggestion>,
}

/// Language/runtime knowledge (Node, Python, ...) kept out of the core engine.
///
/// Adapters may contribute facts about the project, runtime-specific
/// observations derived from trace events, and hypotheses for those
/// observations. They never see or alter the generic hypothesis logic.
pub trait RuntimeAdapter: Send + Sync {
    fn id(&self) -> &'static str;

    /// Whether this runtime took part in the traced command.
    fn detect(&self, ctx: &AdapterContext<'_>) -> bool;

    /// Project/runtime facts (version, package manager, virtualenv, ...).
    fn collect(&self, ctx: &AdapterContext<'_>) -> Vec<FactKind>;

    /// Runtime-specific failure observations: `(kind, pid, event seqs)`.
    /// `kind` must be [`ObservationKind::Runtime`].
    fn observations(&self, ctx: &AdapterContext<'_>) -> Vec<(ObservationKind, u32, Vec<u64>)>;

    /// Hypotheses for an observation this adapter produced.
    fn evaluate(&self, observation: &Observation, facts: &[Fact]) -> Vec<RuntimeHypothesis>;
}
