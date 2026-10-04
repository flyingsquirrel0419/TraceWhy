//! Hypothesis evaluators.
//!
//! Each hypothesis kind is a small function that inspects one observation and
//! the fact store, and returns an [`Eval`]: a score, the facts for and against
//! it, open questions (with the investigations that would answer them), and —
//! should it win — the causal chain, inference and suggestion to present.

mod fs;
mod library;
mod net;
mod process;
mod refused;

use crate::store::FactStore;
use std::path::Path;
use tracewhy_core::{
    ChainStepKind, EvidenceLine, EvidenceRef, FactId, HypothesisStatus, InvestigationTarget,
    Observation, Question, Suggestion, SuggestionKind,
};
use tracewhy_event::{Event, ProcessTree};

/// Every hypothesis kind rules may reference.
pub const KNOWN_HYPOTHESES: &[&str] = &[
    // network
    "container_stopped",
    "container_not_created",
    "port_not_published",
    "wrong_published_port",
    "wrong_interface",
    "startup_race",
    "service_not_listening",
    "remote_port_closed",
    "socket_missing",
    "socket_stale",
    "socket_permission",
    "network_unreachable",
    "host_unreachable",
    "connect_timeout",
    "no_source_address",
    "port_held_by_traced_process",
    "port_held_by_container",
    "port_held_by_process",
    "port_held_by_unknown",
    "port_released",
    "privileged_port",
    "address_not_local",
    "hostname_not_found",
    "dns_server_failure",
    "transient_dns_failure",
    "broken_pipe",
    // filesystem
    "broken_symlink",
    "parent_missing",
    "file_missing",
    "path_exists_now",
    "ancestor_not_searchable",
    "permission_denied",
    "operation_not_permitted",
    "read_only_filesystem",
    "bad_path",
    "inodes_exhausted",
    "disk_full",
    "disk_was_full",
    "quota_exceeded",
    "write_device_error",
    "fd_limit_reached",
    "system_fd_table_full",
    // process
    "missing_interpreter",
    "explicit_path_missing",
    "command_not_in_path",
    "is_directory",
    "not_executable",
    "noexec_mount",
    "wrong_architecture",
    "not_an_executable",
    "executable_busy",
    "killed_by_traced_process",
    "process_crashed",
    "killed_externally",
    "library_wrong_architecture",
    "library_outside_search_path",
    "missing_shared_library",
    // runtime adapters
    "adapter",
];

/// Inputs to an evaluator.
pub struct Ctx<'a> {
    pub obs: &'a Observation,
    pub facts: &'a FactStore,
    pub events: &'a [Event],
    pub tree: &'a ProcessTree,
    pub cwd: &'a Path,
}

/// One step appended to the causal chain after the observation itself.
#[derive(Debug, Clone)]
pub struct ChainItem {
    pub kind: ChainStepKind,
    pub label: String,
    pub evidence: Vec<EvidenceRef>,
    pub inferred: bool,
}

#[derive(Debug, Clone)]
pub struct Eval {
    pub score: f64,
    pub status: HypothesisStatus,
    pub title: String,
    pub detail: Option<String>,
    pub support: Vec<FactId>,
    pub against: Vec<FactId>,
    pub questions: Vec<Question>,
    pub wants: Vec<InvestigationTarget>,
    pub chain: Vec<ChainItem>,
    pub observed: Vec<EvidenceLine>,
    pub inferences: Vec<String>,
    pub suggestion: Option<Suggestion>,
}

impl Eval {
    pub fn new(title: impl Into<String>) -> Self {
        Eval {
            score: 0.2,
            status: HypothesisStatus::Unresolved,
            title: title.into(),
            detail: None,
            support: Vec::new(),
            against: Vec::new(),
            questions: Vec::new(),
            wants: Vec::new(),
            chain: Vec::new(),
            observed: Vec::new(),
            inferences: Vec::new(),
            suggestion: None,
        }
    }

    pub fn supported(mut self, score: f64) -> Self {
        self.score = score;
        self.status = HypothesisStatus::Supported;
        self
    }

    pub fn refuted(mut self, by: FactId) -> Self {
        self.score = 0.03;
        self.status = HypothesisStatus::Refuted;
        self.against.push(by);
        self
    }

    pub fn unresolved(mut self, score: f64, q: &str, want: Option<InvestigationTarget>) -> Self {
        self.score = score;
        self.status = HypothesisStatus::Unresolved;
        self.questions.push(Question {
            text: q.to_string(),
            investigator: want.as_ref().map(|w| w.describe()),
        });
        if let Some(w) = want {
            self.wants.push(w);
        }
        self
    }

    pub fn fact(mut self, id: FactId, ctx: &Ctx<'_>) -> Self {
        if !self.support.contains(&id) {
            self.support.push(id);
            if let Some(f) = ctx.facts.get(id) {
                self.observed.push(EvidenceLine {
                    text: f.kind.describe(),
                    refs: vec![EvidenceRef::Fact { id }],
                });
            }
        }
        self
    }

    pub fn step(mut self, label: impl Into<String>, fact: Option<FactId>) -> Self {
        self.chain.push(ChainItem {
            kind: ChainStepKind::Fact,
            label: label.into(),
            evidence: fact
                .map(|id| vec![EvidenceRef::Fact { id }])
                .unwrap_or_default(),
            inferred: false,
        });
        self
    }

    pub fn inferred_step(mut self, label: impl Into<String>) -> Self {
        self.chain.push(ChainItem {
            kind: ChainStepKind::Fact,
            label: label.into(),
            evidence: Vec::new(),
            inferred: true,
        });
        self
    }

    pub fn infer(mut self, s: impl Into<String>) -> Self {
        self.inferences.push(s.into());
        self
    }

    pub fn detail(mut self, s: impl Into<String>) -> Self {
        self.detail = Some(s.into());
        self
    }

    pub fn fix(mut self, text: impl Into<String>, command: Option<String>) -> Self {
        self.suggestion = Some(Suggestion {
            kind: SuggestionKind::Fix,
            text: text.into(),
            command,
        });
        self
    }

    pub fn next(mut self, text: impl Into<String>, command: Option<String>) -> Self {
        self.suggestion = Some(Suggestion {
            kind: SuggestionKind::NextStep,
            text: text.into(),
            command,
        });
        self
    }
}

/// Evaluate hypothesis `kind` for the observation. `None` = not applicable.
pub fn evaluate(kind: &str, ctx: &Ctx<'_>) -> Option<Eval> {
    net::evaluate(kind, ctx)
        .or_else(|| fs::evaluate(kind, ctx))
        .or_else(|| process::evaluate(kind, ctx))
}

/// Shell-quote a single argument for display in a suggested command.
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

pub fn parent_dir(p: &str) -> String {
    match p.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((d, _)) => d.to_string(),
        None => ".".to_string(),
    }
}
