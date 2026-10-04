//! TraceWhy's reasoning model.
//!
//! The pipeline keeps five concepts strictly apart:
//!
//! * [`Observation`] — a failure symptom seen directly in the trace
//!   (`connect() returned ECONNREFUSED`). Never a root cause by itself.
//! * [`Fact`] — something known to be true about the system, collected from
//!   the trace or by an investigator (`no process listens on :5432`).
//! * [`Hypothesis`] — a candidate explanation for an observation, scored by
//!   the facts that support or contradict it.
//! * [`RootCause`] — the hypothesis selected as the explanation, carrying its
//!   confidence.
//! * [`Conclusion`] — the full user-facing explanation (evidence, inference,
//!   suggestions).

mod adapter;
mod facts;
mod investigator;
mod observation;

pub use adapter::{AdapterContext, RuntimeAdapter, RuntimeHypothesis};
pub use facts::*;
pub use investigator::{
    EnvSnapshot, InvestigationContext, InvestigationCost, InvestigationError, InvestigationRecord,
    InvestigationStatus, InvestigationTarget, Investigator,
};
pub use observation::{Observation, ObservationKind, Relevance};

use serde::{Deserialize, Serialize};
use tracewhy_event::ExitStatus;

pub type ObservationId = u32;
pub type FactId = u32;
pub type HypothesisId = u32;

/// A pointer from a conclusion back to the evidence it rests on.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceRef {
    Event { seq: u64 },
    Observation { id: ObservationId },
    Fact { id: FactId },
}

/// User-facing confidence. Numeric scores stay internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(&self) -> &'static str {
        match self {
            Confidence::High => "HIGH",
            Confidence::Medium => "MEDIUM",
            Confidence::Low => "LOW",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "high" => Some(Confidence::High),
            "medium" => Some(Confidence::Medium),
            "low" => Some(Confidence::Low),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisStatus {
    /// Generated, not yet evaluated against investigation results.
    Candidate,
    /// Supported by facts and not contradicted.
    Supported,
    /// Contradicted by at least one fact.
    Refuted,
    /// Neither supported nor refuted by the available evidence.
    Unresolved,
}

/// An open question that further investigation could answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Question {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investigator: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    pub id: HypothesisId,
    /// Stable hypothesis identifier, e.g. `container_stopped`.
    pub kind: String,
    /// The observation this hypothesis tries to explain.
    pub observation: ObservationId,
    /// Rule that proposed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub status: HypothesisStatus,
    /// Internal score in `[0, 1]`.
    pub score: f64,
    /// One-line statement of the cause, if this hypothesis holds.
    pub title: String,
    #[serde(default)]
    pub evidence_for: Vec<EvidenceRef>,
    #[serde(default)]
    pub evidence_against: Vec<EvidenceRef>,
    #[serde(default)]
    pub unresolved_questions: Vec<Question>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RootCause {
    pub kind: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub hypothesis: HypothesisId,
    pub observation: ObservationId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainStepKind {
    Process,
    Action,
    Failure,
    Fact,
    Cause,
}

/// One link in the causal chain shown under "Evidence".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainStep {
    pub kind: ChainStepKind,
    pub label: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<EvidenceRef>,
    /// Inferred (not directly observed) steps are rendered differently.
    #[serde(default)]
    pub inferred: bool,
}

/// A directly observed statement backing the conclusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceLine {
    pub text: String,
    #[serde(default)]
    pub refs: Vec<EvidenceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuggestionKind {
    /// Directly addresses a high-confidence root cause.
    Fix,
    /// A next diagnostic or corrective step when certainty is lower.
    NextStep,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Suggestion {
    pub kind: SuggestionKind,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Alternative {
    pub kind: String,
    pub title: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConclusionStatus {
    /// The command succeeded; nothing to explain.
    Succeeded,
    /// A root cause was identified (see confidence).
    RootCause,
    /// The command failed but the evidence is insufficient to name a cause.
    Undetermined,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Conclusion {
    pub status: ConclusionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_cause: Option<RootCause>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// Process whose failure propagated to the command's exit status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failing_process: Option<u32>,
    #[serde(default)]
    pub chain: Vec<ChainStep>,
    /// Directly observed facts ("Observed" section).
    #[serde(default)]
    pub evidence: Vec<EvidenceLine>,
    /// What TraceWhy inferred from the evidence ("Inference" section).
    #[serde(default)]
    pub inferences: Vec<String>,
    #[serde(default)]
    pub suggestions: Vec<Suggestion>,
    #[serde(default)]
    pub alternatives: Vec<Alternative>,
    /// Things that may have contributed but are not proven causes.
    #[serde(default)]
    pub contributing: Vec<String>,
    /// Tail of the failing process' stderr as captured by the tracer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_excerpt: Option<String>,
}

impl Conclusion {
    pub fn succeeded(exit: Option<ExitStatus>) -> Self {
        Conclusion {
            status: ConclusionStatus::Succeeded,
            exit,
            root_cause: None,
            confidence: None,
            failing_process: None,
            chain: Vec::new(),
            evidence: Vec::new(),
            inferences: Vec::new(),
            suggestions: Vec::new(),
            alternatives: Vec::new(),
            contributing: Vec::new(),
            stderr_excerpt: None,
        }
    }
}

/// Resource limits protecting TraceWhy from pathological traces.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Limits {
    pub max_raw_trace_bytes: u64,
    pub max_semantic_events: usize,
    pub max_graph_nodes: usize,
    pub max_investigation_depth: u32,
    pub max_investigations: u32,
    pub max_investigation_millis: u64,
    pub max_docker_log_bytes: usize,
    pub max_output_text_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_raw_trace_bytes: 1 << 30,
            max_semantic_events: 400_000,
            max_graph_nodes: 20_000,
            max_investigation_depth: 4,
            max_investigations: 24,
            max_investigation_millis: 8_000,
            max_docker_log_bytes: 16 * 1024,
            max_output_text_bytes: 64 * 1024,
        }
    }
}

/// Well-known service names for common ports; used only for wording.
pub fn well_known_service(port: u16) -> Option<&'static str> {
    Some(match port {
        5432 => "PostgreSQL",
        3306 => "MySQL",
        6379 => "Redis",
        27017 => "MongoDB",
        5672 => "RabbitMQ",
        9200 => "Elasticsearch",
        11211 => "Memcached",
        2181 => "ZooKeeper",
        9092 => "Kafka",
        1433 => "SQL Server",
        8500 => "Consul",
        4222 => "NATS",
        _ => return None,
    })
}

/// Map an image or service name to a friendly product name.
pub fn product_name_for(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    let base = n.rsplit('/').next().unwrap_or(&n);
    let base = base.split(':').next().unwrap_or(base);
    Some(match base {
        b if b.starts_with("postgres") || b == "pg" || b == "timescaledb" => "PostgreSQL",
        b if b.starts_with("mysql") || b.starts_with("mariadb") => "MySQL",
        b if b.starts_with("redis") || b.starts_with("valkey") => "Redis",
        b if b.starts_with("mongo") => "MongoDB",
        b if b.starts_with("rabbitmq") => "RabbitMQ",
        b if b.starts_with("elasticsearch") || b.starts_with("opensearch") => "Elasticsearch",
        b if b.starts_with("memcached") => "Memcached",
        b if b.starts_with("kafka") => "Kafka",
        _ => return None,
    })
}

/// Run `exe --version` with a 2-second limit and return its first output line.
/// Used by runtime adapters for informational version facts only.
pub fn probe_version(exe: &str) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new(exe)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > std::time::Duration::from_secs(2) => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(_) => return None,
        }
    }
    let mut out = String::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.by_ref().take(4096).read_to_string(&mut out);
    }
    if out.trim().is_empty() {
        if let Some(mut e) = child.stderr.take() {
            let _ = e.by_ref().take(4096).read_to_string(&mut out);
        }
    }
    let line = out.lines().next()?.trim().to_string();
    (!line.is_empty() && line.len() < 64).then_some(line)
}
