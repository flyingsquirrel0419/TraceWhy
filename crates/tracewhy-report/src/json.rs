//! The stable machine-readable report (`why --json`).
//!
//! Schema id `tracewhy.report/v1`. Fields are only ever added in v1.

use serde_json::{json, Value};
use tracewhy_format::WhyTrace;

pub const REPORT_SCHEMA: &str = "tracewhy.report/v1";

pub fn report(t: &WhyTrace) -> Value {
    let c = &t.conclusion;
    json!({
        "schema": REPORT_SCHEMA,
        "tracewhy_version": t.tracewhy_version,
        "command": t.run.command,
        "cwd": t.run.cwd,
        "duration_ms": t.run.duration_ms,
        "exit": t.run.exit,
        "exit_code": t.run.exit.as_ref().map(|e| e.shell_code()),
        "status": c.status,
        "root_cause": c.root_cause.as_ref().map(|r| json!({
            "kind": r.kind,
            "title": r.title,
            "detail": r.detail,
        })),
        "confidence": c.confidence,
        "failing_process": c.failing_process,
        "chain": c.chain.iter().map(|s| json!({"kind": s.kind, "label": s.label, "inferred": s.inferred})).collect::<Vec<_>>(),
        "evidence": c.evidence.iter().map(|e| e.text.clone()).collect::<Vec<_>>(),
        "inferences": c.inferences,
        "suggestions": c.suggestions,
        "alternatives": c.alternatives,
        "contributing": c.contributing,
        "stderr_excerpt": c.stderr_excerpt,
        "stats": {
            "raw_events": t.stats.raw_events,
            "semantic_events": t.stats.semantic_events,
            "facts": t.facts.len(),
            "observations": t.observations.len(),
            "hypotheses": t.hypotheses.len(),
            "processes": t.stats.processes,
            "truncated": t.stats.truncated,
        },
        "investigations": t.investigations.iter().map(|r| json!({
            "investigator": r.investigator,
            "target": r.target,
            "status": r.status,
            "duration_ms": r.duration_ms,
        })).collect::<Vec<_>>(),
        "diagnostics": t.diagnostics.iter().map(|d| d.message.clone()).collect::<Vec<_>>(),
    })
}
