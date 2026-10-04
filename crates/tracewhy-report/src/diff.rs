//! Rendering of `why diff`.

use crate::style::{sanitize, thousands, Style};
use crate::RULE;
use tracewhy_core::Confidence;
use tracewhy_diff::TraceDiff;

fn col(s: &str, w: usize) -> String {
    let s: String = s.chars().take(w).collect();
    format!("{s:<w$}")
}

pub fn render_diff(d: &TraceDiff, color: bool, verbose: bool) -> String {
    let s = Style { color };
    let mut out = String::new();
    out.push_str(&s.bold("TraceWhy Diff"));
    out.push('\n');
    out.push_str(&s.dim(RULE));
    out.push('\n');
    let code = |c: Option<i32>| {
        c.map(|c| format!("exit {c}"))
            .unwrap_or_else(|| "exit ?".into())
    };
    out.push_str(&format!(
        "{}{}\n",
        s.green(&col(&format!("WORKING ({})", code(d.good_exit)), 30)),
        s.red(&format!("BROKEN ({})", code(d.bad_exit)))
    ));
    for n in &d.notes {
        out.push_str(&format!("{}\n", s.yellow(&format!("note: {n}"))));
    }

    let limit = if verbose { usize::MAX } else { 6 };
    let env: Vec<_> = d
        .environment
        .iter()
        .filter(|x| verbose || x.relevance >= 0.5)
        .take(limit)
        .collect();
    if !env.is_empty() {
        out.push_str(&format!("\n{}\n", s.heading("Environment")));
        for e in env {
            out.push_str(&format!("{}\n", sanitize(&e.key)));
            out.push_str(&format!(
                "  {}{}\n",
                col(&sanitize(e.good.as_deref().unwrap_or("(absent)")), 28),
                sanitize(e.bad.as_deref().unwrap_or("(absent)"))
            ));
        }
    }
    let exec: Vec<_> = d
        .execution
        .iter()
        .filter(|x| verbose || x.relevance >= 0.5)
        .take(if verbose { 60 } else { 8 })
        .collect();
    if !exec.is_empty() {
        out.push_str(&format!("\n{}\n", s.heading("Execution")));
        for e in exec {
            out.push_str(&format!("{}\n", sanitize(&e.key)));
            out.push_str(&format!(
                "  {}{}\n",
                col(&sanitize(e.good.as_deref().unwrap_or("not reached")), 28),
                sanitize(e.bad.as_deref().unwrap_or("not reached"))
            ));
        }
    }
    match &d.divergence {
        Some(dv) => {
            out.push_str(&format!("\n{}\n", s.heading("Causal divergence")));
            out.push_str(&format!("{}\n", s.green("WORKING")));
            chain(&mut out, &dv.good_chain);
            out.push_str(&format!("{}\n", s.red("BROKEN")));
            chain(&mut out, &dv.bad_chain);
            out.push_str(&format!(
                "\n{}\n  {}\n",
                s.heading("Likely difference"),
                sanitize(&dv.explanation)
            ));
            let label = match dv.confidence {
                Confidence::High => s.green("HIGH"),
                Confidence::Medium => s.yellow("MEDIUM"),
                Confidence::Low => s.red("LOW"),
            };
            out.push_str(&format!("\nConfidence: {label}\n"));
        }
        None => {
            out.push_str(&format!("\n{}\n", s.heading("Causal divergence")));
            out.push_str("  None found: no operation that succeeded in the working run failed in the broken run.\n");
        }
    }
    out.push_str(&s.dim(RULE));
    out.push('\n');
    out.push_str(&s.dim(&format!(
        "{} raw differences → {} semantic differences → {} relevant differences → {} causal divergence{}",
        thousands(d.stats.raw_differences),
        thousands(d.stats.semantic_differences),
        thousands(d.stats.relevant_differences),
        d.stats.causal_divergences,
        if d.stats.causal_divergences == 1 { "" } else { "s" }
    )));
    out.push('\n');
    out
}

fn chain(out: &mut String, steps: &[String]) {
    for (i, st) in steps.iter().enumerate() {
        if i > 0 {
            out.push_str("   ↓\n");
        }
        out.push_str(&format!("{}\n", sanitize(st)));
    }
}
