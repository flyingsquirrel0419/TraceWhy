//! Rendering: the human report, the verbose report, and the stable JSON report.
//!
//! Renderers only format what the engine concluded. Observed evidence and
//! inference are always printed in separate sections.

mod diff;
pub mod json;
pub mod style;

pub use diff::render_diff;
pub use style::Style;

use style::{duration, sanitize, thousands};
use tracewhy_core::{ChainStep, ConclusionStatus, Confidence, InvestigationStatus, SuggestionKind};
use tracewhy_format::WhyTrace;

#[derive(Debug, Clone, Copy)]
pub struct ReportOptions {
    pub verbose: bool,
    pub color: bool,
}

const RULE: &str = "────────────────────────────────────────";

pub fn command_line(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty()
                || a.chars()
                    .any(|c| c.is_whitespace() || "\"'$`\\|&;<>(){}*?".contains(c))
            {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn stats_line(t: &WhyTrace) -> String {
    let causes = match t.conclusion.status {
        ConclusionStatus::RootCause => "1 root cause",
        ConclusionStatus::Undetermined => "no root cause identified",
        ConclusionStatus::Succeeded => "no failure",
    };
    let n = t.facts.len() as u64;
    format!(
        "{} system events → {} {} → {causes}",
        thousands(t.stats.raw_events),
        thousands(n),
        if n == 1 { "fact" } else { "facts" }
    )
}

fn render_chain(out: &mut String, chain: &[ChainStep], s: &Style) {
    let mut start = 2usize;
    let mut prev_len = 0usize;
    for (i, step) in chain.iter().enumerate() {
        let label = sanitize(&step.label);
        let shown = if step.inferred {
            format!("{label} (inferred)")
        } else {
            label.clone()
        };
        let shown = if step.inferred { s.dim(&shown) } else { shown };
        if i == 0 {
            out.push_str(&format!("{}{}\n", " ".repeat(start), s.bold(&shown)));
        } else {
            let mut pipe = start + (prev_len / 2).clamp(2, 12);
            if pipe > 40 {
                pipe = 6 + (i % 2) * 2;
            }
            out.push_str(&format!("{}│\n", " ".repeat(pipe)));
            let text = if step.kind == tracewhy_core::ChainStepKind::Failure {
                s.red(&shown)
            } else {
                shown
            };
            out.push_str(&format!("{}└─ {}\n", " ".repeat(pipe), text));
            start = pipe + 3;
        }
        prev_len = label.chars().count();
    }
}

/// The default human-readable report.
pub fn render(t: &WhyTrace, o: &ReportOptions) -> String {
    let s = Style { color: o.color };
    let c = &t.conclusion;
    let mut out = String::new();
    out.push_str(&s.bold("TraceWhy"));
    out.push('\n');
    out.push_str(&s.dim(RULE));
    out.push('\n');
    let cmd = sanitize(&command_line(&t.run.command));
    let exit_desc = t
        .run
        .exit
        .as_ref()
        .map(|e| e.describe())
        .unwrap_or_else(|| "finished".into());
    let ok = c.status == ConclusionStatus::Succeeded;
    let mark = if ok { s.green("✓") } else { s.red("✗") };
    out.push_str(&format!(
        "{mark} {}\n  {exit_desc} after {}\n",
        s.bold(&cmd),
        duration(t.run.duration_ms)
    ));

    match c.status {
        ConclusionStatus::Succeeded => {
            out.push_str(&format!(
                "\n{}\n",
                s.green("The command succeeded; nothing to explain.")
            ));
            if o.verbose {
                for n in &c.contributing {
                    out.push_str(&format!("  {}\n", s.dim(&sanitize(n))));
                }
            }
        }
        ConclusionStatus::Undetermined => {
            out.push_str(&format!("\n{}\n", s.heading("Root cause")));
            out.push_str(
                "  Not determined: the trace holds no evidence strong enough to name a cause.\n",
            );
            if !c.evidence.is_empty() {
                out.push_str(&format!("\n{}\n", s.heading("Observed")));
                for e in &c.evidence {
                    out.push_str(&format!("  {} {}\n", s.green("✓"), sanitize(&e.text)));
                }
            }
            if !c.contributing.is_empty() {
                out.push_str(&format!(
                    "\n{}\n",
                    s.heading("Possible contributing factors")
                ));
                for n in &c.contributing {
                    out.push_str(&format!(
                        "  ? {}\n",
                        sanitize(n.trim_start_matches("Possible contributing factor: "))
                    ));
                }
            }
        }
        ConclusionStatus::RootCause => {
            let conf = c.confidence.unwrap_or(Confidence::Low);
            let head = if conf == Confidence::Low {
                "Possible cause"
            } else {
                "Root cause"
            };
            out.push_str(&format!("\n{}\n", s.heading(head)));
            if let Some(rc) = &c.root_cause {
                out.push_str(&format!("  {}\n", s.bold(&sanitize(&rc.title))));
                if let Some(d) = &rc.detail {
                    out.push_str(&format!("  {}\n", sanitize(d)));
                }
            }
            if !c.chain.is_empty() {
                out.push_str(&format!("\n{}\n", s.heading("Evidence")));
                render_chain(&mut out, &c.chain, &s);
            }
            if !c.evidence.is_empty() {
                out.push_str(&format!("\n{}\n", s.heading("Observed")));
                for e in &c.evidence {
                    out.push_str(&format!("  {} {}\n", s.green("✓"), sanitize(&e.text)));
                }
            }
            if !c.inferences.is_empty() {
                out.push_str(&format!("\n{}\n", s.heading("Inference")));
                for i in &c.inferences {
                    out.push_str(&format!("  {}\n", sanitize(i)));
                }
            }
            out.push_str(&format!("\n{}\n", s.heading("Confidence")));
            let label = match conf {
                Confidence::High => s.green(conf.label()),
                Confidence::Medium => s.yellow(conf.label()),
                Confidence::Low => s.red(conf.label()),
            };
            out.push_str(&format!("  {label}\n"));
            if !c.alternatives.is_empty() {
                out.push_str(&format!("\n{}\n", s.heading("Other possibilities")));
                for a in &c.alternatives {
                    out.push_str(&format!(
                        "  ? {} {}\n",
                        sanitize(&a.title),
                        s.dim(&format!("({})", a.confidence.label()))
                    ));
                }
            }
            if !c.contributing.is_empty() {
                out.push_str(&format!(
                    "\n{}\n",
                    s.heading("Possible contributing factors")
                ));
                for n in &c.contributing {
                    out.push_str(&format!(
                        "  ? {}\n",
                        sanitize(n.trim_start_matches("Possible contributing factor: "))
                    ));
                }
            }
        }
    }

    if let Some(sug) = c.suggestions.first() {
        let head = match sug.kind {
            SuggestionKind::Fix => "Suggested fix",
            SuggestionKind::NextStep => "Suggested next step",
        };
        out.push_str(&format!("\n{}\n", s.heading(head)));
        match &sug.command {
            Some(cmd) => {
                out.push_str(&format!("  {}\n", s.cyan(&sanitize(cmd))));
                out.push_str(&format!("  {}\n", s.dim(&sanitize(&sug.text))));
            }
            None => out.push_str(&format!("  {}\n", sanitize(&sug.text))),
        }
    } else if c.status == ConclusionStatus::Undetermined {
        out.push_str(&format!("\n{}\n", s.heading("Suggested next step")));
        out.push_str("  Re-run with --verbose to see every observation and investigation.\n");
    }

    if c.status != ConclusionStatus::Succeeded {
        if let Some(e) = &c.stderr_excerpt {
            if o.verbose || c.status == ConclusionStatus::Undetermined {
                out.push_str(&format!("\n{}\n", s.heading("Program output (last lines)")));
                for l in sanitize(e).lines() {
                    out.push_str(&format!("  {}\n", s.dim(l)));
                }
            }
        }
    }

    if o.verbose {
        render_verbose(&mut out, t, &s);
    }

    out.push_str(&s.dim(RULE));
    out.push('\n');
    out.push_str(&s.dim(&stats_line(t)));
    out.push('\n');
    if t.stats.truncated {
        out.push_str(&s.yellow(
            "note: the trace was truncated by resource limits; conclusions may be incomplete\n",
        ));
    }
    out
}

fn render_verbose(out: &mut String, t: &WhyTrace, s: &Style) {
    out.push_str(&format!("\n{}\n", s.heading("Process tree")));
    if let Some(root) = t.process_tree.root {
        let mut stack = vec![(root, 0usize)];
        let mut shown = 0;
        while let Some((pid, depth)) = stack.pop() {
            let Some(p) = t.process_tree.get(pid) else {
                continue;
            };
            shown += 1;
            if shown > 60 {
                out.push_str("  ...\n");
                break;
            }
            let exit = p
                .exit
                .as_ref()
                .map(|e| e.describe())
                .unwrap_or_else(|| "running".into());
            let mark = if p.exit.as_ref().map(|e| e.success()).unwrap_or(true) {
                " "
            } else {
                "✗"
            };
            out.push_str(&format!(
                "  {}{mark} [{pid}] {} {}\n",
                "  ".repeat(depth),
                sanitize(&p.display_name()),
                s.dim(&format!("({exit})"))
            ));
            for c in p.children.iter().rev() {
                stack.push((*c, depth + 1));
            }
        }
    }
    let obs: Vec<_> = t
        .observations
        .iter()
        .filter(|o| o.relevance.score >= 0.1)
        .take(15)
        .collect();
    if !obs.is_empty() {
        out.push_str(&format!("\n{}\n", s.heading("Observations (by relevance)")));
        for o in obs {
            let mut flags = Vec::new();
            if o.relevance.reported_on_stderr {
                flags.push("reported");
            }
            if o.relevance.terminal {
                flags.push("terminal");
            }
            if o.relevance.recovered {
                flags.push("recovered");
            }
            if o.relevance.probe {
                flags.push("probe");
            }
            out.push_str(&format!(
                "  {:.2} [pid {}] {} {}\n",
                o.relevance.score,
                o.pid,
                sanitize(&o.kind.describe()),
                s.dim(&flags.join(","))
            ));
        }
    }
    if !t.hypotheses.is_empty() {
        out.push_str(&format!("\n{}\n", s.heading("Hypotheses")));
        let mut hs: Vec<_> = t.hypotheses.iter().collect();
        hs.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        for h in hs {
            out.push_str(&format!(
                "  {:.2} {:<11} {} {}\n",
                h.score,
                format!("{:?}", h.status).to_lowercase(),
                h.kind,
                s.dim(&sanitize(&h.title))
            ));
        }
    }
    if !t.investigations.is_empty() {
        out.push_str(&format!("\n{}\n", s.heading("Investigations")));
        for r in &t.investigations {
            let st = match r.status {
                InvestigationStatus::Completed => s.green("ok"),
                InvestigationStatus::Skipped => s.dim("skipped"),
                _ => s.yellow(&format!("{:?}", r.status).to_lowercase()),
            };
            out.push_str(&format!(
                "  round {} {:<12} {} {st} {}ms{}\n",
                r.round,
                r.investigator,
                sanitize(&r.target.describe()),
                r.duration_ms,
                r.message
                    .as_ref()
                    .map(|m| format!(" ({})", sanitize(m)))
                    .unwrap_or_default()
            ));
        }
    }
    out.push_str(&format!("\n{}\n", s.heading("Facts")));
    for f in t.facts.iter().take(40) {
        out.push_str(&format!(
            "  #{:<3} {} {}\n",
            f.id,
            sanitize(&f.kind.describe()),
            s.dim(&format!("[{}]", f.source.label()))
        ));
    }
    out.push_str(&format!(
        "\n{}\n  {} raw lines, {} raw events, {} semantic events ({} dropped), {} processes, {} unparsed lines\n",
        s.heading("Trace"),
        thousands(t.stats.raw_lines),
        thousands(t.stats.raw_events),
        thousands(t.stats.semantic_events),
        thousands(t.stats.dropped_events),
        t.stats.processes,
        t.stats.unparsed_lines
    ));
    for d in t.diagnostics.iter().take(10) {
        out.push_str(&format!(
            "  {} {}\n",
            s.yellow("diagnostic:"),
            sanitize(&d.message)
        ));
    }
}
