//! Three-level comparison of a working and a broken run.
//!
//! 1. **Environment diff** — platform, variables, PATH, runtime versions and
//!    investigated system state.
//! 2. **Execution diff** — semantic operations (exec, open, connect, bind,
//!    DNS) keyed independently of pids and timing, compared by outcome.
//! 3. **Causal diff** — the first relevant operation that succeeded in the
//!    working run but failed in the broken one, tied to the broken run's
//!    root cause when it has one.
//!
//! Noise (procfs, temp files, locale probes, caches) is down-weighted so
//! thousands of raw differences condense to a handful of relevant ones.

mod ops;

use ops::{cause_key, noise_weight, operations, raw_key};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracewhy_core::{Confidence, FactKind};
use tracewhy_event::{Endpoint, EventKind};
use tracewhy_format::WhyTrace;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Difference {
    pub category: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub good: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad: Option<String>,
    pub relevance: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Divergence {
    pub key: String,
    pub summary: String,
    pub good_chain: Vec<String>,
    pub bad_chain: Vec<String>,
    pub explanation: String,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffStats {
    pub raw_differences: u64,
    pub semantic_differences: u64,
    pub relevant_differences: u64,
    pub causal_divergences: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceDiff {
    pub good_command: Vec<String>,
    pub bad_command: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub good_exit: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bad_exit: Option<i32>,
    pub environment: Vec<Difference>,
    pub execution: Vec<Difference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub divergence: Option<Divergence>,
    pub stats: DiffStats,
    #[serde(default)]
    pub notes: Vec<String>,
}

fn fact_map(t: &WhyTrace) -> HashMap<String, String> {
    t.facts
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FactKind::RuntimeInfo { .. }
                    | FactKind::DockerStatus { .. }
                    | FactKind::ContainerState { .. }
                    | FactKind::PortListeners { .. }
                    | FactKind::DnsResolution { .. }
                    | FactKind::ExecutableSearch { .. }
                    | FactKind::Filesystem { .. }
            )
        })
        .map(|f| (f.kind.subject_key(), f.kind.describe()))
        .collect()
}

pub fn diff(good: &WhyTrace, bad: &WhyTrace) -> TraceDiff {
    let mut notes = Vec::new();
    if good.run.command != bad.run.command {
        notes.push(
            "The two traces ran different commands; differences may reflect that.".to_string(),
        );
    }
    if good.run.exit.as_ref().map(|e| e.success()) == Some(false) {
        notes.push("The \"good\" trace did not succeed either.".to_string());
    }

    // --- Environment ---
    let mut environment = Vec::new();
    let mut envd = |key: &str, g: Option<String>, b: Option<String>, rel: f64| {
        if g != b {
            environment.push(Difference {
                category: "environment".into(),
                key: key.into(),
                good: g,
                bad: b,
                relevance: rel,
            });
        }
    };
    envd(
        "arch",
        Some(good.run.arch.clone()),
        Some(bad.run.arch.clone()),
        0.9,
    );
    envd(
        "kernel",
        good.run.kernel.clone(),
        bad.run.kernel.clone(),
        0.2,
    );
    envd(
        "cwd",
        Some(good.run.cwd.clone()),
        Some(bad.run.cwd.clone()),
        0.4,
    );
    envd(
        "user",
        good.environment.user.clone(),
        bad.environment.user.clone(),
        0.5,
    );
    let mut keys: Vec<&String> = good
        .environment
        .variables
        .keys()
        .chain(bad.environment.variables.keys())
        .collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        let g = good.environment.variables.get(k);
        let b = bad.environment.variables.get(k);
        let rel = if matches!(
            k.as_str(),
            "PATH"
                | "LD_LIBRARY_PATH"
                | "VIRTUAL_ENV"
                | "PYTHONPATH"
                | "NODE_OPTIONS"
                | "DOCKER_HOST"
        ) {
            0.6
        } else {
            0.3
        };
        match (g, b) {
            (Some(g), Some(b)) if g != b => envd(
                &format!("env:{k}"),
                Some(g.clone().unwrap_or_else(|| "(set)".into())),
                Some(
                    b.clone()
                        .unwrap_or_else(|| "(set, value differs or not recorded)".into()),
                ),
                rel,
            ),
            (Some(g), None) => envd(
                &format!("env:{k}"),
                Some(g.clone().unwrap_or_else(|| "(set)".into())),
                None,
                rel,
            ),
            (None, Some(b)) => envd(
                &format!("env:{k}"),
                None,
                Some(b.clone().unwrap_or_else(|| "(set)".into())),
                rel,
            ),
            _ => {}
        }
    }
    for (k, gv) in &good.environment.fingerprints {
        if let Some(bv) = bad.environment.fingerprints.get(k) {
            if gv != bv {
                envd(
                    &format!("env:{k}"),
                    Some("(value A)".into()),
                    Some("(value B, differs)".into()),
                    0.6,
                );
            }
        }
    }
    let gf = fact_map(good);
    let bf = fact_map(bad);
    let mut fkeys: Vec<&String> = gf.keys().chain(bf.keys()).collect();
    fkeys.sort();
    fkeys.dedup();
    for k in fkeys {
        let (g, b) = (gf.get(k).cloned(), bf.get(k).cloned());
        if g.is_some() && b.is_some() && g != b {
            envd(&format!("fact:{k}"), g, b, 0.7);
        }
    }

    // --- Execution ---
    let gops = operations(&good.events, good);
    let bops = operations(&bad.events, bad);
    let mut raw: HashMap<String, i64> = HashMap::new();
    for e in &good.events {
        *raw.entry(raw_key(e)).or_insert(0) += 1;
    }
    for e in &bad.events {
        *raw.entry(raw_key(e)).or_insert(0) -= 1;
    }
    let raw_differences: u64 = raw.values().map(|v| v.unsigned_abs()).sum();

    let cause = cause_key(bad);
    let mut execution = Vec::new();
    let mut keys: Vec<&String> = gops.keys().chain(bops.keys()).collect();
    keys.sort();
    keys.dedup();
    for k in keys {
        let (g, b) = (gops.get(k), bops.get(k));
        let differs = match (g, b) {
            (Some(g), Some(b)) => g.outcome != b.outcome,
            _ => true,
        };
        if !differs {
            continue;
        }
        let mut rel = noise_weight(k);
        match (g, b) {
            (Some(g), Some(b)) if g.ok && !b.ok => rel *= 1.0,
            (Some(g), Some(b)) if !g.ok && b.ok => rel *= 0.5,
            (Some(_), Some(_)) => rel *= 0.7,
            (None, Some(b)) if !b.ok => rel *= 0.8,
            _ => rel *= 0.35,
        }
        if cause.as_deref() == Some(k.as_str()) {
            rel = 1.0;
        }
        execution.push((
            b.map(|o| o.first_seq).unwrap_or(u64::MAX),
            Difference {
                category: k.split(':').next().unwrap_or("").to_string(),
                key: k.clone(),
                good: g.map(|o| o.outcome.clone()),
                bad: b.map(|o| o.outcome.clone()),
                relevance: (rel * 100.0).round() / 100.0,
            },
        ));
    }
    let semantic_differences = execution.len() as u64;
    execution.sort_by(|a, b| {
        b.1.relevance
            .partial_cmp(&a.1.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.cmp(&b.0))
    });
    let execution: Vec<Difference> = execution.into_iter().map(|x| x.1).collect();
    let relevant: Vec<&Difference> = execution.iter().filter(|d| d.relevance >= 0.5).collect();

    // --- Causal divergence ---
    let flip = |d: &&Difference| {
        gops.get(&d.key).map(|o| o.ok).unwrap_or(false)
            && bops.get(&d.key).map(|o| !o.ok).unwrap_or(false)
    };
    // The broken run's root-cause operation is the divergence whenever the
    // working run did not fail the same way (it succeeded, or never needed it).
    let differs_from_good = |d: &&Difference| {
        bops.get(&d.key).map(|o| !o.ok).unwrap_or(false)
            && gops.get(&d.key).map(|o| o.ok).unwrap_or(true)
    };
    let chosen = cause
        .as_ref()
        .and_then(|c| {
            relevant
                .iter()
                .find(|d| &d.key == c && differs_from_good(d))
        })
        .or_else(|| {
            // Earliest operation in the broken run that flipped from success to failure.
            relevant
                .iter()
                .filter(|d| flip(d) && !d.key.starts_with("exit:"))
                .min_by_key(|d| bops.get(&d.key).map(|o| o.first_seq).unwrap_or(u64::MAX))
        })
        .copied();
    let divergence = chosen.map(|d| {
        let tied = cause.as_deref() == Some(d.key.as_str()) && gops.contains_key(&d.key);
        let tied_absent = cause.as_deref() == Some(d.key.as_str()) && !gops.contains_key(&d.key);
        let (good_chain, bad_chain) = chains(d, good, bad);
        let subject = d
            .key
            .split_once(':')
            .map(|x| x.1)
            .unwrap_or(&d.key)
            .to_string();
        let explanation = match d.category.as_str() {
            "dns" => format!("{subject} cannot be resolved in the broken environment."),
            "connect" => format!(
                "The connection to {subject} fails in the broken environment ({}).",
                d.bad.clone().unwrap_or_default()
            ),
            "file" => format!(
                "{subject} is not accessible in the broken environment ({}).",
                d.bad.clone().unwrap_or_default()
            ),
            "exec" => format!(
                "{subject} cannot be executed in the broken environment ({}).",
                d.bad.clone().unwrap_or_default()
            ),
            "bind" => format!(
                "{subject} cannot be bound in the broken environment ({}).",
                d.bad.clone().unwrap_or_default()
            ),
            _ => format!(
                "{} behaves differently: {} vs {}.",
                d.key,
                d.good.clone().unwrap_or_default(),
                d.bad.clone().unwrap_or_default()
            ),
        };
        let mut explanation = explanation;
        let changed_vars: Vec<&str> = good
            .environment
            .fingerprints
            .iter()
            .filter(|(k, v)| {
                bad.environment
                    .fingerprints
                    .get(*k)
                    .map(|b| b != *v)
                    .unwrap_or(false)
            })
            .map(|(k, _)| k.as_str())
            .collect();
        if !changed_vars.is_empty() && changed_vars.len() <= 3 {
            explanation.push_str(&format!(
                " Possibly related: environment variable{} {} differ{} between the runs.",
                if changed_vars.len() == 1 { "" } else { "s" },
                changed_vars.join(", "),
                if changed_vars.len() == 1 { "s" } else { "" }
            ));
        }
        Divergence {
            key: d.key.clone(),
            summary: format!(
                "{}: {} → {}",
                d.key,
                d.good.clone().unwrap_or_default(),
                d.bad.clone().unwrap_or_default()
            ),
            good_chain,
            bad_chain,
            explanation,
            confidence: if tied {
                Confidence::High
            } else if tied_absent {
                // The working run reached its goal another way; the broken one failed here.
                if good.run.exit.as_ref().map(|e| e.success()).unwrap_or(false) {
                    Confidence::High
                } else {
                    Confidence::Medium
                }
            } else if bad.run.exit.as_ref().map(|e| !e.success()).unwrap_or(false) {
                Confidence::Medium
            } else {
                Confidence::Low
            },
        }
    });

    let stats = DiffStats {
        raw_differences,
        semantic_differences,
        relevant_differences: relevant.len() as u64,
        causal_divergences: u64::from(divergence.is_some()),
    };
    TraceDiff {
        good_command: good.run.command.clone(),
        bad_command: bad.run.command.clone(),
        good_exit: good.run.exit.as_ref().map(|e| e.shell_code()),
        bad_exit: bad.run.exit.as_ref().map(|e| e.shell_code()),
        environment,
        execution,
        divergence,
        stats,
        notes,
    }
}

/// Short causal chains for both runs around the diverging operation.
fn chains(d: &Difference, good: &WhyTrace, bad: &WhyTrace) -> (Vec<String>, Vec<String>) {
    let subject = d
        .key
        .split_once(':')
        .map(|x| x.1)
        .unwrap_or(&d.key)
        .to_string();
    let mut g = vec![subject.clone()];
    let mut b = vec![subject.clone()];
    if d.good.is_none() {
        g.push("not looked up in the working run".into());
        // If the working run made exactly one TCP connection, show it: that is
        // unambiguously where it went instead.
        if d.category == "dns" {
            let mut eps: Vec<String> = good
                .events
                .iter()
                .filter_map(|e| match &e.kind {
                    EventKind::Connected {
                        endpoint: ep @ Endpoint::Inet { .. },
                        protocol: tracewhy_event::Protocol::Tcp,
                    } => Some(ep.to_string()),
                    _ => None,
                })
                .collect();
            eps.sort();
            eps.dedup();
            if let [ep] = eps.as_slice() {
                g.push(format!("TCP connect {ep}"));
                g.push("success".into());
            }
        }
        b.push(d.bad.clone().unwrap_or_default());
        if cause_key(bad).as_deref() == Some(d.key.as_str()) {
            for step in bad
                .conclusion
                .chain
                .iter()
                .skip_while(|s| s.kind != tracewhy_core::ChainStepKind::Failure)
                .skip(1)
            {
                b.push(step.label.clone());
            }
        }
        return (g, b);
    }
    match d.category.as_str() {
        "dns" => {
            let addrs: Vec<String> = d
                .good
                .clone()
                .unwrap_or_default()
                .split(", ")
                .map(String::from)
                .collect();
            g.push(d.good.clone().unwrap_or_default());
            // What the working run did with the address.
            if let Some((ep, ok)) = good.events.iter().find_map(|e| match &e.kind {
                EventKind::Connected {
                    endpoint: ep @ Endpoint::Inet { address, .. },
                    ..
                } if addrs.contains(&address.to_string()) => Some((ep.to_string(), true)),
                EventKind::ConnectFailed {
                    endpoint: ep @ Endpoint::Inet { address, .. },
                    ..
                } if addrs.contains(&address.to_string()) => Some((ep.to_string(), false)),
                _ => None,
            }) {
                g.push(format!("TCP connect {ep}"));
                g.push(if ok {
                    "success".into()
                } else {
                    "failed".into()
                });
            }
            b.push(d.bad.clone().unwrap_or_default());
        }
        _ => {
            g.push(d.good.clone().unwrap_or_default());
            b.push(d.bad.clone().unwrap_or_default());
        }
    }
    // Extend the broken chain with its own root-cause explanation.
    if cause_key(bad).as_deref() == Some(d.key.as_str()) {
        for step in bad
            .conclusion
            .chain
            .iter()
            .skip_while(|s| s.kind != tracewhy_core::ChainStepKind::Failure)
            .skip(1)
        {
            b.push(step.label.clone());
        }
    }
    (g, b)
}
