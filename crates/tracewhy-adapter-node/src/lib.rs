//! Node.js runtime adapter.
//!
//! Knows about package.json, lockfiles / package managers and node_modules.
//! Its one runtime-specific observation is "module not found": the program's
//! `Cannot find module 'x'` report, corroborated by the trace's failed
//! node_modules lookups and checked against the project on disk.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracewhy_core::{
    AdapterContext, Fact, FactKind, Observation, ObservationKind, RuntimeAdapter,
    RuntimeHypothesis, Suggestion, SuggestionKind,
};
use tracewhy_event::EventKind;

pub struct NodeAdapter;

const NODE_BINS: &[&str] = &[
    "node", "nodejs", "npm", "npx", "pnpm", "yarn", "bun", "tsx", "ts-node",
];

/// The nearest directory at or above `start` that contains package.json.
pub fn project_root(start: &Path) -> Option<PathBuf> {
    let mut d = Some(start);
    let mut n = 0;
    while let Some(dir) = d {
        if dir.join("package.json").is_file() {
            return Some(dir.to_path_buf());
        }
        n += 1;
        if n > 12 {
            break;
        }
        d = dir.parent();
    }
    None
}

pub fn package_manager(root: &Path) -> &'static str {
    if root.join("pnpm-lock.yaml").exists() {
        "pnpm"
    } else if root.join("yarn.lock").exists() {
        "yarn"
    } else if root.join("bun.lockb").exists() || root.join("bun.lock").exists() {
        "bun"
    } else {
        "npm"
    }
}

/// Bare package name of a module specifier (`@scope/pkg/sub` → `@scope/pkg`).
pub fn package_of(spec: &str) -> Option<String> {
    if spec.starts_with('.') || spec.starts_with('/') || spec.starts_with("node:") {
        return None;
    }
    let mut parts = spec.split('/');
    let first = parts.next()?;
    if first.starts_with('@') {
        Some(format!("{first}/{}", parts.next()?))
    } else {
        Some(first.to_string())
    }
}

/// Module specifiers reported missing in Node error output.
pub fn missing_modules(stderr: &str) -> Vec<String> {
    let mut out = Vec::new();
    for marker in ["Cannot find module '", "Cannot find package '"] {
        let mut rest = stderr;
        while let Some(i) = rest.find(marker) {
            let after = &rest[i + marker.len()..];
            if let Some(end) = after.find('\'') {
                let spec = after[..end].to_string();
                if !out.contains(&spec) {
                    out.push(spec);
                }
                rest = &after[end..];
            } else {
                break;
            }
        }
    }
    out
}

fn chain_stderr(ctx: &AdapterContext<'_>) -> String {
    ctx.events
        .iter()
        .filter(|e| ctx.failure_chain.contains(&e.process()))
        .filter_map(|e| match &e.kind {
            EventKind::Output { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect()
}

fn read_package_json(root: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(root.join("package.json")).ok()?;
    serde_json::from_str(&text).ok()
}

fn declared(pkg: &Value, name: &str) -> bool {
    [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]
    .iter()
    .any(|k| pkg.get(k).and_then(|d| d.get(name)).is_some())
}

fn prop(key: &str, subject: &str, value: &str, description: String) -> FactKind {
    FactKind::Property {
        key: key.into(),
        subject: subject.into(),
        value: value.into(),
        description,
    }
}

fn find_prop<'a>(facts: &'a [Fact], key: &str, subject: &str) -> Option<&'a Fact> {
    facts.iter().rev().find(|f| matches!(&f.kind, FactKind::Property { key: k, subject: s, .. } if k == key && s == subject))
}

fn prop_value(f: &Fact) -> &str {
    match &f.kind {
        FactKind::Property { value, .. } => value,
        _ => "",
    }
}

impl RuntimeAdapter for NodeAdapter {
    fn id(&self) -> &'static str {
        "node"
    }

    fn detect(&self, ctx: &AdapterContext<'_>) -> bool {
        ctx.tree.processes.values().any(|p| {
            p.executable
                .as_deref()
                .map(|e| NODE_BINS.contains(&e.rsplit('/').next().unwrap_or(e)))
                .unwrap_or(false)
        })
    }

    fn collect(&self, ctx: &AdapterContext<'_>) -> Vec<FactKind> {
        let mut out = Vec::new();
        let node_exe = ctx
            .tree
            .processes
            .values()
            .filter_map(|p| p.executable.clone())
            .find(|e| e.ends_with("/node") || e.ends_with("/nodejs"));
        let version = node_exe.as_deref().and_then(run_version);
        let mut details = BTreeMap::new();
        let Some(root) = project_root(&ctx.cwd) else {
            out.push(FactKind::RuntimeInfo {
                runtime: "Node.js".into(),
                version,
                details,
            });
            return out;
        };
        let root_s = root.to_string_lossy().into_owned();
        let pm = package_manager(&root);
        details.insert("project_root".into(), root_s.clone());
        details.insert("package_manager".into(), pm.into());
        let has_nm = root.join("node_modules").is_dir();
        details.insert(
            "node_modules".into(),
            if has_nm { "present" } else { "missing" }.into(),
        );
        if root.join(".env").exists() {
            details.insert("dotenv_file".into(), "present".into());
        }
        let pkg = read_package_json(&root);
        if let Some(e) = pkg
            .as_ref()
            .and_then(|p| p.get("engines"))
            .and_then(|e| e.get("node"))
            .and_then(|v| v.as_str())
        {
            details.insert("engines.node".into(), e.into());
        }
        out.push(FactKind::RuntimeInfo {
            runtime: "Node.js".into(),
            version,
            details,
        });
        out.push(prop(
            "node.node_modules",
            &root_s,
            if has_nm { "present" } else { "missing" },
            if has_nm {
                format!("{root_s}/node_modules exists")
            } else {
                format!("{root_s}/node_modules does not exist")
            },
        ));
        for spec in missing_modules(&chain_stderr(ctx)) {
            let Some(name) = package_of(&spec) else {
                continue;
            };
            let is_declared = pkg.as_ref().map(|p| declared(p, &name)).unwrap_or(false);
            out.push(prop(
                "node.declared",
                &name,
                if is_declared { "yes" } else { "no" },
                if is_declared {
                    format!("package.json declares \"{name}\"")
                } else {
                    format!("package.json does not declare \"{name}\"")
                },
            ));
            let installed = root
                .join("node_modules")
                .join(&name)
                .join("package.json")
                .is_file();
            out.push(prop(
                "node.installed",
                &name,
                if installed { "yes" } else { "no" },
                if installed {
                    format!("node_modules/{name} is installed")
                } else {
                    format!("node_modules/{name} is not installed")
                },
            ));
            out.push(prop(
                "node.package_manager",
                &name,
                pm,
                format!("Project uses {pm}"),
            ));
        }
        out
    }

    fn observations(&self, ctx: &AdapterContext<'_>) -> Vec<(ObservationKind, u32, Vec<u64>)> {
        let stderr = chain_stderr(ctx);
        let mut out = Vec::new();
        for spec in missing_modules(&stderr) {
            let Some(name) = package_of(&spec) else {
                continue;
            };
            // Corroborate with the trace: failed lookups in node_modules.
            let probes: Vec<(u32, u64)> = ctx
                .events
                .iter()
                .filter_map(|e| match &e.kind {
                    EventKind::PathOpFailed { path, .. }
                    | EventKind::FileOpenFailed { path, .. }
                        if path.ends_with("/node_modules")
                            || path.contains(&format!("/node_modules/{name}")) =>
                    {
                        Some((e.process(), e.seq))
                    }
                    _ => None,
                })
                .collect();
            let Some(&(pid, _)) = probes.last() else {
                continue;
            };
            let mut detail = BTreeMap::new();
            detail.insert("specifier".into(), spec.clone());
            detail.insert("failed_lookups".into(), probes.len().to_string());
            out.push((
                ObservationKind::Runtime {
                    adapter: "node".into(),
                    code: "MODULE_NOT_FOUND".into(),
                    subject: name,
                    detail,
                },
                pid,
                probes.iter().map(|p| p.1).collect(),
            ));
        }
        out
    }

    fn evaluate(&self, obs: &Observation, facts: &[Fact]) -> Vec<RuntimeHypothesis> {
        let ObservationKind::Runtime {
            adapter,
            code,
            subject: name,
            detail,
        } = &obs.kind
        else {
            return Vec::new();
        };
        if adapter != "node" || code != "MODULE_NOT_FOUND" {
            return Vec::new();
        }
        let lookups = detail.get("failed_lookups").cloned().unwrap_or_default();
        let observed = vec![format!(
            "Node.js looked for \"{name}\" in node_modules {lookups} time(s) and failed"
        )];
        let nm = facts.iter().rev().find(
            |f| matches!(&f.kind, FactKind::Property { key, .. } if key == "node.node_modules"),
        );
        let (Some(dec), Some(inst)) = (
            find_prop(facts, "node.declared", name),
            find_prop(facts, "node.installed", name),
        ) else {
            return vec![RuntimeHypothesis {
                kind: "node_module_missing".into(),
                title: format!("Node.js module \"{name}\" is not installed."),
                score: 0.6,
                support: Vec::new(),
                against: Vec::new(),
                observed,
                inference: None,
                suggestion: Some(Suggestion {
                    kind: SuggestionKind::NextStep,
                    text: format!("Install \"{name}\""),
                    command: Some(format!("npm install {name}")),
                }),
            }];
        };
        let pm = find_prop(facts, "node.package_manager", name)
            .map(prop_value)
            .unwrap_or("npm")
            .to_string();
        let install = if pm == "npm" {
            "npm install".to_string()
        } else {
            format!("{pm} install")
        };
        let add = match pm.as_str() {
            "npm" => format!("npm install {name}"),
            "yarn" => format!("yarn add {name}"),
            other => format!("{other} add {name}"),
        };
        let nm_missing = nm.map(|f| prop_value(f) == "missing").unwrap_or(false);
        let mut out = Vec::new();
        if prop_value(inst) == "yes" {
            return vec![RuntimeHypothesis {
                kind: "node_module_resolution".into(),
                title: format!("\"{name}\" is installed but Node.js could not resolve it from the running script's location."),
                score: 0.55,
                support: vec![inst.id],
                against: Vec::new(),
                observed,
                inference: Some("The script may live outside the project directory, or NODE_PATH / module type settings differ.".into()),
                suggestion: Some(Suggestion { kind: SuggestionKind::NextStep, text: "Run the script from the project directory".into(), command: None }),
            }];
        }
        if prop_value(dec) == "yes" {
            let mut support = vec![dec.id, inst.id];
            if nm_missing {
                if let Some(n) = nm {
                    support.push(n.id);
                }
                out.push(RuntimeHypothesis {
                    kind: "node_dependencies_not_installed".into(),
                    title: "Dependencies are not installed (node_modules is missing).".into(),
                    score: 0.93,
                    support,
                    against: Vec::new(),
                    observed,
                    inference: Some(format!("package.json declares \"{name}\", but no node_modules directory exists; dependencies were never installed here.")),
                    suggestion: Some(Suggestion { kind: SuggestionKind::Fix, text: "Install the project's dependencies".into(), command: Some(install) }),
                });
            } else {
                out.push(RuntimeHypothesis {
                    kind: "node_package_not_installed".into(),
                    title: format!(
                        "Package \"{name}\" is declared in package.json but not installed."
                    ),
                    score: 0.9,
                    support,
                    against: Vec::new(),
                    observed,
                    inference: Some("node_modules is out of date with package.json.".into()),
                    suggestion: Some(Suggestion {
                        kind: SuggestionKind::Fix,
                        text: "Reinstall dependencies".into(),
                        command: Some(install),
                    }),
                });
            }
        } else {
            out.push(RuntimeHypothesis {
                kind: "node_package_not_declared".into(),
                title: format!("Package \"{name}\" is used but not declared in package.json."),
                score: 0.85,
                support: vec![dec.id, inst.id],
                against: Vec::new(),
                observed,
                inference: None,
                suggestion: Some(Suggestion {
                    kind: SuggestionKind::Fix,
                    text: format!("Add \"{name}\" as a dependency"),
                    command: Some(add),
                }),
            });
        }
        out
    }
}

fn run_version(exe: &str) -> Option<String> {
    tracewhy_core::probe_version(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_specifiers() {
        assert_eq!(package_of("express"), Some("express".into()));
        assert_eq!(package_of("@scope/pkg/sub/x"), Some("@scope/pkg".into()));
        assert_eq!(package_of("lodash/fp"), Some("lodash".into()));
        assert_eq!(package_of("./local"), None);
        assert_eq!(package_of("node:fs"), None);
    }

    #[test]
    fn finds_missing_modules() {
        let s = "Error: Cannot find module 'express'\nRequire stack:\n- /a.js\nError [ERR_MODULE_NOT_FOUND]: Cannot find package 'zod' imported from /b.mjs\n";
        assert_eq!(
            missing_modules(s),
            vec!["express".to_string(), "zod".to_string()]
        );
    }
}
