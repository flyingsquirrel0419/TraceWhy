//! Python runtime adapter.
//!
//! Knows about interpreters, virtualenvs and dependency manifests. Its
//! runtime-specific observation is `ModuleNotFoundError`, corroborated by
//! the import system's directory scans in the trace and checked against
//! the interpreter's and the project's site-packages on disk.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tracewhy_core::{
    AdapterContext, Fact, FactKind, Observation, ObservationKind, RuntimeAdapter,
    RuntimeHypothesis, Suggestion, SuggestionKind,
};
use tracewhy_event::{EventKind, FileAccess};

pub struct PythonAdapter;

fn is_python(exe: &str) -> bool {
    let b = exe.rsplit('/').next().unwrap_or(exe);
    b == "python"
        || b == "python3"
        || (b.starts_with("python3.") && b[8..].bytes().all(|c| c.is_ascii_digit()))
}

/// Modules reported by `ModuleNotFoundError: No module named 'x'` (top-level package).
pub fn missing_modules(stderr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let marker = "No module named '";
    let mut rest = stderr;
    while let Some(i) = rest.find(marker) {
        let after = &rest[i + marker.len()..];
        let Some(end) = after.find('\'') else { break };
        let top = after[..end].split('.').next().unwrap_or("").to_string();
        if !top.is_empty() && !out.contains(&top) {
            out.push(top);
        }
        rest = &after[end..];
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

/// Project-local virtualenv directories near `cwd`.
pub fn project_venvs(cwd: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut d = Some(cwd);
    let mut n = 0;
    while let Some(dir) = d {
        for name in [".venv", "venv", "env", ".env"] {
            let p = dir.join(name);
            if p.join("pyvenv.cfg").is_file() {
                out.push(p);
            }
        }
        if !out.is_empty() || dir.join(".git").exists() || n > 6 {
            break;
        }
        n += 1;
        d = dir.parent();
    }
    out
}

/// Whether `module` is importable from site-packages directories under `prefix`.
fn installed_in(prefix: &Path, module: &str) -> Option<PathBuf> {
    let lib = prefix.join("lib");
    let rd = std::fs::read_dir(&lib).ok()?;
    for e in rd.flatten() {
        let sp = e.path().join("site-packages");
        for cand in [sp.join(module), sp.join(format!("{module}.py"))] {
            if cand.exists() {
                return Some(cand);
            }
        }
        if let Ok(files) = std::fs::read_dir(&sp) {
            for f in files.flatten() {
                let n = f.file_name().to_string_lossy().into_owned();
                if n.starts_with(&format!("{module}.")) && n.ends_with(".so") {
                    return Some(f.path());
                }
            }
        }
    }
    None
}

fn declared(root: &Path, module: &str) -> Option<String> {
    let norm = |s: &str| s.to_ascii_lowercase().replace(['-', '.'], "_");
    let m = norm(module);
    for file in [
        "requirements.txt",
        "requirements-dev.txt",
        "pyproject.toml",
        "setup.cfg",
        "Pipfile",
    ] {
        let Ok(text) = std::fs::read_to_string(root.join(file)) else {
            continue;
        };
        for line in text.lines() {
            let l = line.trim().trim_start_matches(['"', '\'']);
            let name: String = l
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                .collect();
            if !name.is_empty() && norm(&name) == m {
                return Some(file.to_string());
            }
        }
    }
    None
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

fn value(f: &Fact) -> &str {
    match &f.kind {
        FactKind::Property { value, .. } => value,
        _ => "",
    }
}

fn interpreter(ctx: &AdapterContext<'_>) -> Option<String> {
    ctx.failure_chain
        .iter()
        .rev()
        .filter_map(|p| ctx.tree.get(*p))
        .chain(ctx.tree.processes.values())
        .filter_map(|p| p.executable.clone())
        .find(|e| is_python(e))
}

impl RuntimeAdapter for PythonAdapter {
    fn id(&self) -> &'static str {
        "python"
    }

    fn detect(&self, ctx: &AdapterContext<'_>) -> bool {
        interpreter(ctx).is_some()
    }

    fn collect(&self, ctx: &AdapterContext<'_>) -> Vec<FactKind> {
        let mut out = Vec::new();
        let exe = interpreter(ctx);
        let mut details = BTreeMap::new();
        if let Some(e) = &exe {
            details.insert("interpreter".into(), e.clone());
        }
        if let Some(v) = ctx.env.get("VIRTUAL_ENV") {
            details.insert("virtual_env".into(), v.into());
        }
        let venvs = project_venvs(&ctx.cwd);
        if let Some(v) = venvs.first() {
            details.insert("project_venv".into(), v.to_string_lossy().into_owned());
        }
        for f in [
            "pyproject.toml",
            "requirements.txt",
            "uv.lock",
            "poetry.lock",
            "Pipfile",
        ] {
            if ctx.cwd.join(f).exists() {
                details.insert(format!("file.{f}"), "present".into());
            }
        }
        let version = exe.as_deref().and_then(version_of);
        out.push(FactKind::RuntimeInfo {
            runtime: "Python".into(),
            version,
            details,
        });

        let Some(exe) = exe else { return out };
        // The interpreter's prefix: /usr for /usr/bin/python3, <venv> for <venv>/bin/python.
        let prefix = Path::new(&exe)
            .parent()
            .and_then(|b| b.parent())
            .map(|p| p.to_path_buf());
        for module in missing_modules(&chain_stderr(ctx)) {
            let in_interp = prefix.as_deref().and_then(|p| installed_in(p, &module));
            out.push(prop(
                "python.installed_for_interpreter",
                &module,
                if in_interp.is_some() { "yes" } else { "no" },
                match &in_interp {
                    Some(p) => format!("\"{module}\" is installed for {exe} ({})", p.display()),
                    None => format!("\"{module}\" is not installed for {exe}"),
                },
            ));
            for v in &venvs {
                let uses_venv = exe.starts_with(&*v.to_string_lossy());
                if let (false, Some(p)) = (uses_venv, installed_in(v, &module)) {
                    out.push(prop(
                        "python.installed_in_project_venv",
                        &module,
                        &v.to_string_lossy(),
                        format!(
                            "\"{module}\" is installed in the project virtualenv {} ({})",
                            v.display(),
                            p.display()
                        ),
                    ));
                }
            }
            if let Some(file) = declared(&ctx.cwd, &module) {
                out.push(prop(
                    "python.declared",
                    &module,
                    &file,
                    format!("{file} declares \"{module}\""),
                ));
            }
        }
        out
    }

    fn observations(&self, ctx: &AdapterContext<'_>) -> Vec<(ObservationKind, u32, Vec<u64>)> {
        let mut out = Vec::new();
        for module in missing_modules(&chain_stderr(ctx)) {
            // Corroborate: the import system scanned its search path directories.
            let scans: Vec<(u32, u64, String)> = ctx
                .events
                .iter()
                .filter_map(|e| match &e.kind {
                    EventKind::FileOpened {
                        path,
                        access: FileAccess::Directory,
                        ..
                    } if path.contains("/site-packages")
                        || path.contains("/dist-packages")
                        || path.contains("/lib/python") =>
                    {
                        Some((e.process(), e.seq, path.clone()))
                    }
                    EventKind::PathOpFailed { path, .. }
                    | EventKind::FileOpenFailed { path, .. }
                        if path
                            .rsplit('/')
                            .next()
                            .map(|b| b == module || b.starts_with(&format!("{module}.")))
                            .unwrap_or(false) =>
                    {
                        Some((e.process(), e.seq, path.clone()))
                    }
                    _ => None,
                })
                .collect();
            let Some((pid, _, _)) = scans.last().cloned() else {
                continue;
            };
            let mut detail = BTreeMap::new();
            let mut dirs: Vec<String> = scans.iter().map(|s| s.2.clone()).collect();
            dirs.dedup();
            detail.insert("searched".into(), dirs.len().to_string());
            out.push((
                ObservationKind::Runtime {
                    adapter: "python".into(),
                    code: "ModuleNotFoundError".into(),
                    subject: module,
                    detail,
                },
                pid,
                scans.iter().map(|s| s.1).collect(),
            ));
        }
        out
    }

    fn evaluate(&self, obs: &Observation, facts: &[Fact]) -> Vec<RuntimeHypothesis> {
        let ObservationKind::Runtime {
            adapter,
            code,
            subject: module,
            detail,
        } = &obs.kind
        else {
            return Vec::new();
        };
        if adapter != "python" || code != "ModuleNotFoundError" {
            return Vec::new();
        }
        let searched = detail.get("searched").cloned().unwrap_or_default();
        let observed = vec![format!(
            "The import system searched {searched} location(s) without finding \"{module}\""
        )];
        let interp = find_prop(facts, "python.installed_for_interpreter", module);
        let venv = find_prop(facts, "python.installed_in_project_venv", module);
        let decl = find_prop(facts, "python.declared", module);
        let mut out = Vec::new();
        if let Some(i) = interp {
            if value(i) == "yes" {
                return vec![RuntimeHypothesis {
                    kind: "python_import_shadowed".into(),
                    title: format!("\"{module}\" is installed but could not be imported (shadowed or broken sys.path)."),
                    score: 0.5,
                    support: vec![i.id],
                    against: Vec::new(),
                    observed,
                    inference: Some("A local file or PYTHONPATH entry may shadow the package.".into()),
                    suggestion: Some(Suggestion { kind: SuggestionKind::NextStep, text: format!("Check `python -c 'import sys; print(sys.path)'` and files named {module}.py"), command: None }),
                }];
            }
        }
        if let (Some(v), Some(i)) = (venv, interp) {
            let path = value(v).to_string();
            out.push(RuntimeHypothesis {
                kind: "python_venv_not_active".into(),
                title: format!("\"{module}\" is installed in the project virtualenv, but the command used a different Python (virtualenv not active)."),
                score: 0.93,
                support: vec![v.id, i.id],
                against: Vec::new(),
                observed: observed.clone(),
                inference: Some(format!("The project's virtualenv at {path} has the module; the interpreter that ran does not.")),
                suggestion: Some(Suggestion {
                    kind: SuggestionKind::Fix,
                    text: "Activate the virtualenv (or run its interpreter directly)".into(),
                    command: Some(format!("source {path}/bin/activate")),
                }),
            });
        }
        if let (Some(d), Some(i)) = (decl, interp) {
            if venv.is_none() {
                let file = value(d).to_string();
                let cmd = if file == "requirements.txt" {
                    "pip install -r requirements.txt".to_string()
                } else {
                    "pip install -e .".to_string()
                };
                out.push(RuntimeHypothesis {
                    kind: "python_package_not_installed".into(),
                    title: format!("\"{module}\" is declared in {file} but not installed for this interpreter."),
                    score: 0.88,
                    support: vec![d.id, i.id],
                    against: Vec::new(),
                    observed: observed.clone(),
                    inference: None,
                    suggestion: Some(Suggestion { kind: SuggestionKind::Fix, text: "Install the project's dependencies".into(), command: Some(cmd) }),
                });
            }
        }
        if out.is_empty() {
            out.push(RuntimeHypothesis {
                kind: "python_module_missing".into(),
                title: format!("Python module \"{module}\" is not installed."),
                score: if interp.is_some() { 0.8 } else { 0.6 },
                support: interp.map(|i| vec![i.id]).unwrap_or_default(),
                against: Vec::new(),
                observed,
                inference: Some(
                    "The distribution name may differ from the module name (e.g. yaml → PyYAML)."
                        .into(),
                ),
                suggestion: Some(Suggestion {
                    kind: SuggestionKind::NextStep,
                    text: format!("Install the package that provides \"{module}\""),
                    command: Some(format!("pip install {module}")),
                }),
            });
        }
        out
    }
}

fn version_of(exe: &str) -> Option<String> {
    let v = tracewhy_core::probe_version(exe)?;
    Some(v.strip_prefix("Python ").unwrap_or(&v).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_parsing() {
        assert_eq!(
            missing_modules("ModuleNotFoundError: No module named 'requests'\n"),
            vec!["requests"]
        );
        assert_eq!(
            missing_modules("No module named 'google.protobuf'"),
            vec!["google"]
        );
        assert!(missing_modules("all good").is_empty());
        assert!(is_python("/usr/bin/python3.12"));
        assert!(is_python("/x/.venv/bin/python"));
        assert!(!is_python("/usr/bin/python3-config"));
    }
}
