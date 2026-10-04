//! Shared-library hypotheses.

use super::{shell_quote, Ctx, Eval};
use tracewhy_core::{FactKind, InvestigationTarget};

pub(super) fn library_eval(
    kind: &str,
    ctx: &Ctx<'_>,
    lib: &str,
    exe: Option<&str>,
) -> Option<Eval> {
    let f = ctx.facts.by_key("library_search", lib);
    let Some(f) = f else {
        if kind == "missing_shared_library" {
            return Some(
                Eval::new(format!("Shared library {lib} is missing.")).unresolved(
                    0.55,
                    &format!("Is {lib} anywhere on this system?"),
                    Some(InvestigationTarget::Library {
                        name: lib.to_string(),
                        executable: exe.map(String::from),
                    }),
                ),
            );
        }
        return None;
    };
    let FactKind::LibrarySearch {
        search_dirs,
        found,
        found_elsewhere,
        ..
    } = &f.kind
    else {
        return None;
    };
    let who = exe
        .map(|e| e.rsplit('/').next().unwrap_or(e))
        .unwrap_or("the program");
    match kind {
        "library_wrong_architecture" => {
            if found.iter().any(|c| c.compatible) {
                return Some(Eval::new("compatible found").refuted(f.id));
            }
            let c = found.first()?;
            Some(
                Eval::new(format!(
                    "{lib} is installed at {} but built for {}, not this architecture.",
                    c.path,
                    c.machine.as_deref().unwrap_or("another architecture")
                ))
                .fact(f.id, ctx)
                .step(format!("{} has wrong architecture", c.path), Some(f.id))
                .supported(0.9)
                .next(
                    format!("Install the {lib} build matching this system's architecture"),
                    None,
                ),
            )
        }
        "library_outside_search_path" => {
            if !found.is_empty() {
                return None;
            }
            let p = found_elsewhere.first()?;
            let dir = super::parent_dir(p);
            Some(
                Eval::new(format!("{who} needs {lib}; it exists at {p}, but the dynamic loader does not search {dir}."))
                    .fact(f.id, ctx)
                    .step(format!("found only in {dir}"), Some(f.id))
                    .supported(0.9)
                    .fix(format!("Add {dir} to the loader path"), Some(format!("export LD_LIBRARY_PATH={}${{LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}}", shell_quote(&dir)))),
            )
        }
        "missing_shared_library" => {
            if !found.is_empty() || !found_elsewhere.is_empty() {
                return Some(Eval::new("present").refuted(f.id));
            }
            Some(
                Eval::new(format!("Shared library {lib} is not installed (needed by {who})."))
                    .fact(f.id, ctx)
                    .step(format!("{lib} not found in {} loader directories", search_dirs.len()), Some(f.id))
                    .supported(0.93)
                    .next(format!("Install the package that provides {lib} (on Debian/Ubuntu, `apt-file search` finds it)"), Some(format!("apt-file search {}", shell_quote(lib)))),
            )
        }
        _ => None,
    }
}
