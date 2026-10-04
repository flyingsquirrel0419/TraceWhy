//! Path status, ancestor checks, PATH search and script interpreters.

use crate::sys;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use tracewhy_core::{AccessCheck, EnvSnapshot, ExecCandidate, FactKind};

fn file_type(m: &std::fs::Metadata) -> &'static str {
    let t = m.file_type();
    if t.is_dir() {
        "directory"
    } else if t.is_symlink() {
        "symlink"
    } else if t.is_file() {
        "file"
    } else {
        use std::os::unix::fs::FileTypeExt;
        if t.is_socket() {
            "socket"
        } else if t.is_fifo() {
            "fifo"
        } else if t.is_char_device() || t.is_block_device() {
            "device"
        } else {
            "other"
        }
    }
}

/// `PathStatus` for one path (without following into ancestors).
pub fn path_status(path: &str) -> FactKind {
    let lmeta = std::fs::symlink_metadata(path);
    let Ok(lm) = lmeta else {
        return FactKind::PathStatus {
            path: path.to_string(),
            exists: false,
            file_type: None,
            mode: None,
            uid: None,
            gid: None,
            owner: None,
            symlink_target: None,
            broken_symlink: false,
            access: AccessCheck::default(),
            checked_as: Some(sys::current_user()),
        };
    };
    let is_link = lm.file_type().is_symlink();
    let target = if is_link {
        std::fs::read_link(path)
            .ok()
            .map(|t| t.to_string_lossy().into_owned())
    } else {
        None
    };
    let followed = std::fs::metadata(path);
    let broken = is_link && followed.is_err();
    let m = followed.as_ref().unwrap_or(&lm);
    FactKind::PathStatus {
        path: path.to_string(),
        exists: !broken,
        file_type: Some(file_type(m).to_string()),
        mode: Some(m.permissions().mode()),
        uid: Some(m.uid()),
        gid: Some(m.gid()),
        owner: sys::user_name(m.uid()),
        symlink_target: target,
        broken_symlink: broken,
        access: AccessCheck {
            read: sys::access(path, libc::R_OK),
            write: sys::access(path, libc::W_OK),
            execute: sys::access(path, libc::X_OK),
        },
        checked_as: Some(sys::current_user()),
    }
}

fn parent(p: &str) -> Option<String> {
    let parent = Path::new(p).parent()?.to_string_lossy().into_owned();
    if parent.is_empty() {
        None
    } else {
        Some(parent)
    }
}

/// Status of `path`, its parent, nearest existing ancestor, unsearchable
/// ancestors and (for scripts) the `#!` interpreter.
pub fn investigate_path(path: &str, env: &EnvSnapshot) -> Vec<FactKind> {
    let mut out = vec![path_status(path)];
    let exists = std::fs::symlink_metadata(path).is_ok();
    if let Some(par) = parent(path) {
        out.push(path_status(&par));
    }
    if !exists {
        let mut cur = parent(path);
        while let Some(c) = cur {
            if std::fs::symlink_metadata(&c).is_ok() {
                out.push(FactKind::NearestExistingAncestor {
                    path: path.to_string(),
                    ancestor: c,
                });
                break;
            }
            cur = parent(&c);
        }
    }
    // The first ancestor directory the current user cannot traverse.
    if path.starts_with('/') {
        let mut acc = String::new();
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for c in comps.iter().take(comps.len().saturating_sub(1)) {
            acc.push('/');
            acc.push_str(c);
            match std::fs::metadata(&acc) {
                Ok(m) if m.is_dir() => {
                    if !sys::access(&acc, libc::X_OK) {
                        out.push(FactKind::AncestorNotSearchable {
                            path: path.to_string(),
                            ancestor: acc.clone(),
                        });
                        break;
                    }
                }
                _ => break,
            }
        }
    }
    if let Some(f) = interpreter_fact(path, env) {
        out.push(f);
    }
    out
}

/// For a script starting with `#!`, which interpreter it needs and whether it exists.
pub fn interpreter_fact(path: &str, env: &EnvSnapshot) -> Option<FactKind> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = [0u8; 256];
    let n = f.read(&mut buf).ok()?;
    let head = buf.get(..n)?;
    let rest = head.strip_prefix(b"#!")?;
    let line_end = rest.iter().position(|b| *b == b'\n').unwrap_or(rest.len());
    let line = String::from_utf8_lossy(&rest[..line_end])
        .trim()
        .to_string();
    let mut parts = line.split_whitespace();
    let interp = parts.next()?.to_string();
    let (interpreter, exists) = if interp.ends_with("/env") {
        let prog = parts.find(|p| !p.starts_with('-'))?.to_string();
        let found = env
            .path_dirs()
            .iter()
            .any(|d| is_executable_file(&format!("{d}/{prog}")));
        (
            format!("{interp} {prog}"),
            std::fs::metadata(&interp).is_ok() && found,
        )
    } else {
        let exists = std::fs::metadata(&interp).is_ok();
        (interp, exists)
    };
    Some(FactKind::ScriptInterpreter {
        script: path.to_string(),
        interpreter,
        interpreter_exists: exists,
    })
}

fn is_executable_file(p: &str) -> bool {
    std::fs::metadata(p).map(|m| m.is_file()).unwrap_or(false) && sys::access(p, libc::X_OK)
}

/// Search PATH for `name`, plus common locations that are not on PATH.
pub fn search_executable(name: &str, env: &EnvSnapshot, cwd: &Path) -> Vec<FactKind> {
    let dirs = env.path_dirs();
    let mut candidates = Vec::new();
    let mut out = Vec::new();
    for d in &dirs {
        let base = if d.starts_with('/') {
            d.clone()
        } else {
            cwd.join(d).to_string_lossy().into_owned()
        };
        let p = format!("{}/{name}", base.trim_end_matches('/'));
        let Ok(lm) = std::fs::symlink_metadata(&p) else {
            continue;
        };
        let followed = std::fs::metadata(&p);
        let broken = lm.file_type().is_symlink() && followed.is_err();
        let is_dir = followed.as_ref().map(|m| m.is_dir()).unwrap_or(false);
        candidates.push(ExecCandidate {
            path: p.clone(),
            exists: !broken,
            executable: !broken && !is_dir && sys::access(&p, libc::X_OK),
            broken_symlink: broken,
            is_dir,
        });
        out.push(path_status(&p));
    }
    let home = env.get("HOME").unwrap_or("").to_string();
    let mut extra: Vec<String> = vec![
        cwd.join("node_modules/.bin").to_string_lossy().into_owned(),
        cwd.join(".venv/bin").to_string_lossy().into_owned(),
        cwd.join("venv/bin").to_string_lossy().into_owned(),
        cwd.join("bin").to_string_lossy().into_owned(),
        "/usr/local/bin".into(),
        "/usr/local/sbin".into(),
        "/usr/sbin".into(),
        "/sbin".into(),
        "/snap/bin".into(),
    ];
    if !home.is_empty() {
        for d in [
            ".local/bin",
            ".cargo/bin",
            "go/bin",
            ".npm-global/bin",
            ".bun/bin",
            ".deno/bin",
        ] {
            extra.push(format!("{home}/{d}"));
        }
    }
    if let Ok(rd) = std::fs::read_dir("/opt") {
        for e in rd.flatten().take(64) {
            extra.push(e.path().join("bin").to_string_lossy().into_owned());
        }
    }
    let elsewhere: Vec<String> = extra
        .into_iter()
        .filter(|d| !dirs.contains(d))
        .map(|d| format!("{d}/{name}"))
        .filter(|p| is_executable_file(p))
        .take(5)
        .collect();
    out.insert(
        0,
        FactKind::ExecutableSearch {
            name: name.to_string(),
            path_dirs: dirs,
            candidates,
            elsewhere,
        },
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env(path: &str) -> EnvSnapshot {
        let mut vars = BTreeMap::new();
        vars.insert("PATH".to_string(), path.to_string());
        EnvSnapshot { vars }
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tw-path-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn missing_file_reports_ancestor() {
        let d = tmpdir("anc");
        let p = d.join("a/b/c.txt").to_string_lossy().into_owned();
        let facts = investigate_path(&p, &env("/bin"));
        assert!(matches!(
            &facts[0],
            FactKind::PathStatus { exists: false, .. }
        ));
        assert!(facts.iter().any(|f| matches!(f, FactKind::NearestExistingAncestor { ancestor, .. } if *ancestor == d.to_string_lossy())));
    }

    #[test]
    fn broken_symlink_and_interpreter() {
        let d = tmpdir("link");
        let link = d.join("l");
        std::os::unix::fs::symlink(d.join("nope"), &link).unwrap();
        let f = path_status(&link.to_string_lossy());
        assert!(matches!(
            f,
            FactKind::PathStatus {
                broken_symlink: true,
                exists: false,
                ..
            }
        ));
        let script = d.join("s.sh");
        std::fs::write(&script, "#!/nonexistent/interp\necho hi\n").unwrap();
        let fact = interpreter_fact(&script.to_string_lossy(), &env("/bin")).unwrap();
        assert!(matches!(
            fact,
            FactKind::ScriptInterpreter {
                interpreter_exists: false,
                ..
            }
        ));
        std::fs::write(&script, "#!/usr/bin/env definitely-not-a-real-prog-xyz\n").unwrap();
        let fact = interpreter_fact(&script.to_string_lossy(), &env("/bin:/usr/bin")).unwrap();
        assert!(matches!(
            fact,
            FactKind::ScriptInterpreter {
                interpreter_exists: false,
                ..
            }
        ));
    }

    #[test]
    fn path_search_finds_non_executable() {
        let d = tmpdir("search");
        let p = d.join("tool");
        std::fs::write(&p, "x").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let facts = search_executable("tool", &env(&d.to_string_lossy()), &d);
        let FactKind::ExecutableSearch { candidates, .. } = &facts[0] else {
            panic!()
        };
        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].exists);
        // root may bypass permission bits; the mode is still reported.
        let facts = search_executable("nonexistent-xyz", &env(&d.to_string_lossy()), &d);
        let FactKind::ExecutableSearch { candidates, .. } = &facts[0] else {
            panic!()
        };
        assert!(candidates.is_empty());
    }
}
