//! Filesystem hypotheses: missing paths, permissions, full disks, fd limits.

use super::{parent_dir, shell_quote, Ctx, Eval};
use tracewhy_core::{human_bytes, Fact, FactKind, InvestigationTarget, ObservationKind};
use tracewhy_event::FileAccess;

pub fn evaluate(kind: &str, ctx: &Ctx<'_>) -> Option<Eval> {
    match &ctx.obs.kind {
        ObservationKind::FileAccessFailed {
            path,
            op,
            access,
            error,
            ..
        } => file(kind, ctx, path, op, *access, error.as_str()),
        ObservationKind::WriteFailed { target, error } => {
            write(kind, ctx, target.as_deref(), error.as_str())
        }
        ObservationKind::ResourceLimit { error, .. } => fds(kind, ctx, error.as_str()),
        _ => None,
    }
}

pub(super) struct PathView<'a> {
    pub fact: &'a Fact,
    pub exists: bool,
    pub broken: bool,
    pub file_type: Option<&'a str>,
    pub mode: Option<u32>,
    pub owner: Option<&'a str>,
    pub read: bool,
    pub write: bool,
    pub target: Option<&'a str>,
    pub checked_as: Option<&'a str>,
}

pub(super) fn view<'a>(ctx: &'a Ctx<'_>, path: &str) -> Option<PathView<'a>> {
    let fact = ctx.facts.path(path)?;
    match &fact.kind {
        FactKind::PathStatus {
            exists,
            broken_symlink,
            file_type,
            mode,
            owner,
            access,
            symlink_target,
            checked_as,
            ..
        } => Some(PathView {
            fact,
            exists: *exists,
            broken: *broken_symlink,
            file_type: file_type.as_deref(),
            mode: *mode,
            owner: owner.as_deref(),
            read: access.read,
            write: access.write,
            target: symlink_target.as_deref(),
            checked_as: checked_as.as_deref(),
        }),
        _ => None,
    }
}

fn verb(op: &str, access: Option<FileAccess>) -> &'static str {
    match (op, access) {
        ("open", Some(FileAccess::Write)) => "write",
        ("open", Some(FileAccess::ReadWrite)) => "open for writing",
        ("open", Some(FileAccess::Directory)) => "open directory",
        ("open", _) => "read",
        ("mkdir", _) => "create directory",
        ("unlink" | "rmdir", _) => "delete",
        ("rename", _) => "rename",
        ("chmod", _) => "chmod",
        ("chown", _) => "chown",
        ("stat" | "access", _) => "access",
        ("chdir", _) => "enter directory",
        _ => "access",
    }
}

fn creates(op: &str, access: Option<FileAccess>) -> bool {
    matches!(
        op,
        "mkdir" | "symlink" | "link" | "mknod" | "rename" | "unlink" | "rmdir"
    ) || (op == "open"
        && matches!(
            access,
            Some(FileAccess::Write) | Some(FileAccess::ReadWrite)
        ))
}

fn file(
    kind: &str,
    ctx: &Ctx<'_>,
    path: &str,
    op: &str,
    access: Option<FileAccess>,
    err: &str,
) -> Option<Eval> {
    let pv = view(ctx, path);
    let parent = parent_dir(path);
    let want_path = || InvestigationTarget::Path {
        path: path.to_string(),
    };
    let v = verb(op, access);
    match (kind, err) {
        ("broken_symlink", "ENOENT") => {
            let p = pv?;
            if !p.broken {
                return None;
            }
            Some(
                Eval::new(format!("{path} is a broken symbolic link (→ {}).", p.target.unwrap_or("?")))
                    .fact(p.fact.id, ctx)
                    .step("broken symlink", Some(p.fact.id))
                    .supported(0.92)
                    .fix(format!("Point {path} at an existing target, or recreate the missing target"), None),
            )
        }
        ("parent_missing", "ENOENT") => {
            let p = pv?;
            if p.exists || p.broken {
                return None;
            }
            let anc = ctx.facts.by_key("nearest_existing_ancestor", path)?;
            let FactKind::NearestExistingAncestor { ancestor, .. } = &anc.kind else { return None };
            if *ancestor == parent {
                return Some(Eval::new("parent exists").refuted(anc.id));
            }
            let missing = first_missing_below(path, ancestor);
            let e = Eval::new(format!("Directory {missing} does not exist, so {path} cannot be reached."))
                .fact(p.fact.id, ctx)
                .fact(anc.id, ctx)
                .step(format!("{missing} missing"), Some(anc.id))
                .supported(if ctx.obs.relevance.reported_on_stderr { 0.88 } else { 0.75 });
            // Only creating something is fixed by creating the directory.
            Some(if creates(op, access) {
                e.fix(format!("Create the directory {parent}"), Some(format!("mkdir -p {}", shell_quote(&parent))))
            } else {
                e.next(format!("Check the path {path}: the directory {missing} does not exist"), None)
            })
        }
        ("file_missing", "ENOENT") => {
            let Some(p) = pv else {
                return Some(Eval::new(format!("{path} does not exist.")).unresolved(0.4, &format!("Does {path} exist now?"), Some(want_path())));
            };
            if p.exists {
                return Some(Eval::new("missing").refuted(p.fact.id));
            }
            if p.broken {
                return None;
            }
            if let Some(anc) = ctx.facts.by_key("nearest_existing_ancestor", path) {
                if let FactKind::NearestExistingAncestor { ancestor, .. } = &anc.kind {
                    if *ancestor != parent {
                        return None;
                    }
                }
            }
            let reported = ctx.obs.relevance.reported_on_stderr;
            let title = if creates(op, access) {
                format!("{path} could not be created.")
            } else if reported {
                {
                let noun = if matches!(op, "open") && !matches!(access, Some(FileAccess::Directory) | Some(FileAccess::Path)) { "file" } else { "path" };
                format!("Required {noun} {path} does not exist.")
            }
            } else {
                format!("{path} does not exist.")
            };
            let mut e = Eval::new(title)
                .fact(p.fact.id, ctx)
                .step("file does not exist", Some(p.fact.id))
                .supported(if reported { 0.88 } else { 0.6 });
            if reported {
                e = e.infer("The program reported this missing file right before failing, so it treats the file as required.");
            } else {
                e = e.infer("The program failed after this file was not found; it may be required.");
            }
            if let Some(req) = ctx_requested(ctx) {
                if !req.starts_with('/') {
                    e = e.infer(format!(
                        "The path was given relative (\"{req}\") and resolved against the working directory {}.",
                        parent_dir(path)
                    ));
                }
            }
            Some(e.next(format!("Create {path}, or point the program at the correct location"), None))
        }
        ("path_exists_now", "ENOENT") => {
            let p = pv?;
            if !p.exists {
                return None;
            }
            Some(
                Eval::new(format!("{path} exists now, but did not when the program tried to {v} it."))
                    .fact(p.fact.id, ctx)
                    .inferred_step("created after the failure")
                    .infer("Something created the file after the failure (a race with another process), or it was created since.")
                    .supported(0.35)
                    .next("Re-run the command; if it now succeeds, the failure was a race", None),
            )
        }
        ("ancestor_not_searchable", "EACCES") => {
            let f = ctx.facts.by_key("ancestor_not_searchable", path)?;
            let FactKind::AncestorNotSearchable { ancestor, .. } = &f.kind else { return None };
            Some(
                Eval::new(format!("The current user cannot enter directory {ancestor}, so {path} is unreachable."))
                    .fact(f.id, ctx)
                    .step(format!("{ancestor} not searchable"), Some(f.id))
                    .supported(0.9)
                    .fix(format!("Grant execute (search) permission on {ancestor}"), Some(format!("chmod o+x {}", shell_quote(ancestor)))),
            )
        }
        ("permission_denied", "EACCES") => {
            // For creations the parent directory's write permission matters.
            let (subject, need_write) = if creates(op, access) && pv.as_ref().map(|p| !p.exists).unwrap_or(true) {
                (parent.clone(), true)
            } else {
                (
                    path.to_string(),
                    matches!(access, Some(FileAccess::Write) | Some(FileAccess::ReadWrite)) || creates(op, access),
                )
            };
            let Some(sv) = view(ctx, &subject) else {
                return Some(Eval::new(format!("Permission denied on {path}.")).unresolved(
                    0.5,
                    &format!("Who owns {subject} and what is its mode?"),
                    Some(InvestigationTarget::Path { path: subject.clone() }),
                ));
            };
            let need_read = !need_write && !matches!(op, "stat" | "access");
            let denied = (need_write && !sv.write) || (need_read && !sv.read);
            if !sv.exists {
                return None;
            }
            if !denied {
                return Some(Eval::new("permissions allow").refuted(sv.fact.id));
            }
            let mode = sv.mode.map(|m| format!("{:o}", m & 0o7777)).unwrap_or_else(|| "?".into());
            let owner = sv.owner.unwrap_or("another user");
            let action = if need_write { "write to" } else { "read" };
            let user = sv.checked_as.map(String::from).unwrap_or_else(|| "the current user".into());
            let user_name = user.split(" (").next().unwrap_or(&user).to_string();
            let mut e = Eval::new(format!("The current user ({user_name}) cannot {action} {subject} (mode {mode}, owner {owner})."))
                .fact(sv.fact.id, ctx)
                .step(format!("mode {mode}, owner {owner}"), Some(sv.fact.id))
                .supported(0.92);
            if subject != path {
                e = e.infer(format!("Creating {path} requires write permission on its directory {subject}."));
            }
            let own = sv.owner.map(|o| o == user_name).unwrap_or(false);
            let bit = if need_write { "w" } else { "r" };
            let text = if own {
                format!("Restore your own {action} permission (chmod u+{bit})")
            } else {
                format!("Run as {owner}, or give {user_name} access (e.g. via the file's group and chmod g+{bit})")
            };
            Some(e.next(text, Some(format!("ls -ld {}", shell_quote(&subject)))))
        }
        ("operation_not_permitted", "EPERM") => Some(
            Eval::new(format!("The kernel refused to {v} {path} (EPERM): immutable attribute, ownership rules, or missing capability."))
                .supported(0.55)
                .next(format!("Check `lsattr {}` and the process' privileges", shell_quote(path)), None),
        ),
        ("read_only_filesystem", "EROFS") => {
            let fsf = fs_fact(ctx, path);
            let mut e = Eval::new(format!("{path} is on a read-only filesystem."));
            if let Some(f) = fsf {
                if let FactKind::Filesystem { mount_point, read_only, .. } = &f.kind {
                    let mp = mount_point.clone().unwrap_or_else(|| path.to_string());
                    if *read_only {
                        e = Eval::new(format!("{path} is on a read-only filesystem ({mp})."))
                            .fact(f.id, ctx)
                            .step(format!("{mp} mounted read-only"), Some(f.id));
                        return Some(e.supported(0.95).next("Write to a writable location, or remount the filesystem read-write", None));
                    }
                }
            }
            Some(e.supported(0.75).next("Write to a writable location, or remount the filesystem read-write", None))
        }
        ("bad_path", "ENOTDIR" | "ELOOP" | "EISDIR" | "ENAMETOOLONG") => {
            let title = match err {
                "ENOTDIR" => format!("A component of {path} is a file, not a directory."),
                "ELOOP" => format!("{path} contains a symbolic-link loop."),
                "EISDIR" => format!("{path} is a directory, but the program expected a file."),
                _ => format!("{path} is too long."),
            };
            let mut e = Eval::new(title);
            if let Some(p) = pv {
                e = e.fact(p.fact.id, ctx);
            }
            Some(e.supported(0.7).next(format!("Fix the path {path}"), None))
        }
        _ => None,
    }
}

fn ctx_requested(ctx: &Ctx<'_>) -> Option<String> {
    match &ctx.obs.kind {
        ObservationKind::FileAccessFailed { requested, .. } => requested.clone(),
        _ => None,
    }
}

fn first_missing_below(path: &str, ancestor: &str) -> String {
    let rest = path
        .strip_prefix(ancestor)
        .unwrap_or(path)
        .trim_start_matches('/');
    let first = rest.split('/').next().unwrap_or(rest);
    if ancestor.ends_with('/') {
        format!("{ancestor}{first}")
    } else {
        format!("{ancestor}/{first}")
    }
}

/// The filesystem fact covering `path` (longest matching investigated path).
fn fs_fact<'a>(ctx: &'a Ctx<'_>, path: &str) -> Option<&'a Fact> {
    ctx.facts
        .of_type("filesystem")
        .into_iter()
        .filter(|f| match &f.kind {
            FactKind::Filesystem {
                path: p,
                mount_point,
                ..
            } => {
                p == path
                    || path.starts_with(p.as_str())
                    || mount_point
                        .as_deref()
                        .map(|m| path.starts_with(m))
                        .unwrap_or(false)
            }
            _ => false,
        })
        .max_by_key(|f| match &f.kind {
            FactKind::Filesystem { path: p, .. } => p.len(),
            _ => 0,
        })
}

/// Out of space: at most 2% free, or (small filesystems) under 4 MiB and 25%.
fn nearly_full(avail: u64, total: u64) -> bool {
    avail.saturating_mul(50) <= total || (avail < (4 << 20) && avail.saturating_mul(4) <= total)
}

pub(super) fn write_target_dir(ctx: &Ctx<'_>, target: Option<&str>) -> String {
    match target {
        Some(t) if t.starts_with('/') => t.to_string(),
        _ => ctx.cwd.to_string_lossy().into_owned(),
    }
}

fn write(kind: &str, ctx: &Ctx<'_>, target: Option<&str>, err: &str) -> Option<Eval> {
    let at = write_target_dir(ctx, target);
    let fsf = fs_fact(ctx, &at);
    let what = target.filter(|t| t.starts_with('/')).unwrap_or("a file");
    let fs = fsf.and_then(|f| match &f.kind {
        FactKind::Filesystem {
            mount_point,
            avail_bytes,
            total_bytes,
            free_inodes,
            total_inodes,
            ..
        } => Some((
            f.id,
            mount_point.clone().unwrap_or_else(|| at.clone()),
            *avail_bytes,
            *total_bytes,
            *free_inodes,
            *total_inodes,
        )),
        _ => None,
    });
    let q = || InvestigationTarget::Filesystem { path: at.clone() };
    match (kind, err) {
        ("inodes_exhausted", "ENOSPC") => {
            let (id, mp, _, _, free_i, total_i) = fs?;
            if total_i == 0 || free_i > 0 {
                return None;
            }
            Some(
                Eval::new(format!("Filesystem {mp} has no free inodes (too many files), so writing {what} failed."))
                    .fact(id, ctx)
                    .step(format!("{mp}: 0 free inodes"), Some(id))
                    .supported(0.93)
                    .next(format!("Delete unneeded small files on {mp} (e.g. caches, temp files)"), Some(format!("df -i {}", shell_quote(&mp)))),
            )
        }
        ("disk_full", "ENOSPC") => {
            let Some((id, mp, avail, total, free_i, total_i)) = fs else {
                return Some(
                    Eval::new(format!("The disk holding {what} is full.")).unresolved(
                        0.5,
                        "How much space is free?",
                        Some(q()),
                    ),
                );
            };
            // No free inodes is a different cause (inodes_exhausted).
            if !nearly_full(avail, total) || (total_i > 0 && free_i == 0) {
                return None;
            }
            Some(
                Eval::new(format!(
                    "The disk is full: filesystem {mp} has {} free, so writing {what} failed.",
                    human_bytes(avail)
                ))
                .fact(id, ctx)
                .step(format!("{mp} full ({} free)", human_bytes(avail)), Some(id))
                .supported(0.93)
                .next(
                    format!("Free up space on {mp}"),
                    Some(format!("df -h {}", shell_quote(&mp))),
                ),
            )
        }
        ("disk_was_full", "ENOSPC") => {
            let (id, mp, avail, total, free_i, _) = fs?;
            if nearly_full(avail, total) || free_i == 0 {
                return None;
            }
            Some(
                Eval::new(format!("Filesystem {mp} ran out of space while writing {what} (it has {} free now).", human_bytes(avail)))
                    .fact(id, ctx)
                    .inferred_step("space freed after the failure")
                    .infer("The kernel reported ENOSPC at the time of the write; space was freed afterwards (possibly by the failing program cleaning up).")
                    .supported(0.6)
                    .next(format!("Check how much the program writes versus free space on {mp}"), None),
            )
        }
        ("quota_exceeded", "EDQUOT") => Some(
            Eval::new(format!(
                "The user's disk quota was exceeded while writing {what}."
            ))
            .supported(0.85)
            .next("Check quota usage (`quota -s`) and free space", None),
        ),
        ("write_device_error", "EIO" | "EFBIG" | "EROFS") => Some(
            Eval::new(match err {
                "EIO" => format!("The device reported an I/O error while writing {what}."),
                "EFBIG" => format!(
                    "{what} exceeded the maximum file size (RLIMIT_FSIZE or filesystem limit)."
                ),
                _ => format!("{what} is on a read-only filesystem."),
            })
            .supported(0.6)
            .next(
                "Check `dmesg` for device errors and filesystem limits",
                None,
            ),
        ),
        _ => None,
    }
}

fn fds(kind: &str, ctx: &Ctx<'_>, err: &str) -> Option<Eval> {
    match (kind, err) {
        ("fd_limit_reached", "EMFILE") => {
            let mut e = Eval::new("The process ran out of file descriptors (too many open files).");
            if let Some(f) = ctx.facts.first_of("fd_limit") {
                if let FactKind::FdLimit { soft, hard } = &f.kind {
                    e = Eval::new("The process ran out of file descriptors (too many open files).")
                        .infer(format!(
                            "The open-file limit inherited from this shell is {soft}; the program or a wrapper may set a lower one."
                        ))
                    .fact(f.id, ctx)
                    .step(format!("RLIMIT_NOFILE = {soft}"), Some(f.id));
                    let bigger = (*soft * 4).min(*hard).max(*soft);
                    return Some(e.supported(0.88).next(
                        "Raise the limit for this shell, or fix a descriptor leak in the program",
                        Some(format!("ulimit -n {bigger}")),
                    ));
                }
            }
            Some(e.unresolved(
                0.6,
                "What is the open-file limit?",
                Some(InvestigationTarget::FdLimit),
            ))
        }
        ("system_fd_table_full", "ENFILE") => Some(
            Eval::new("The system-wide open-file table is full (ENFILE).")
                .supported(0.8)
                .next(
                    "Check fs.file-max and processes holding many descriptors",
                    Some("cat /proc/sys/fs/file-nr".into()),
                ),
        ),
        _ => None,
    }
}
