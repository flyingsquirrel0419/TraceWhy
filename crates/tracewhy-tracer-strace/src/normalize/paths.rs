//! Path-based syscalls (stat, access, mkdir, unlink, ...) and path helpers.

use super::Normalizer;
use crate::args::{parse_fd, parse_string};
use crate::parse::{RawRecord, Syscall};
use tracewhy_event::{Errno, EventKind, FileAccess};

impl Normalizer {
    pub(super) fn path_op(
        &mut self,
        rec: &RawRecord,
        pid: u32,
        sc: &Syscall,
        args: &[&str],
        err: Option<Errno>,
    ) {
        let name = sc.name.as_str();
        let at_style = name.ends_with("at") || name.ends_with("at2") || name == "statx";
        let op = match name {
            "stat" | "lstat" | "stat64" | "lstat64" | "newfstatat" | "fstatat64" | "statx" => {
                "stat"
            }
            "access" | "faccessat" | "faccessat2" => "access",
            "readlink" | "readlinkat" => "readlink",
            "mkdir" | "mkdirat" => "mkdir",
            "unlink" | "unlinkat" => "unlink",
            "rmdir" => "rmdir",
            "rename" | "renameat" | "renameat2" => "rename",
            "link" | "linkat" => "link",
            "symlink" | "symlinkat" => "symlink",
            "chmod" | "fchmodat" | "fchmodat2" => "chmod",
            "chown" | "lchown" | "fchownat" => "chown",
            "truncate" => "truncate",
            "utimensat" | "utime" | "utimes" => "utime",
            "mknod" | "mknodat" => "mknod",
            "statfs" => "statfs",
            "chroot" => "chroot",
            "mount" => "mount",
            _ => {
                if let Some(error) = err.filter(|e| e.is_diagnostic()) {
                    let detail = args.iter().find_map(|a| parse_string(a));
                    self.push(
                        rec,
                        EventKind::SyscallFailed {
                            syscall: name.to_string(),
                            detail,
                            error,
                        },
                    );
                }
                return;
            }
        };
        if at_style {
            if let Some(d) = args.first() {
                self.note_cwd_from(pid, d);
            }
        }
        let Some(error) = err else { return };
        // Collect (dirfd, path) pairs in argument order.
        let mut paths: Vec<(Option<&str>, String)> = Vec::new();
        let mut last_dirfd: Option<&str> = None;
        for a in args {
            if a.starts_with('"') {
                if let Some(p) = parse_string(a) {
                    paths.push((last_dirfd, p));
                }
            } else if parse_fd(a).is_some() && at_style {
                last_dirfd = Some(a);
            }
        }
        let pick = if matches!(op, "rename" | "link" | "symlink") && !error.is("ENOENT") {
            paths.last()
        } else {
            paths.first()
        };
        let Some((dirfd, given)) = pick else { return };
        if given.is_empty() {
            return;
        }
        let path = self.resolve_path(pid, *dirfd, given);
        let requested = (*given != path).then(|| given.clone());
        self.push(
            rec,
            EventKind::PathOpFailed {
                op: op.to_string(),
                path,
                requested,
                error,
            },
        );
    }
}

pub(super) fn access_from_flags(flags: &str) -> FileAccess {
    if flags.contains("O_PATH") {
        FileAccess::Path
    } else if flags.contains("O_DIRECTORY") {
        FileAccess::Directory
    } else if flags.contains("O_RDWR") {
        FileAccess::ReadWrite
    } else if flags.contains("O_WRONLY") || flags.contains("O_CREAT") {
        FileAccess::Write
    } else {
        FileAccess::Read
    }
}

/// Resolve `.` and `..` components without touching the filesystem.
pub fn lexical_normalize(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for comp in path.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if parts.last().map(|p| *p != "..").unwrap_or(false) {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            c => parts.push(c),
        }
    }
    let joined = parts.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        ".".into()
    } else {
        joined
    }
}
