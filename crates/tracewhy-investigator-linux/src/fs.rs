//! Filesystem capacity and mount flags.

use crate::sys;
use std::path::Path;
use tracewhy_core::{FactKind, InvestigationError};

/// Facts about the filesystem holding `path` (or its nearest existing ancestor).
pub fn filesystem(path: &str) -> Result<FactKind, InvestigationError> {
    let mut probe = Path::new(path).to_path_buf();
    while std::fs::symlink_metadata(&probe).is_err() {
        match probe.parent() {
            Some(p) if !p.as_os_str().is_empty() => probe = p.to_path_buf(),
            _ => break,
        }
    }
    let probe_s = probe.to_string_lossy().into_owned();
    let vfs = sys::statvfs(&probe_s)
        .ok_or_else(|| InvestigationError::Failed(format!("statvfs({probe_s}) failed")))?;
    let canon = std::fs::canonicalize(&probe)
        .unwrap_or(probe)
        .to_string_lossy()
        .into_owned();
    let mount = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .and_then(|t| mount_for(&t, &canon));
    Ok(FactKind::Filesystem {
        path: path.to_string(),
        mount_point: mount.as_ref().map(|m| m.0.clone()),
        fs_type: mount.map(|m| m.1),
        read_only: vfs.read_only,
        noexec: vfs.noexec,
        total_bytes: vfs.total_bytes,
        avail_bytes: vfs.avail_bytes,
        total_inodes: vfs.total_inodes,
        free_inodes: vfs.free_inodes,
    })
}

fn unescape_mount(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// Longest mount point that is a prefix of `path`: (mount point, fs type).
pub fn mount_for(mountinfo: &str, path: &str) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for line in mountinfo.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let Some(mp) = left.split_whitespace().nth(4) else {
            continue;
        };
        let mp = unescape_mount(mp);
        let fstype = right.split_whitespace().next().unwrap_or("").to_string();
        let covers = mp == "/" || path == mp || path.starts_with(&format!("{mp}/"));
        if covers && best.as_ref().map(|b| mp.len() >= b.0.len()).unwrap_or(true) {
            best = Some((mp, fstype));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_longest_mount() {
        let mi = "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n30 22 0:5 / /data rw - xfs /dev/sdb rw\n31 22 0:6 / /data2 rw - tmpfs t rw\n32 22 0:7 / /my\\040disk rw - vfat x rw\n";
        assert_eq!(
            mount_for(mi, "/data/x/y"),
            Some(("/data".into(), "xfs".into()))
        );
        assert_eq!(
            mount_for(mi, "/data2"),
            Some(("/data2".into(), "tmpfs".into()))
        );
        assert_eq!(mount_for(mi, "/datax"), Some(("/".into(), "ext4".into())));
        assert_eq!(
            mount_for(mi, "/my disk/f"),
            Some(("/my disk".into(), "vfat".into()))
        );
    }

    #[test]
    fn real_filesystem() {
        let f = filesystem("/tmp/does/not/exist/file").unwrap();
        assert!(matches!(f, FactKind::Filesystem { total_bytes, .. } if total_bytes > 0));
    }
}
