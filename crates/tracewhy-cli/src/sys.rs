//! Small OS helpers for the CLI.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub fn can_execute(p: &Path) -> bool {
    let Ok(c) = CString::new(p.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: valid NUL-terminated path for the duration of the call.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

pub fn isatty(fd: i32) -> bool {
    // SAFETY: isatty only inspects the descriptor.
    unsafe { libc::isatty(fd) == 1 }
}

extern "C" fn noop(_: libc::c_int) {}

/// While alive, SIGINT/SIGQUIT do not kill TraceWhy (the traced command still
/// receives them), so a Ctrl-C'd command still gets a report. A handler (not
/// SIG_IGN) is used so children get the default disposition after exec.
pub struct InterruptGuard {
    old: Vec<(libc::c_int, libc::sighandler_t)>,
}

pub fn ignore_interrupts() -> InterruptGuard {
    let mut old = Vec::new();
    for sig in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: installing an async-signal-safe no-op handler.
        let prev = unsafe {
            libc::signal(
                sig,
                noop as extern "C" fn(libc::c_int) as libc::sighandler_t,
            )
        };
        old.push((sig, prev));
    }
    InterruptGuard { old }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        for (sig, h) in &self.old {
            // SAFETY: restoring the handler that was previously installed.
            unsafe { libc::signal(*sig, *h) };
        }
    }
}
