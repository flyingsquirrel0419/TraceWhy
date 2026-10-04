//! open()/creat() and write() family handling.

use super::paths::access_from_flags;
use super::util::{is_console_like, looks_textual};
use super::Normalizer;
use crate::args::{all_strings, parse_fd, parse_string};
use crate::parse::{RawRecord, Syscall};
use tracewhy_event::{Errno, EventKind, OutputStream};

impl Normalizer {
    pub(super) fn open_like(
        &mut self,
        rec: &RawRecord,
        pid: u32,
        sc: &Syscall,
        args: &[&str],
        err: Option<Errno>,
    ) {
        let name = sc.name.as_str();
        let (dirfd, pi, fi) = match name {
            "openat" | "openat2" => (args.first().copied(), 1, 2),
            _ => (None, 0, 1),
        };
        if let Some(d) = dirfd {
            self.note_cwd_from(pid, d);
        }
        let Some(given) = args.get(pi).and_then(|a| parse_string(a)) else {
            return;
        };
        let flags = if name == "creat" {
            "O_WRONLY|O_CREAT"
        } else {
            args.get(fi).copied().unwrap_or("")
        };
        let access = access_from_flags(flags);
        let resolved = self.resolve_path(pid, dirfd, &given);
        let requested = (given != resolved).then(|| given.clone());
        match err {
            None => {
                let path = sc
                    .ret
                    .annotation
                    .clone()
                    .filter(|a| a.starts_with('/'))
                    .unwrap_or(resolved);
                self.push(
                    rec,
                    EventKind::FileOpened {
                        path,
                        requested,
                        access,
                    },
                );
            }
            Some(error) => self.push(
                rec,
                EventKind::FileOpenFailed {
                    path: resolved,
                    requested,
                    access,
                    error,
                },
            ),
        }
    }

    pub(super) fn write_like(
        &mut self,
        rec: &RawRecord,
        pid: u32,
        sc: &Syscall,
        args: &[&str],
        err: Option<Errno>,
    ) {
        let fdarg = args.first().and_then(|a| parse_fd(a));
        if self.is_dns_fd(pid, fdarg.as_ref()) {
            self.maybe_dns(rec, pid, sc, args);
            return;
        }
        match err {
            None => {
                let stream = match fdarg.as_ref().and_then(|f| f.fd) {
                    Some(1) => Some(OutputStream::Stdout),
                    Some(2) => Some(OutputStream::Stderr),
                    _ => None,
                }
                .filter(|_| is_console_like(fdarg.as_ref().and_then(|f| f.annotation.as_deref())));
                if let Some(stream) = stream {
                    let rest = args.get(1).copied().unwrap_or("");
                    let text: Vec<u8> = all_strings(rest).concat();
                    if !text.is_empty() && looks_textual(&text) {
                        self.push(
                            rec,
                            EventKind::Output {
                                stream,
                                text: String::from_utf8_lossy(&text).into_owned(),
                            },
                        );
                    }
                }
            }
            Some(error) => {
                if matches!(
                    error.as_str(),
                    "EAGAIN" | "EINTR" | "EWOULDBLOCK" | "ERESTARTSYS"
                ) {
                    return;
                }
                let target = fdarg.and_then(|f| f.annotation);
                self.push(rec, EventKind::WriteFailed { target, error });
            }
        }
    }
}
