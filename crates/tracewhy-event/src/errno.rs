use serde::{Deserialize, Serialize};

/// A symbolic errno name such as `ENOENT`.
///
/// Stored symbolically (not numerically) so traces stay portable across
/// architectures whose errno numbering differs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Errno(pub String);

impl Errno {
    pub fn new(name: impl Into<String>) -> Self {
        Errno(name.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is(&self, name: &str) -> bool {
        self.0 == name
    }

    /// Human readable description for common errno values.
    pub fn describe(&self) -> &'static str {
        match self.0.as_str() {
            "ENOENT" => "No such file or directory",
            "EACCES" => "Permission denied",
            "EPERM" => "Operation not permitted",
            "ECONNREFUSED" => "Connection refused",
            "EADDRINUSE" => "Address already in use",
            "EADDRNOTAVAIL" => "Cannot assign requested address",
            "ENOSPC" => "No space left on device",
            "EDQUOT" => "Disk quota exceeded",
            "EROFS" => "Read-only file system",
            "EMFILE" => "Too many open files",
            "ENFILE" => "Too many open files in system",
            "ENETUNREACH" => "Network is unreachable",
            "EHOSTUNREACH" => "No route to host",
            "ETIMEDOUT" => "Connection timed out",
            "ECONNRESET" => "Connection reset by peer",
            "EPIPE" => "Broken pipe",
            "ENOEXEC" => "Exec format error",
            "ENOTDIR" => "Not a directory",
            "EISDIR" => "Is a directory",
            "ELOOP" => "Too many levels of symbolic links",
            "ETXTBSY" => "Text file busy",
            "ENOMEM" => "Cannot allocate memory",
            "EEXIST" => "File exists",
            "EIO" => "Input/output error",
            "ENAMETOOLONG" => "File name too long",
            "EXDEV" => "Invalid cross-device link",
            "EBUSY" => "Device or resource busy",
            _ => "",
        }
    }

    /// Errnos that are interesting enough to keep even for syscalls TraceWhy
    /// does not model explicitly.
    pub fn is_diagnostic(&self) -> bool {
        matches!(
            self.0.as_str(),
            "EMFILE"
                | "ENFILE"
                | "ENOSPC"
                | "EDQUOT"
                | "EROFS"
                | "ENOMEM"
                | "EACCES"
                | "EPERM"
                | "ENETUNREACH"
                | "EHOSTUNREACH"
                | "EADDRNOTAVAIL"
                | "ETIMEDOUT"
                | "ECONNRESET"
                | "EPIPE"
                | "ENOEXEC"
                | "ETXTBSY"
                | "ELOOP"
                | "ENAMETOOLONG"
                | "EIO"
        )
    }
}

impl std::fmt::Display for Errno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
