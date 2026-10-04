//! strace-based [`TraceBackend`] for Linux.

pub mod args;
pub mod dns;
pub mod normalize;
pub mod parse;

pub use normalize::{normalize_str, NormalizeLimits, NormalizedTrace, Normalizer};

use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracewhy_event::{
    BackendCapabilities, BackendError, BackendInfo, CommandSpec, Diagnostic, ExitStatus,
    ProcessTree, TraceBackend, TraceOutput,
};

/// Syscall classes traced by default. `%file,%network,%process` cover the
/// failure families; writes give stderr text and ENOSPC/EPIPE; `fchdir`
/// keeps working directories accurate; pipe/dup surface EMFILE.
pub const TRACE_SET: &str =
    "%file,%network,%process,write,writev,pwrite64,fchdir,pipe,pipe2,dup,dup2,dup3";

#[derive(Debug, Clone)]
pub struct StraceBackend {
    pub strace_path: PathBuf,
    pub string_limit: u32,
    pub limits: NormalizeLimits,
    pub max_raw_bytes: u64,
    /// Use `--seccomp-bpf` to reduce tracing overhead when supported.
    pub seccomp_bpf: bool,
    pub version: Option<String>,
}

impl StraceBackend {
    /// Locate strace and probe its version.
    pub fn detect() -> Result<Self, BackendError> {
        let path = find_in_path("strace").ok_or_else(|| {
            BackendError::Unsupported(
                "strace is not installed. Install it (e.g. `sudo apt install strace`, \
                 `sudo dnf install strace`) and run `why doctor`."
                    .into(),
            )
        })?;
        let version = strace_version(&path);
        let seccomp_bpf = version
            .as_deref()
            .and_then(parse_version)
            .map(|(maj, min)| (maj, min) >= (5, 3))
            .unwrap_or(false);
        Ok(StraceBackend {
            strace_path: path,
            string_limit: 512,
            limits: NormalizeLimits::default(),
            max_raw_bytes: 1 << 30,
            seccomp_bpf,
            version,
        })
    }

    fn build_command(&self, trace_file: &Path, spec: &CommandSpec) -> Command {
        let mut cmd = Command::new(&self.strace_path);
        cmd.arg("-f")
            .arg("-yy")
            .arg("-ttt")
            .arg("-s")
            .arg(self.string_limit.to_string())
            .arg("-e")
            .arg(format!("trace={TRACE_SET}"))
            .arg("-o")
            .arg(trace_file);
        if self.seccomp_bpf {
            cmd.arg("--seccomp-bpf");
        }
        cmd.arg("--").arg(&spec.program).args(&spec.args);
        cmd.current_dir(&spec.cwd);
        cmd.stdin(Stdio::inherit()).stderr(Stdio::inherit());
        let redirected = spec
            .stdout_to_stderr
            .then(|| {
                use std::os::fd::AsFd;
                std::io::stderr().as_fd().try_clone_to_owned().ok()
            })
            .flatten();
        match redirected {
            Some(fd) => cmd.stdout(Stdio::from(fd)),
            None => cmd.stdout(Stdio::inherit()),
        };
        cmd
    }

    /// Parse an existing strace output file (used by tests and `why` internals).
    pub fn parse_file(
        &self,
        path: &Path,
        initial_cwd: Option<&str>,
    ) -> Result<NormalizedTrace, BackendError> {
        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file.take(self.max_raw_bytes));
        let mut normalizer = Normalizer::new(self.limits.clone());
        let mut buf = Vec::with_capacity(1024);
        let mut line_no = 0u64;
        let mut first = true;
        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            line_no += 1;
            let line = String::from_utf8_lossy(&buf);
            if first {
                first = false;
                if let (Some(cwd), Some(pid)) = (initial_cwd, leading_pid(&line)) {
                    normalizer.set_initial_cwd(pid, cwd);
                }
            }
            normalizer.feed_line(line_no, &line);
        }
        let mut out = normalizer.finish();
        if out.stats.raw_bytes >= self.max_raw_bytes {
            out.stats.truncated = true;
            out.diagnostics.push(Diagnostic {
                line: None,
                message: format!(
                    "raw trace exceeded {} bytes; the remainder was not analyzed",
                    self.max_raw_bytes
                ),
            });
        }
        Ok(out)
    }
}

fn leading_pid(line: &str) -> Option<u32> {
    line.split_whitespace().next()?.parse().ok()
}

impl TraceBackend for StraceBackend {
    fn info(&self) -> BackendInfo {
        BackendInfo {
            name: "strace".into(),
            version: self.version.clone(),
            capabilities: BackendCapabilities {
                processes: true,
                files: true,
                network: true,
                dns_payloads: true,
                output_capture: true,
                timestamps: true,
            },
        }
    }

    fn run(&self, spec: &CommandSpec) -> Result<TraceOutput, BackendError> {
        let dir = TempDir::create()?;
        let trace_file = dir.path.join("trace.strace");
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let start = Instant::now();
        let mut child = self
            .build_command(&trace_file, spec)
            .spawn()
            .map_err(|e| BackendError::Failed(format!("failed to start strace: {e}")))?;
        let status = child.wait()?;
        let duration_ms = start.elapsed().as_millis() as u64;

        if !trace_file.exists() || std::fs::metadata(&trace_file).map(|m| m.len()).unwrap_or(0) == 0
        {
            return Err(BackendError::Unsupported(format!(
                "strace produced no trace (exit status {status}). Process tracing may be \
                 blocked (ptrace restrictions, seccomp, or missing CAP_SYS_PTRACE in a \
                 container). Run `why doctor` for details."
            )));
        }
        let cwd = spec.cwd.to_string_lossy().into_owned();
        let normalized = self.parse_file(&trace_file, Some(&cwd))?;
        let tree = ProcessTree::build(&normalized.events);
        let exit = tree
            .root_exit()
            .cloned()
            .or_else(|| exit_from_status(&status));
        Ok(TraceOutput {
            events: normalized.events,
            stats: normalized.stats,
            diagnostics: normalized.diagnostics,
            exit,
            started_at,
            duration_ms,
            backend: self.info(),
        })
    }
}

fn exit_from_status(status: &std::process::ExitStatus) -> Option<ExitStatus> {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        return Some(ExitStatus::Exited { code });
    }
    status.signal().map(|s| ExitStatus::Killed {
        signal: tracewhy_event::signal_name(s),
        core_dumped: status.core_dumped(),
    })
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, BackendError> {
        use std::os::unix::fs::DirBuilderExt;
        let base = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        for attempt in 0..16u32 {
            let path = base.join(format!(
                "tracewhy-{}-{nanos:x}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(BackendError::Failed(
            "could not create a private temporary directory".into(),
        ))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

pub fn find_in_path(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| {
            std::fs::metadata(p)
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
}

pub fn strace_version(path: &Path) -> Option<String> {
    let out = Command::new(path)
        .arg("-V")
        .stderr(Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next()?;
    first
        .split_whitespace()
        .find(|t| {
            t.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        })
        .map(|s| s.to_string())
}

fn parse_version(v: &str) -> Option<(u32, u32)> {
    let mut it = v.split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Check that strace can actually trace a trivial process here.
pub fn probe(strace: &Path) -> Result<(), String> {
    let out = Command::new(strace)
        .args(["-f", "-o", "/dev/null", "--", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parse() {
        assert_eq!(parse_version("6.8"), Some((6, 8)));
        assert_eq!(parse_version("5.3.1"), Some((5, 3)));
        assert_eq!(parse_version("x"), None);
    }

    fn backend() -> Option<StraceBackend> {
        let b = StraceBackend::detect().ok()?;
        probe(&b.strace_path).ok()?;
        Some(b)
    }

    #[test]
    fn traces_real_commands_and_exit_codes() {
        let Some(b) = backend() else {
            eprintln!("strace unavailable; skipping");
            return;
        };
        let cwd = std::env::temp_dir();
        for (cmd, args, want) in [
            ("true", vec![], ExitStatus::Exited { code: 0 }),
            ("false", vec![], ExitStatus::Exited { code: 1 }),
            ("sh", vec!["-c", "exit 7"], ExitStatus::Exited { code: 7 }),
            (
                "sh",
                vec!["-c", "kill -SEGV $$"],
                ExitStatus::Killed {
                    signal: "SIGSEGV".into(),
                    core_dumped: false,
                },
            ),
        ] {
            let spec = CommandSpec {
                program: cmd.into(),
                args: args.iter().map(|s| s.to_string()).collect(),
                cwd: cwd.clone(),
                stdout_to_stderr: false,
            };
            let out = b.run(&spec).unwrap();
            match (&out.exit, &want) {
                (Some(ExitStatus::Killed { signal, .. }), ExitStatus::Killed { signal: w, .. }) => {
                    assert_eq!(signal, w)
                }
                (got, want) => assert_eq!(got.as_ref(), Some(want), "{cmd} {args:?}"),
            }
            assert!(out.stats.semantic_events > 0);
        }
    }
}
