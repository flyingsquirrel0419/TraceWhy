//! Running the docker CLI with a hard timeout.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub fn find_docker() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join("docker"))
        .find(|p| p.is_file())
}

fn spawn_and_wait(
    docker: &Path,
    args: &[&str],
    timeout: Duration,
    merge: bool,
) -> Result<String, String> {
    let mut cmd = Command::new(docker);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("DOCKER_CLI_HINTS", "false");
    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    // Drain pipes on threads so a chatty command cannot block on a full pipe.
    let out_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(o) = stdout.as_mut() {
            let _ = o.take(8 << 20).read_to_end(&mut s);
        }
        s
    });
    let err_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(e) = stderr.as_mut() {
            let _ = e.take(1 << 20).read_to_end(&mut s);
        }
        s
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("docker {} timed out", args.first().unwrap_or(&"")));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(e) => return Err(e.to_string()),
        }
    };
    let out = String::from_utf8_lossy(&out_t.join().unwrap_or_default()).into_owned();
    let err = String::from_utf8_lossy(&err_t.join().unwrap_or_default()).into_owned();
    if !status.success() {
        let first = err
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("")
            .trim()
            .to_string();
        return Err(if first.is_empty() {
            format!("docker exited with {status}")
        } else {
            first
        });
    }
    Ok(if merge { format!("{out}{err}") } else { out })
}

pub fn run(docker: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    spawn_and_wait(docker, args, timeout, false)
}

/// Like [`run`], but returns stdout followed by stderr (container logs use both).
pub fn run_merged(docker: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    spawn_and_wait(docker, args, timeout, true)
}
