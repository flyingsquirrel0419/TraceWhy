//! The `.whytrace` format: a portable, versioned JSON record of one run —
//! semantic events, process tree, facts, investigations, hypotheses, the
//! cause graph and the conclusion.
//!
//! Compatibility policy: readers accept any file whose `format_version` is
//! less than or equal to [`FORMAT_VERSION`]; unknown object fields are
//! ignored (unknown enum variants are not, so adding one needs a new version) and
//! missing optional fields take defaults. A breaking change bumps the version.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use tracewhy_core::{Conclusion, Fact, Hypothesis, InvestigationRecord, Observation};
use tracewhy_event::{BackendInfo, Diagnostic, Event, ExitStatus, ProcessTree, TraceStats};
use tracewhy_graph::CauseGraph;
use tracewhy_redact::{RedactionInfo, Redactor};

pub const FORMAT_NAME: &str = "whytrace";
pub const FORMAT_VERSION: u32 = 1;
/// Refuse to load files larger than this (defense against hostile input).
pub const MAX_FILE_BYTES: u64 = 512 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunInfo {
    pub command: Vec<String>,
    pub cwd: String,
    pub platform: String,
    pub arch: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<String>,
    pub started_at: f64,
    pub duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<BackendInfo>,
}

/// What the environment looked like, without leaking secret values.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EnvFingerprint {
    /// Every environment variable name; values only for a safe allowlist.
    pub variables: BTreeMap<String, Option<String>>,
    /// Short fingerprints of values not recorded verbatim, so a diff can tell
    /// "changed" from "same" without storing the value. Never computed for
    /// secret-looking names.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fingerprints: BTreeMap<String, String>,
    #[serde(default)]
    pub path_dirs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default)]
    pub uid: Option<u32>,
}

/// Variables whose values are recorded (still passed through redaction).
pub const SAFE_ENV_VALUES: &[&str] = &[
    "PATH",
    "SHELL",
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "CI",
    "NODE_ENV",
    "NODE_OPTIONS",
    "VIRTUAL_ENV",
    "CONDA_DEFAULT_ENV",
    "PYTHONPATH",
    "PYTHONHOME",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "GOPATH",
    "CARGO_HOME",
    "RUSTUP_TOOLCHAIN",
    "JAVA_HOME",
    "DOCKER_HOST",
    "COMPOSE_FILE",
    "COMPOSE_PROJECT_NAME",
    "HOSTALIASES",
    "RES_OPTIONS",
    "LOCALDOMAIN",
    "PWD",
    "HOME",
    "USER",
];

impl EnvFingerprint {
    pub fn capture(vars: &BTreeMap<String, String>) -> Self {
        let variables = vars
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    SAFE_ENV_VALUES.contains(&k.as_str()).then(|| v.clone()),
                )
            })
            .collect();
        let fingerprints = vars
            .iter()
            .filter(|(k, _)| !SAFE_ENV_VALUES.contains(&k.as_str()) && !secret_name(k))
            .map(|(k, v)| (k.clone(), fingerprint(k, v)))
            .collect();
        EnvFingerprint {
            variables,
            fingerprints,
            path_dirs: vars
                .get("PATH")
                .map(|p| p.split(':').map(String::from).collect())
                .unwrap_or_default(),
            user: vars.get("USER").cloned(),
            // Filled in by the CLI, which knows the effective uid.
            uid: None,
        }
    }
}

/// Names whose values must never be fingerprinted.
pub fn secret_name(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    [
        "PASS",
        "SECRET",
        "TOKEN",
        "KEY",
        "CREDENTIAL",
        "AUTH",
        "COOKIE",
        "SESSION",
        "PRIVATE",
        "SIGNATURE",
        "DSN",
        "_URL",
        "URI",
    ]
    .iter()
    .any(|w| n.contains(w))
}

/// 32-bit fingerprint (high half of 64-bit FNV-1a) of a variable's value (not reversible in general,
/// but only used for non-secret names).
pub fn fingerprint(name: &str, value: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes().chain([0u8]).chain(value.bytes()) {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{:08x}", (h >> 32) as u32)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhyTrace {
    pub format: String,
    pub format_version: u32,
    pub tracewhy_version: String,
    pub run: RunInfo,
    #[serde(default)]
    pub environment: EnvFingerprint,
    #[serde(default)]
    pub process_tree: ProcessTree,
    #[serde(default)]
    pub events: Vec<Event>,
    #[serde(default)]
    pub observations: Vec<Observation>,
    #[serde(default)]
    pub facts: Vec<Fact>,
    #[serde(default)]
    pub graph: CauseGraph,
    #[serde(default)]
    pub investigations: Vec<InvestigationRecord>,
    #[serde(default)]
    pub hypotheses: Vec<Hypothesis>,
    pub conclusion: Conclusion,
    #[serde(default)]
    pub stats: TraceStats,
    #[serde(default)]
    pub redactions: RedactionInfo,
    #[serde(default)]
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("cannot read {0}: {1}")]
    Io(String, std::io::Error),
    #[error("{0} is larger than {1} bytes")]
    TooLarge(String, u64),
    #[error("{0} is not a valid .whytrace file: {1}")]
    Invalid(String, String),
    #[error("{0} uses format version {1}; this TraceWhy supports up to {FORMAT_VERSION}. Upgrade TraceWhy.")]
    UnsupportedVersion(String, u32),
}

impl WhyTrace {
    /// Serialize to JSON, redacting every string unless `redact` is false.
    pub fn to_json(&self, redactor: Option<&Redactor>) -> Result<String, FormatError> {
        let mut v = serde_json::to_value(self)
            .map_err(|e| FormatError::Invalid("trace".into(), e.to_string()))?;
        if let Some(r) = redactor {
            r.redact_value(&mut v);
            let info = serde_json::to_value(r.info())
                .map_err(|e| FormatError::Invalid("trace".into(), e.to_string()))?;
            if let Some(obj) = v.as_object_mut() {
                obj.insert("redactions".into(), info);
            }
        } else if let Some(obj) = v.as_object_mut() {
            obj.insert(
                "redactions".into(),
                serde_json::json!({"applied": false, "counts": {}}),
            );
        }
        serde_json::to_string_pretty(&v)
            .map_err(|e| FormatError::Invalid("trace".into(), e.to_string()))
    }

    /// Write atomically (temp file + rename) with owner-only permissions.
    pub fn write(&self, path: &Path, redactor: Option<&Redactor>) -> Result<(), FormatError> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let name = path.display().to_string();
        let json = self.to_json(redactor)?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let tmp = path.with_file_name(format!(
            ".{}.{}-{nanos:x}.tmp",
            path.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            std::process::id()
        ));
        // Exclusive creation, never following a planted symlink.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| FormatError::Io(tmp.display().to_string(), e))?;
        let written = f
            .write_all(json.as_bytes())
            .and_then(|_| f.write_all(b"\n"))
            .and_then(|_| f.sync_all());
        drop(f);
        let result = written.and_then(|_| std::fs::rename(&tmp, path));
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result.map_err(|e| FormatError::Io(name, e))
    }

    pub fn from_json(name: &str, text: &str) -> Result<Self, FormatError> {
        let v: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| FormatError::Invalid(name.into(), e.to_string()))?;
        if v.get("format").and_then(|f| f.as_str()) != Some(FORMAT_NAME) {
            return Err(FormatError::Invalid(
                name.into(),
                "missing \"format\": \"whytrace\"".into(),
            ));
        }
        let ver = v
            .get("format_version")
            .and_then(|f| f.as_u64())
            .ok_or_else(|| FormatError::Invalid(name.into(), "missing format_version".into()))?;
        let ver = u32::try_from(ver).unwrap_or(u32::MAX);
        if ver == 0 || ver > FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion(name.into(), ver));
        }
        let mut t: WhyTrace = serde_json::from_value(v)
            .map_err(|e| FormatError::Invalid(name.into(), e.to_string()))?;
        t.graph.reindex();
        Ok(t)
    }

    pub fn read(path: &Path) -> Result<Self, FormatError> {
        let name = path.display().to_string();
        let f = std::fs::File::open(path).map_err(|e| FormatError::Io(name.clone(), e))?;
        let len = f.metadata().map(|m| m.len()).unwrap_or(0);
        if len > MAX_FILE_BYTES {
            return Err(FormatError::TooLarge(name, MAX_FILE_BYTES));
        }
        let mut text = String::new();
        f.take(MAX_FILE_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| FormatError::Io(name.clone(), e))?;
        Self::from_json(&name, &text)
    }
}

#[cfg(test)]
mod tests;
