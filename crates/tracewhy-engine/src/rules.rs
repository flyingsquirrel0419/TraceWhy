//! Declarative rules: which hypotheses and investigations an observation triggers.
//!
//! Rules are TOML, embedded at build time from the repository's `rules/`
//! directory. Additional rule files can be loaded at runtime from the
//! directory named by `TRACEWHY_RULES_DIR`; they may combine any existing
//! hypothesis kinds and investigation targets.

use crate::hypotheses::KNOWN_HYPOTHESES;
use serde::{Deserialize, Serialize};
use tracewhy_core::{Observation, ObservationKind};
use tracewhy_event::{Endpoint, Protocol};

/// Investigation target kinds a rule may request.
pub const KNOWN_TARGETS: &[&str] = &[
    "port",
    "local_addresses",
    "docker",
    "path",
    "filesystem",
    "executable",
    "elf",
    "library",
    "hostname",
    "fd_limit",
    "network",
    "privileges",
];

pub const BUILTIN_RULES: &[(&str, &str)] = &[
    (
        "rules/network/network.toml",
        include_str!("../../../rules/network/network.toml"),
    ),
    (
        "rules/filesystem/filesystem.toml",
        include_str!("../../../rules/filesystem/filesystem.toml"),
    ),
    (
        "rules/process/process.toml",
        include_str!("../../../rules/process/process.toml"),
    ),
    (
        "rules/runtime/runtime.toml",
        include_str!("../../../rules/runtime/runtime.toml"),
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// Observation type name (see `ObservationKind::name`).
    pub observation: String,
    /// Error codes that trigger the rule; empty matches any.
    #[serde(default)]
    pub errors: Vec<String>,
    /// `inet` or `unix`, for connect/bind observations.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// `tcp`, `udp` or `unix`.
    #[serde(default)]
    pub protocols: Vec<String>,
    pub hypotheses: Vec<String>,
    #[serde(default)]
    pub investigate: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
    pub warnings: Vec<String>,
}

impl RuleSet {
    pub fn builtin() -> Self {
        let mut set = RuleSet::default();
        for (name, text) in BUILTIN_RULES {
            set.load_str(name, text);
        }
        set
    }

    /// Built-in rules plus any `*.toml` in `$TRACEWHY_RULES_DIR`.
    pub fn with_user_rules() -> Self {
        let mut set = Self::builtin();
        if let Some(dir) = std::env::var_os("TRACEWHY_RULES_DIR") {
            match std::fs::read_dir(&dir) {
                Ok(entries) => {
                    let mut files: Vec<_> = entries
                        .flatten()
                        .map(|e| e.path())
                        .filter(|p| p.extension().map(|e| e == "toml").unwrap_or(false))
                        .collect();
                    files.sort();
                    for f in files {
                        match std::fs::read_to_string(&f) {
                            Ok(t) => set.load_str(&f.to_string_lossy(), &t),
                            Err(e) => set.warnings.push(format!("{}: {e}", f.display())),
                        }
                    }
                }
                Err(e) => set
                    .warnings
                    .push(format!("TRACEWHY_RULES_DIR {}: {e}", dir.to_string_lossy())),
            }
        }
        set
    }

    pub fn load_str(&mut self, name: &str, text: &str) {
        let file: RuleFile = match toml::from_str(text) {
            Ok(f) => f,
            Err(e) => {
                self.warnings.push(format!("{name}: {e}"));
                return;
            }
        };
        for rule in file.rule {
            match validate(&rule) {
                Ok(()) => {
                    if self.rules.iter().any(|r| r.id == rule.id) {
                        self.warnings
                            .push(format!("{name}: duplicate rule id {}, ignored", rule.id));
                    } else {
                        self.rules.push(rule);
                    }
                }
                Err(e) => self.warnings.push(format!("{name}: rule {}: {e}", rule.id)),
            }
        }
    }

    pub fn matching<'a>(&'a self, obs: &'a Observation) -> impl Iterator<Item = &'a Rule> + 'a {
        self.rules.iter().filter(move |r| r.matches(obs))
    }
}

pub fn validate(rule: &Rule) -> Result<(), String> {
    const OBS: &[&str] = &[
        "exec_failed",
        "file_access_failed",
        "connect_failed",
        "bind_failed",
        "dns_failed",
        "write_failed",
        "resource_limit",
        "library_load_failed",
        "process_crashed",
        "runtime",
    ];
    if rule.id.trim().is_empty() {
        return Err("empty id".into());
    }
    if !OBS.contains(&rule.observation.as_str()) {
        return Err(format!("unknown observation type {:?}", rule.observation));
    }
    for h in &rule.hypotheses {
        if !KNOWN_HYPOTHESES.contains(&h.as_str()) {
            return Err(format!("unknown hypothesis {h:?}"));
        }
    }
    for t in &rule.investigate {
        if !KNOWN_TARGETS.contains(&t.as_str()) {
            return Err(format!("unknown investigation target {t:?}"));
        }
    }
    if let Some(e) = &rule.endpoint {
        if e != "inet" && e != "unix" {
            return Err(format!("endpoint must be inet or unix, got {e:?}"));
        }
    }
    Ok(())
}

impl Rule {
    pub fn matches(&self, obs: &Observation) -> bool {
        if obs.kind.name() != self.observation {
            return false;
        }
        if !self.errors.is_empty() {
            match obs.kind.error_code() {
                Some(code) if self.errors.iter().any(|e| e == &code) => {}
                _ => return false,
            }
        }
        let (endpoint, protocol) = match &obs.kind {
            ObservationKind::ConnectFailed {
                endpoint, protocol, ..
            }
            | ObservationKind::BindFailed {
                endpoint, protocol, ..
            } => (Some(endpoint), Some(*protocol)),
            _ => (None, None),
        };
        if let Some(want) = &self.endpoint {
            let is = match endpoint {
                Some(Endpoint::Inet { .. }) => "inet",
                Some(Endpoint::Unix { .. }) => "unix",
                None => return false,
            };
            if is != want {
                return false;
            }
        }
        if !self.protocols.is_empty() {
            let p = match protocol {
                Some(Protocol::Tcp) => "tcp",
                Some(Protocol::Udp) => "udp",
                Some(Protocol::Unix) => "unix",
                _ => "other",
            };
            if !self.protocols.iter().any(|x| x == p) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_rules_are_valid() {
        let set = RuleSet::builtin();
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
        assert!(set.rules.len() >= 15);
    }

    #[test]
    fn rejects_unknown_names() {
        let mut set = RuleSet::default();
        set.load_str(
            "x",
            r#"[[rule]]
id = "x"
observation = "connect_failed"
hypotheses = ["made_up"]
"#,
        );
        assert!(set.rules.is_empty());
        assert_eq!(set.warnings.len(), 1);
        set.load_str("y", "not toml [[");
        assert_eq!(set.warnings.len(), 2);
    }

    #[test]
    fn user_rule_can_reuse_hypotheses() {
        let mut set = RuleSet::default();
        set.load_str(
            "custom",
            r#"[[rule]]
id = "custom.timeout"
observation = "connect_failed"
errors = ["ETIMEDOUT"]
hypotheses = ["connect_timeout"]
investigate = ["port"]
"#,
        );
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
        assert_eq!(set.rules.len(), 1);
    }
}
