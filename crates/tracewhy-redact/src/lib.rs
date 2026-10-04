//! Secret redaction.
//!
//! Every string TraceWhy prints or exports passes through a [`Redactor`] by
//! default. Patterns favor precision: well-known token formats, credential
//! key/value pairs, URL passwords, auth headers, and long high-entropy
//! strings that do not look like paths or hashes.

use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Mutex;

pub const REDACTED: &str = "<redacted>";

struct Rule {
    name: &'static str,
    re: Regex,
    /// Capture groups to keep verbatim before the redacted part.
    keep: usize,
}

/// Summary of what was redacted, stored in `.whytrace` files.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionInfo {
    pub applied: bool,
    #[serde(default)]
    pub counts: BTreeMap<String, u64>,
}

pub struct Redactor {
    rules: Vec<Rule>,
    home: Option<String>,
    home_re: Option<Regex>,
    counts: Mutex<BTreeMap<String, u64>>,
}

fn rule(name: &'static str, pattern: &str, keep: usize) -> Option<Rule> {
    // Patterns are compile-time constants; `rules_all_compile` guards them.
    Regex::new(pattern).ok().map(|re| Rule { name, re, keep })
}

/// Number of built-in redaction rules (checked by tests so none is silently dropped).
pub const RULE_COUNT: usize = 18;

impl Redactor {
    /// Redactor for the current user (`$HOME` becomes `~`).
    pub fn new() -> Self {
        Self::with_home(std::env::var("HOME").ok())
    }

    pub fn with_home(home: Option<String>) -> Self {
        let rules: Vec<Rule> = [
            rule("private_key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.)*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", 0),
            rule("auth_header", r#"(?i)\b((?:proxy-)?authorization\s*[:=]\s*"?)(?:[A-Za-z]+\s+)?[^\s"',;]+"#, 1),
            rule("bearer", r"(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]{8,}=*", 1),
            rule("url_password", r"(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^/\s@]+(@)", 2),
            rule("query_param", r#"(?i)([?&;](?:access_token|refresh_token|id_token|token|api_key|apikey|api-key|key|secret|client_secret|password|passwd|pwd|sig|signature|auth|session|sessionid|code|x-amz-signature|x-amz-credential)=)[^&\s"'#]+"#, 1),
            rule("basic_auth_flag", r#"((?:^|\s)(?:-u|--user|--proxy-user)(?:=|\s+)[^\s:"']+:)[^\s"']+"#, 1),
            rule("cli_flag", r#"(?i)(--?(?:password|passwd|pass|pw|token|secret|api-key|api_key|apikey|access-key|access-token|secret-key|auth-token|client-secret|private-key)(?:=|\s+))[^\s"']+"#, 1),
            rule("key_value", r#"(?i)\b([A-Z0-9_.\-]*(?:password|passwd|secret|token|api_?key|access_?key|private_?key|credentials?|auth_?key|session_?key)[A-Z0-9_]*["']?\s*[=:]\s*["']?)[^\s"'&,;}]{2,}"#, 1),
            rule("aws_access_key", r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b", 0),
            rule("github_token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b", 0),
            rule("gitlab_token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b", 0),
            rule("anthropic_key", r"\bsk-ant-[A-Za-z0-9_\-]{20,}", 0),
            rule("openai_key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}", 0),
            rule("stripe_key", r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b", 0),
            rule("slack_token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,}", 0),
            rule("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0),
            rule("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", 0),
            rule("jwt", r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}", 0),
        ]
        .into_iter()
        .flatten()
        .collect();
        let home = home
            .filter(|h| h.len() > 1 && h.starts_with('/'))
            .map(|h| h.trim_end_matches('/').to_string());
        let home_re = Regex::new(r"(^|[^A-Za-z0-9_.\-])/(?:home|Users)/([A-Za-z0-9_.\-]+)").ok();
        Redactor {
            rules,
            home,
            home_re,
            counts: Mutex::new(BTreeMap::new()),
        }
    }

    fn bump(&self, name: &str, n: u64) {
        if n == 0 {
            return;
        }
        if let Ok(mut c) = self.counts.lock() {
            *c.entry(name.to_string()).or_insert(0) += n;
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn info(&self) -> RedactionInfo {
        RedactionInfo {
            applied: true,
            counts: self.counts.lock().map(|c| c.clone()).unwrap_or_default(),
        }
    }

    /// Redact secrets and home-directory paths in `s`.
    ///
    /// Applied to a fixpoint (bounded), because a replacement can expose a
    /// new match boundary; redacting already-redacted text is a no-op.
    pub fn redact<'a>(&self, s: &'a str) -> Cow<'a, str> {
        let mut cur = self.redact_once(s);
        for _ in 0..3 {
            let Cow::Owned(prev) = &cur else { break };
            match self.redact_once(prev) {
                Cow::Owned(next) if next != *prev => cur = Cow::Owned(next),
                _ => break,
            }
        }
        cur
    }

    fn redact_once<'a>(&self, s: &'a str) -> Cow<'a, str> {
        let mut cur: Cow<'a, str> = Cow::Borrowed(s);
        for r in &self.rules {
            if !r.re.is_match(&cur) {
                continue;
            }
            let mut n = 0u64;
            let replaced =
                r.re.replace_all(&cur, |c: &Captures<'_>| {
                    n += 1;
                    let mut out = String::new();
                    for g in 1..=r.keep {
                        if g == r.keep && r.keep >= 2 {
                            // The last kept group is a suffix (e.g. the `@` in URLs).
                            out.push_str(REDACTED);
                            out.push_str(c.get(g).map(|m| m.as_str()).unwrap_or(""));
                            return out;
                        }
                        out.push_str(c.get(g).map(|m| m.as_str()).unwrap_or(""));
                    }
                    out.push_str(REDACTED);
                    out
                })
                .into_owned();
            self.bump(r.name, n);
            cur = Cow::Owned(replaced);
        }
        if let Some(e) = self.redact_entropy(&cur) {
            cur = Cow::Owned(e);
        }
        // Other users' home directories first (the current user's is kept for
        // the exact `~` substitution below), so the result is idempotent.
        if let Some(re) = &self.home_re {
            if re.is_match(&cur) {
                let mut n = 0;
                let own = self.home.clone();
                let out = re
                    .replace_all(&cur, |c: &Captures<'_>| {
                        let whole = c.get(0).map(|m| m.as_str()).unwrap_or("");
                        let prefix = c.get(1).map(|m| m.as_str()).unwrap_or("");
                        if own.as_deref() == Some(&whole[prefix.len()..]) {
                            return whole.to_string();
                        }
                        n += 1;
                        format!("{prefix}/home/<user>")
                    })
                    .into_owned();
                self.bump("other_home_dir", n);
                cur = Cow::Owned(out);
            }
        }
        if let Some(h) = &self.home {
            if cur.contains(h.as_str()) {
                let n = cur.matches(h.as_str()).count() as u64;
                cur = Cow::Owned(replace_home(&cur, h));
                self.bump("home_dir", n);
            }
        }
        cur
    }

    fn redact_entropy(&self, s: &str) -> Option<String> {
        let bytes = s.as_bytes();
        let is_tok =
            |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'=' || b == b'_' || b == b'-';
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        let mut last = 0;
        let mut changed = false;
        while i < bytes.len() {
            if !is_tok(bytes[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < bytes.len() && is_tok(bytes[i]) {
                i += 1;
            }
            let tok = &s[start..i];
            let prev = if start > 0 { bytes[start - 1] } else { b' ' };
            let next = bytes.get(i).copied().unwrap_or(b' ');
            // Path components and file names are not secrets.
            if prev == b'/' || prev == b'.' || next == b'/' || next == b'.' {
                continue;
            }
            if looks_secret(tok) {
                out.push_str(&s[last..start]);
                out.push_str(REDACTED);
                last = i;
                changed = true;
                self.bump("high_entropy", 1);
            }
        }
        if !changed {
            return None;
        }
        out.push_str(&s[last..]);
        Some(out)
    }

    /// Redact every string (and object key) in a JSON value in place.
    pub fn redact_value(&self, v: &mut serde_json::Value) {
        match v {
            serde_json::Value::String(s) => {
                if let Cow::Owned(r) = self.redact(s) {
                    *s = r;
                }
            }
            serde_json::Value::Array(a) => {
                // argv-style arrays: a sensitive flag's value is the next element.
                let mut redact_next = false;
                for x in a.iter_mut() {
                    if redact_next {
                        if let serde_json::Value::String(s) = x {
                            if !s.starts_with('-') {
                                *s = REDACTED.to_string();
                                self.bump("cli_flag", 1);
                            }
                        }
                        redact_next = false;
                        continue;
                    }
                    if let serde_json::Value::String(s) = x {
                        redact_next = is_secret_flag(s);
                    }
                    self.redact_value(x);
                }
            }
            // Object keys are structural (field names, env var names, pids)
            // and are not rewritten: rewriting could merge distinct keys.
            serde_json::Value::Object(m) => m.values_mut().for_each(|x| self.redact_value(x)),
            _ => {}
        }
    }
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

fn replace_home(s: &str, home: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(home) {
        let after = &rest[i + home.len()..];
        let before_ok = out.is_empty() && i == 0
            || rest[..i]
                .chars()
                .last()
                .or_else(|| out.chars().last())
                .map(|c| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-')))
                .unwrap_or(true);
        let after_ok = after.is_empty()
            || after.starts_with('/')
            || !after.as_bytes()[0].is_ascii_alphanumeric();
        out.push_str(&rest[..i]);
        out.push_str(if before_ok && after_ok { "~" } else { home });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// A command-line flag whose following argument is a secret (`--token VALUE`).
pub fn is_secret_flag(arg: &str) -> bool {
    let a = arg.trim_start_matches('-');
    arg.starts_with('-')
        && !arg.contains('=')
        && matches!(
            a.to_ascii_lowercase().as_str(),
            "password"
                | "passwd"
                | "pass"
                | "token"
                | "secret"
                | "api-key"
                | "apikey"
                | "api_key"
                | "access-key"
                | "secret-key"
                | "auth-token"
                | "client-secret"
                | "access-token"
                | "private-key"
                | "pw"
        )
}

/// Redact a command line given as separate arguments.
pub fn redact_argv(r: &Redactor, argv: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut redact_next = false;
    for a in argv {
        if redact_next && !a.starts_with('-') {
            out.push(REDACTED.to_string());
            redact_next = false;
            continue;
        }
        redact_next = is_secret_flag(a);
        out.push(r.redact(a).into_owned());
    }
    out
}

/// Long, mixed-character, high-entropy tokens that are not hex digests.
pub fn looks_secret(tok: &str) -> bool {
    if tok.len() < 32 || tok.len() > 512 {
        return false;
    }
    if tok.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return false;
    }
    let lower = tok.bytes().any(|b| b.is_ascii_lowercase());
    let upper = tok.bytes().any(|b| b.is_ascii_uppercase());
    let digit = tok.bytes().any(|b| b.is_ascii_digit());
    if !(digit && (lower || upper)) || !(lower && upper || digit && tok.len() >= 40) {
        return false;
    }
    // Identifiers like SOME_LONG_CONSTANT_NAME_WITH_WORDS are not secrets.
    if tok.contains('_')
        && tok.split('_').all(|p| {
            p.len() <= 12
                && p.bytes()
                    .all(|b| b.is_ascii_alphabetic() || b.is_ascii_digit())
                && p.len() > 1
        })
        && tok.matches('_').count() >= 3
    {
        return false;
    }
    entropy(tok) >= 4.0
}

fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests;
