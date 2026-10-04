//! Line-level strace output parser.
//!
//! Turns one line of `strace -f -ttt -yy` output into a [`RawRecord`]. It never
//! panics: unrecognized input yields `None` so the caller can record a
//! diagnostic and move on.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub struct RawRecord {
    pub line: u64,
    pub pid: Option<u32>,
    pub ts: Option<f64>,
    pub kind: RawKind,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RawKind {
    Syscall(Syscall),
    Signal { name: String },
    Exited { code: i32 },
    Killed { signal: String, core_dumped: bool },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Syscall {
    pub name: String,
    /// Raw text between the outer parentheses.
    pub args: String,
    pub ret: Ret,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Ret {
    pub raw: String,
    /// Numeric return value; `None` for `?` or unparseable values.
    pub value: Option<i64>,
    pub errno: Option<String>,
    /// `-yy` annotation on a returned fd, e.g. `/etc/hosts` or `TCP:[123]`.
    pub annotation: Option<String>,
}

impl Ret {
    pub fn ok(&self) -> bool {
        self.errno.is_none() && self.value.map(|v| v >= 0).unwrap_or(false)
    }
}

/// Result of feeding one line to the parser.
#[derive(Debug, Clone, PartialEq)]
pub enum LineResult {
    Record(RawRecord),
    /// Start of an interrupted syscall; completed by a later `resumed` line.
    Pending,
    /// Recognized but carries no information (blank line, strace chatter).
    Ignored,
    Unparsed(String),
}

/// Stateful parser that stitches `<unfinished ...>` / `resumed` pairs.
#[derive(Debug, Default)]
pub struct LineParser {
    pending: HashMap<u32, PendingCall>,
}

#[derive(Debug)]
struct PendingCall {
    name: String,
    args_prefix: String,
}

const UNFINISHED: &str = "<unfinished ...>";

impl LineParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_line(&mut self, line_no: u64, line: &str) -> LineResult {
        let line = line.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() {
            return LineResult::Ignored;
        }
        let (pid, ts, rest) = split_prefix(line);
        let rest = rest.trim_start();

        if rest.starts_with("strace:") || rest.starts_with("Process ") {
            return LineResult::Ignored;
        }
        if let Some(inner) = rest
            .strip_prefix("+++ ")
            .and_then(|r| r.strip_suffix(" +++"))
        {
            return match parse_exit(inner) {
                Some(kind) => LineResult::Record(RawRecord {
                    line: line_no,
                    pid,
                    ts,
                    kind,
                }),
                None => LineResult::Ignored,
            };
        }
        if let Some(inner) = rest.strip_prefix("--- ") {
            let name: String = inner.split([' ', '{']).next().unwrap_or("").to_string();
            if name.starts_with("SIG") {
                return LineResult::Record(RawRecord {
                    line: line_no,
                    pid,
                    ts,
                    kind: RawKind::Signal { name },
                });
            }
            return LineResult::Ignored;
        }
        if let Some(r) = rest.strip_prefix("<... ") {
            // `<... name resumed>REST`
            let Some(end) = r.find(" resumed>") else {
                return LineResult::Unparsed(line.to_string());
            };
            let name = r[..end].to_string();
            let tail = &r[end + " resumed>".len()..];
            let key = pid.unwrap_or(0);
            let prefix = match self.pending.remove(&key) {
                Some(p) if p.name == name => p.args_prefix,
                // Unknown prefix: the arguments before the interruption are lost.
                _ => String::new(),
            };
            if let Some(t) = tail.strip_suffix(UNFINISHED) {
                // Resumed and interrupted again.
                self.pending.insert(
                    key,
                    PendingCall {
                        name,
                        args_prefix: format!("{prefix}{}", t.strip_suffix(' ').unwrap_or(t)),
                    },
                );
                return LineResult::Pending;
            }
            let full = format!("{name}({prefix}{tail}");
            return match parse_call(&full) {
                Some(sc) => LineResult::Record(RawRecord {
                    line: line_no,
                    pid,
                    ts,
                    kind: RawKind::Syscall(sc),
                }),
                None => LineResult::Unparsed(line.to_string()),
            };
        }
        if let Some(head) = rest.strip_suffix(UNFINISHED) {
            // strace separates the marker with exactly one space.
            let head = head.strip_suffix(' ').unwrap_or(head);
            let Some(open) = head.find('(') else {
                return LineResult::Unparsed(line.to_string());
            };
            let name = head[..open].to_string();
            if !is_ident(&name) {
                return LineResult::Unparsed(line.to_string());
            }
            self.pending.insert(
                pid.unwrap_or(0),
                PendingCall {
                    name,
                    args_prefix: head[open + 1..].to_string(),
                },
            );
            return LineResult::Pending;
        }
        match parse_call(rest) {
            Some(sc) => LineResult::Record(RawRecord {
                line: line_no,
                pid,
                ts,
                kind: RawKind::Syscall(sc),
            }),
            None => LineResult::Unparsed(line.to_string()),
        }
    }

    /// Number of syscalls still waiting for their `resumed` line.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

fn is_ident(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '?')
}

/// Split the optional `PID` / `[pid PID]` and timestamp prefix.
fn split_prefix(line: &str) -> (Option<u32>, Option<f64>, &str) {
    let mut rest = line;
    let mut pid = None;
    if let Some(r) = rest.strip_prefix("[pid") {
        let r = r.trim_start();
        if let Some(end) = r.find(']') {
            pid = r[..end].trim().parse().ok();
            rest = &r[end + 1..];
        }
    } else {
        let tok_end = rest.find(' ').unwrap_or(rest.len());
        let tok = &rest[..tok_end];
        if !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_digit()) {
            pid = tok.parse().ok();
            rest = &rest[tok_end..];
        }
    }
    rest = rest.trim_start();
    let mut ts = None;
    let tok_end = rest.find(' ').unwrap_or(rest.len());
    let tok = &rest[..tok_end];
    if !tok.is_empty()
        && tok
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'.' || b == b':')
    {
        if tok.contains(':') {
            // -tt format HH:MM:SS.micros → seconds since midnight.
            let parts: Vec<&str> = tok.split(':').collect();
            if parts.len() == 3 {
                let h: f64 = parts[0].parse().unwrap_or(0.0);
                let m: f64 = parts[1].parse().unwrap_or(0.0);
                let s: f64 = parts[2].parse().unwrap_or(0.0);
                ts = Some(h * 3600.0 + m * 60.0 + s);
                rest = &rest[tok_end..];
            }
        } else if tok.contains('.') {
            ts = tok.parse().ok();
            if ts.is_some() {
                rest = &rest[tok_end..];
            }
        }
    }
    (pid, ts, rest)
}

fn parse_exit(inner: &str) -> Option<RawKind> {
    if let Some(code) = inner.strip_prefix("exited with ") {
        return code
            .trim()
            .parse()
            .ok()
            .map(|code| RawKind::Exited { code });
    }
    if let Some(r) = inner.strip_prefix("killed by ") {
        let core_dumped = r.contains("(core dumped)");
        let signal = r.split_whitespace().next()?.to_string();
        return Some(RawKind::Killed {
            signal,
            core_dumped,
        });
    }
    None
}

/// Parse `name(args) = ret`.
pub fn parse_call(s: &str) -> Option<Syscall> {
    let open = s.find('(')?;
    let name = s[..open].trim();
    if !is_ident(name) {
        return None;
    }
    let body = &s[open + 1..];
    let close = find_matching_close(body)?;
    let args = body[..close].to_string();
    let after = body[close + 1..].trim_start();
    let ret_text = after.strip_prefix('=')?.trim();
    Some(Syscall {
        name: name.to_string(),
        args,
        ret: parse_ret(ret_text),
    })
}

/// Index of the `)` closing the argument list, honoring nesting and strings.
fn find_matching_close(body: &str) -> Option<usize> {
    let bytes = body.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;
    let mut in_str = false;
    // The closing paren of the call is the last top-level ')' followed by " =".
    let mut candidate = None;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'(' | b'[' | b'{' => depth += 1,
                b']' | b'}' => depth -= 1,
                b')' => {
                    if depth == 0 {
                        let rest = body[i + 1..].trim_start();
                        if rest.starts_with('=') {
                            candidate = Some(i);
                            break;
                        }
                    } else {
                        depth -= 1;
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    candidate
}

pub fn parse_ret(s: &str) -> Ret {
    let mut ret = Ret {
        raw: s.to_string(),
        ..Ret::default()
    };
    let end = s.find([' ', '<']).unwrap_or(s.len());
    let val = &s[..end];
    ret.value = if let Some(hex) = val.strip_prefix("0x") {
        i64::from_str_radix(hex, 16).ok()
    } else {
        val.parse().ok()
    };
    let mut rest = &s[end..];
    if rest.starts_with('<') {
        // Annotation runs to the last '>' before any trailing " (...)" text.
        let ann_end = match rest.find("> ") {
            Some(i) => i,
            None => rest.rfind('>').unwrap_or(rest.len().saturating_sub(1)),
        };
        if ann_end > 0 {
            ret.annotation = Some(rest[1..ann_end].to_string());
            rest = &rest[(ann_end + 1).min(rest.len())..];
        }
    }
    let rest = rest.trim_start();
    if ret.value.map(|v| v < 0).unwrap_or(false) || val == "?" {
        let tok = rest.split_whitespace().next().unwrap_or("");
        if tok.starts_with('E')
            && tok.len() > 1
            && tok
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        {
            ret.errno = Some(tok.to_string());
        }
    }
    ret
}

#[cfg(test)]
mod tests;
