use crate::{Event, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExitStatus {
    Exited { code: i32 },
    Killed { signal: String, core_dumped: bool },
}

impl ExitStatus {
    pub fn success(&self) -> bool {
        matches!(self, ExitStatus::Exited { code: 0 })
    }

    /// Shell-style numeric status: the exit code, or 128 + signal number.
    pub fn shell_code(&self) -> i32 {
        match self {
            ExitStatus::Exited { code } => *code,
            ExitStatus::Killed { signal, .. } => 128 + signal_number(signal).unwrap_or(0),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            ExitStatus::Exited { code } => format!("exited with code {code}"),
            ExitStatus::Killed {
                signal,
                core_dumped,
            } => {
                if *core_dumped {
                    format!("killed by {signal} (core dumped)")
                } else {
                    format!("killed by {signal}")
                }
            }
        }
    }
}

/// Signal name for a Linux signal number (inverse of [`signal_number`]).
pub fn signal_name(n: i32) -> String {
    const NAMES: [&str; 32] = [
        "",
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    match usize::try_from(n).ok().and_then(|i| NAMES.get(i)) {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => format!("SIG{n}"),
    }
}

/// Linux signal numbers (generic numbering used by x86_64 and aarch64).
pub fn signal_number(name: &str) -> Option<i32> {
    Some(match name {
        "SIGHUP" => 1,
        "SIGINT" => 2,
        "SIGQUIT" => 3,
        "SIGILL" => 4,
        "SIGTRAP" => 5,
        "SIGABRT" => 6,
        "SIGBUS" => 7,
        "SIGFPE" => 8,
        "SIGKILL" => 9,
        "SIGUSR1" => 10,
        "SIGSEGV" => 11,
        "SIGUSR2" => 12,
        "SIGPIPE" => 13,
        "SIGALRM" => 14,
        "SIGTERM" => 15,
        "SIGSTKFLT" => 16,
        "SIGCHLD" => 17,
        "SIGCONT" => 18,
        "SIGSTOP" => 19,
        "SIGTSTP" => 20,
        "SIGTTIN" => 21,
        "SIGTTOU" => 22,
        "SIGURG" => 23,
        "SIGXCPU" => 24,
        "SIGXFSZ" => 25,
        "SIGVTALRM" => 26,
        "SIGPROF" => 27,
        "SIGWINCH" => 28,
        "SIGIO" | "SIGPOLL" => 29,
        "SIGPWR" => 30,
        "SIGSYS" => 31,
        // Real-time and otherwise unnamed signals: "SIG42", "SIGRT_3".
        other => {
            if let Some(n) = other
                .strip_prefix("SIGRT_")
                .and_then(|n| n.parse::<i32>().ok())
            {
                return Some(32 + n);
            }
            return other.strip_prefix("SIG").and_then(|n| n.parse().ok());
        }
    })
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<u32>,
    /// Set when this "process" is really a thread of `thread_of`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_of: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<ExitStatus>,
    pub first_seq: u64,
    pub last_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ts: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_ts: Option<f64>,
    #[serde(default)]
    pub children: Vec<u32>,
}

impl ProcessInfo {
    fn new(pid: u32, seq: u64) -> Self {
        ProcessInfo {
            pid,
            parent: None,
            thread_of: None,
            executable: None,
            args: Vec::new(),
            exit: None,
            first_seq: seq,
            last_seq: seq,
            exit_seq: None,
            start_ts: None,
            end_ts: None,
            children: Vec::new(),
        }
    }

    /// Short display name: program basename plus a hint of its arguments.
    pub fn display_name(&self) -> String {
        let exe = self
            .executable
            .as_deref()
            .map(|e| e.rsplit('/').next().unwrap_or(e).to_string())
            .unwrap_or_else(|| format!("pid {}", self.pid));
        let mut parts = vec![exe];
        for a in self.args.iter().skip(1).take(3) {
            parts.push(a.clone());
        }
        let mut s = parts.join(" ");
        if s.chars().count() > 60 {
            s = s.chars().take(57).collect::<String>() + "...";
        }
        s
    }
}

/// Process tree reconstructed from fork/clone/exec/exit events.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessTree {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<u32>,
    pub processes: BTreeMap<u32, ProcessInfo>,
}

impl ProcessTree {
    /// Build a tree from an ordered event stream. Linear in the number of events.
    pub fn build(events: &[Event]) -> Self {
        let mut tree = ProcessTree::default();
        for ev in events {
            if tree.root.is_none() {
                tree.root = Some(ev.pid);
            }
            let p = tree
                .processes
                .entry(ev.pid)
                .or_insert_with(|| ProcessInfo::new(ev.pid, ev.seq));
            p.last_seq = ev.seq;
            if p.start_ts.is_none() {
                p.start_ts = ev.ts;
            }
            if ev.ts.is_some() {
                p.end_ts = ev.ts;
            }
            match &ev.kind {
                EventKind::ProcessExec { executable, args } => {
                    p.executable = Some(executable.clone());
                    p.args = args.clone();
                }
                EventKind::ProcessExited { code } => {
                    p.exit = Some(ExitStatus::Exited { code: *code });
                    p.exit_seq = Some(ev.seq);
                }
                EventKind::ProcessKilled {
                    signal,
                    core_dumped,
                } => {
                    p.exit = Some(ExitStatus::Killed {
                        signal: signal.clone(),
                        core_dumped: *core_dumped,
                    });
                    p.exit_seq = Some(ev.seq);
                }
                EventKind::ProcessSpawned { child, thread } => {
                    let parent = ev.pid;
                    let parent_exe = p.executable.clone();
                    let parent_args = p.args.clone();
                    let group = p.thread_of.unwrap_or(parent);
                    let c = tree
                        .processes
                        .entry(*child)
                        .or_insert_with(|| ProcessInfo::new(*child, ev.seq));
                    if *thread {
                        c.thread_of = Some(group);
                    } else {
                        c.parent = Some(group);
                    }
                    // A forked child runs the parent's image until it execs.
                    if c.executable.is_none() {
                        c.executable = parent_exe;
                        c.args = parent_args;
                    }
                    if !*thread {
                        // Each child is spawned once; duplicates are removed in `build`.
                        if let Some(g) = tree.processes.get_mut(&group) {
                            g.children.push(*child);
                        }
                    }
                }
                _ => {}
            }
        }
        for p in tree.processes.values_mut() {
            if p.children.len() > 1 {
                p.children.sort_unstable();
                p.children.dedup();
            }
        }
        tree
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessInfo> {
        self.processes.get(&pid)
    }

    /// The thread group a pid belongs to.
    pub fn group_of(&self, pid: u32) -> u32 {
        self.processes
            .get(&pid)
            .and_then(|p| p.thread_of)
            .unwrap_or(pid)
    }

    pub fn root_exit(&self) -> Option<&ExitStatus> {
        self.root
            .and_then(|r| self.processes.get(&r))
            .and_then(|p| p.exit.as_ref())
    }

    /// Ancestors of `pid` from the root down to (and including) `pid`.
    pub fn lineage(&self, pid: u32) -> Vec<u32> {
        let mut out = vec![self.group_of(pid)];
        let mut cur = self.group_of(pid);
        let mut guard = 0;
        while let Some(parent) = self.processes.get(&cur).and_then(|p| p.parent) {
            guard += 1;
            if guard > 4096 || out.contains(&parent) {
                break;
            }
            out.push(parent);
            cur = parent;
        }
        out.reverse();
        out
    }

    /// Walks from the root towards the process whose failure most plausibly
    /// propagated into the root's failure.
    ///
    /// At each level we pick the non-thread child that failed before its
    /// parent exited, preferring a matching exit status and then the most
    /// recent failure.
    pub fn failure_chain(&self) -> Vec<u32> {
        let Some(root) = self.root else {
            return Vec::new();
        };
        let mut chain = vec![root];
        let mut cur = root;
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4096 {
                break;
            }
            let Some(info) = self.processes.get(&cur) else {
                break;
            };
            let Some(status) = &info.exit else { break };
            if status.success() {
                break;
            }
            let parent_code = status.shell_code();
            let parent_exit_seq = info.exit_seq.unwrap_or(u64::MAX);
            let best = info
                .children
                .iter()
                .filter_map(|c| self.processes.get(c))
                .filter(|c| c.thread_of.is_none())
                .filter_map(|c| {
                    let st = c.exit.as_ref()?;
                    if st.success() || c.exit_seq.unwrap_or(u64::MAX) > parent_exit_seq {
                        return None;
                    }
                    let matches = st.shell_code() == parent_code;
                    Some((matches, c.exit_seq.unwrap_or(0), c.pid))
                })
                .max();
            match best {
                Some((_, _, pid)) if !chain.contains(&pid) => {
                    chain.push(pid);
                    cur = pid;
                }
                _ => break,
            }
        }
        chain
    }

    /// All pids that belong to the thread group `pid` (the process and its threads).
    pub fn threads_of(&self, pid: u32) -> Vec<u32> {
        let g = self.group_of(pid);
        self.processes
            .values()
            .filter(|p| p.pid == g || p.thread_of == Some(g))
            .map(|p| p.pid)
            .collect()
    }

    pub fn process_count(&self) -> usize {
        self.processes
            .values()
            .filter(|p| p.thread_of.is_none())
            .count()
    }
}

#[cfg(test)]
mod tests;
