//! Parser/normalizer throughput benchmark on a synthetic strace log.
//!
//! cargo run --release -p tracewhy-tracer-strace --example bench -- [LINES]

use std::time::Instant;
use tracewhy_tracer_strace::{normalize_str, NormalizeLimits};

fn peak_rss_kib() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse().ok())
        })
        .unwrap_or(0)
}

fn main() {
    let lines: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(1_000_000);
    let mut text = String::with_capacity(lines * 110);
    let procs = (lines / 500).max(1);
    let per = lines / procs;
    for p in 0..procs {
        let pid = 10_000 + p;
        if p > 0 {
            text.push_str(&format!(
                "10000 1.0 clone(child_stack=NULL, flags=SIGCHLD) = {pid}\n"
            ));
        }
        for i in 0..per {
            match i % 10 {
                0 => text.push_str(&format!("{pid} 1.{i:06} openat(AT_FDCWD</srv/app>, \"node_modules/pkg{i}/index.js\", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)\n")),
                1 => text.push_str(&format!("{pid} 1.{i:06} newfstatat(AT_FDCWD</srv/app>, \"/srv/app/lib/{i}\", 0x7ffd, 0) = -1 ENOENT (No such file or directory)\n")),
                2 => text.push_str(&format!("{pid} 1.{i:06} write(2</dev/pts/0<char 136:0>>, \"log line {i}\\n\", 13) = 13\n")),
                3 => text.push_str(&format!("{pid} 1.{i:06} connect(5<TCP:[{i}]>, {{sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr(\"10.0.0.1\")}}, 16) = 0\n")),
                _ => text.push_str(&format!("{pid} 1.{i:06} openat(AT_FDCWD</srv/app>, \"/srv/app/src/f{i}.js\", O_RDONLY|O_CLOEXEC) = 3</srv/app/src/f{i}.js>\n")),
            }
        }
        text.push_str(&format!("{pid} 2.0 +++ exited with 0 +++\n"));
    }
    let bytes = text.len();
    let start = Instant::now();
    let t = normalize_str(
        &text,
        NormalizeLimits {
            max_events: usize::MAX,
            ..Default::default()
        },
    );
    let parse = start.elapsed();
    let start = Instant::now();
    let tree = tracewhy_event::ProcessTree::build(&t.events);
    let tree_t = start.elapsed();
    println!(
        "{} lines, {:.1} MiB: normalize {:.2?} ({:.0} lines/s, {:.0} MiB/s), process tree {:.2?} ({} processes), {} events, peak RSS {} MiB",
        t.stats.raw_lines,
        bytes as f64 / (1 << 20) as f64,
        parse,
        t.stats.raw_lines as f64 / parse.as_secs_f64(),
        bytes as f64 / (1 << 20) as f64 / parse.as_secs_f64(),
        tree_t,
        tree.process_count(),
        t.events.len(),
        peak_rss_kib() / 1024
    );
}
