//! Randomized robustness tests: hostile or corrupted input must never panic.
//! (A deterministic xorshift generator keeps failures reproducible.)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tracewhy_tracer_strace::{dns, normalize_str, NormalizeLimits};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const SEEDS: &[&str] = &[
    r#"1 1.0 openat(AT_FDCWD</srv>, "a\"b\\c", O_RDONLY|O_CREAT, 0644) = -1 ENOENT (No such file or directory)"#,
    r#"2 1.1 connect(3<TCP:[1]>, {sa_family=AF_INET6, sin6_port=htons(5432), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "::1", &sin6_addr), sin6_scope_id=0}, 28) = -1 EINPROGRESS (x)"#,
    r#"2 1.2 getsockopt(3<TCP:[1]>, SOL_SOCKET, SO_ERROR, [ECONNREFUSED], [4]) = 0"#,
    r#"3 1.3 execve("/bin/x", ["x", "y z"], 0x1 /* 9 vars */) = -1 EACCES (Permission denied)"#,
    r#"3 1.4 recvfrom(3<UDP:[1.2.3.4:5->127.0.0.53:53]>, "\366\301\205\243\0\1\0\0\0\0\0\1\2db\7invalid\0\0\1\0\1", 2048, 0, NULL, NULL) = 30"#,
    "4 1.5 read(3,  <unfinished ...>",
    "4 1.6 <... read resumed>\"abc\", 10) = 3",
    "5 1.7 +++ killed by SIGSEGV (core dumped) +++",
    "5 1.8 --- SIGPIPE {si_signo=SIGPIPE} ---",
    "6 1.9 clone3({flags=CLONE_VM|CLONE_THREAD, child_tid=0x1}, 88) = 7",
    r#"6 2.0 write(2</dev/pts/0<char 136:0>>, "\x1b[31merror\x1b[0m\n", 15) = 15"#,
];

const NOISE: &[&str] = &[
    "(",
    ")",
    "{",
    "}",
    "[",
    "]",
    "\"",
    "\\",
    ",",
    " = ",
    "<",
    ">",
    "...",
    "\0",
    "é",
    "-1",
    " E",
    "\n",
    "<unfinished ...>",
    "<... x resumed>",
];

#[test]
fn mutated_strace_lines_never_panic() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..4000 {
        let mut text = String::new();
        for _ in 0..rng.below(12) + 1 {
            let mut line = SEEDS[rng.below(SEEDS.len())].to_string();
            for _ in 0..rng.below(4) {
                let pos = rng.below(line.len() + 1);
                let pos = (0..=pos)
                    .rev()
                    .find(|p| line.is_char_boundary(*p))
                    .unwrap_or(0);
                match rng.below(3) {
                    0 => line.insert_str(pos, NOISE[rng.below(NOISE.len())]),
                    1 => line.truncate(pos),
                    _ => {
                        let end = (pos + rng.below(8)).min(line.len());
                        let end = (end..=line.len())
                            .find(|p| line.is_char_boundary(*p))
                            .unwrap_or(line.len());
                        line.replace_range(pos..end, "");
                    }
                }
            }
            text.push_str(&line);
            text.push('\n');
        }
        let _ = normalize_str(&text, NormalizeLimits::default());
    }
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(42);
    for _ in 0..2000 {
        let len = rng.below(300);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let text = String::from_utf8_lossy(&bytes);
        let _ = normalize_str(&text, NormalizeLimits::default());
        let _ = dns::decode(&bytes);
    }
}

#[test]
fn large_trace_scales_linearly() {
    // 200k lines across 2,000 processes; must stay fast (no quadratic paths).
    let mut text = String::with_capacity(200_000 * 90);
    let mut seq = 0u64;
    for p in 0..2000u32 {
        let pid = 1000 + p;
        if p > 0 {
            text.push_str(&format!(
                "1000 1.0 clone(child_stack=NULL, flags=SIGCHLD) = {pid}\n"
            ));
        }
        for i in 0..98 {
            seq += 1;
            if i % 7 == 0 {
                text.push_str(&format!("{pid} 1.{seq} openat(AT_FDCWD</w>, \"/w/f{i}\", O_RDONLY) = -1 ENOENT (No such file or directory)\n"));
            } else {
                text.push_str(&format!(
                    "{pid} 1.{seq} openat(AT_FDCWD</w>, \"/w/f{i}\", O_RDONLY) = 3</w/f{i}>\n"
                ));
            }
        }
        text.push_str(&format!("{pid} 2.0 +++ exited with 0 +++\n"));
    }
    let start = std::time::Instant::now();
    let t = normalize_str(&text, NormalizeLimits::default());
    let tree = tracewhy_event::ProcessTree::build(&t.events);
    let elapsed = start.elapsed();
    assert!(t.events.len() > 190_000);
    assert_eq!(tree.process_count(), 2000);
    // Generous bound for unoptimized CI builds; a quadratic pass would take minutes.
    assert!(
        elapsed.as_secs() < 30,
        "normalizing 200k lines took {elapsed:?}"
    );
}
