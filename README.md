# TraceWhy

**Understand why a command failed.**

```text
$ why npm run dev
TraceWhy
────────────────────────────────────────
✗ npm run dev
  exited with code 1 after 158ms

Root cause
  PostgreSQL isn't running.
  Container "demo-postgres-1" for service "postgres" is exited (exit code 0).

Evidence
  node server.js
         │
         └─ connect 127.0.0.1:5432
                       │
                       └─ ECONNREFUSED
                                │
                                └─ no listener
                                        │
                                        └─ demo-postgres-1 container exited

Observed
  ✓ Connection to 127.0.0.1:5432 was refused (ECONNREFUSED)
  ✓ The program reported: "Error: connect ECONNREFUSED 127.0.0.1:5432"
  ✓ No process is listening on port 5432
  ✓ compose.yaml defines services: postgres
  ✓ Container "demo-postgres-1" is exited (exit code 0)

Inference
  The program connected to 127.0.0.1:5432, which compose.yaml publishes for service "postgres"; it appears to depend on that service.
  The failure propagated: node /usr/bin/npm run dev → sh -c node server.js → node server.js.

Confidence
  HIGH

Suggested fix
  docker compose up -d postgres
  Start the postgres service
────────────────────────────────────────
1,122 system events → 10 facts → 1 root cause
```

This is real output (one inference line trimmed for width); the scenario is
[`fixtures/docker-container-exited`](fixtures/docker-container-exited) and runs in CI.

*Evidence-driven debugging. Debug the system, not the error message.*

## Why TraceWhy?

`ECONNREFUSED`, `ENOENT` and `EACCES` are symptoms, not causes. The same
`ECONNREFUSED` can mean the service never started, its container crashed, it
listens on another interface, the port isn't published, or it simply wasn't
ready yet. Reading the log tells you *what* failed; TraceWhy tells you *why*.

TraceWhy runs your command, observes what it actually did at the system level,
then **investigates**: who listens on that port, which compose service publishes
it, what state its container is in, whether the file's parent directory
exists, which user lacks which permission bit, where the dynamic loader
searched. It names a cause only when the evidence supports it, separates what
it observed from what it inferred, and says how confident it is.

- **Precision over recall.** When the evidence is thin, TraceWhy says
  "not determined" or "possible cause" instead of guessing. A missing optional
  `.env` file in a run that failed for another reason is not blamed.
- **Deterministic and offline.** No LLM, no network, no account, no telemetry.
- **Private by default.** Tokens, passwords, credentials in URLs and home
  directories are redacted from every report and every exported trace.

It is not a log analyzer, not an `strace` pretty-printer, and not an
observability agent.

## How it works

```text
command ──▶ strace ──▶ raw syscalls ──▶ semantic events ──▶ observations
                                                               │
             ┌─────────────────────────────────────────────────┘
             ▼
        hypotheses ◀──▶ investigators (ports, PATH, filesystem, DNS,
             │          shared libraries, Docker) + runtime adapters (Node, Python)
             ▼
   ranked hypotheses ──▶ root cause + confidence ──▶ explanation + cause graph
```

1. **Trace** — the command runs under `strace -f`; output is normalized into
   backend-neutral events (exec, open, connect, bind, DNS answers decoded from
   the wire, process lifecycle, stderr).
2. **Observe** — failed operations become observations, each scored for
   relevance: was it recovered from, was it a search-path probe, was it the last
   failure before the process died, did the program report it, is the process on
   the failure path (`npm → sh → node`)?
3. **Hypothesize** — declarative [rules](RULES.md) map each observation to
   candidate explanations.
4. **Investigate** — investigators gather new evidence, cheapest and most
   informative first, within depth, count and time budgets.
5. **Conclude** — hypotheses are scored against supporting and contradicting
   facts; confidence is HIGH only with direct evidence, independent
   corroboration and no close rival.

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

## Installation

Requirements: Linux (x86_64 or aarch64) and `strace` (`sudo apt install strace`,
`sudo dnf install strace`, `sudo apk add strace`). Docker is optional.

From source (Rust 1.85+):

```sh
git clone https://github.com/flyingsquirrel0419/TraceWhy
cd TraceWhy
cargo install --path crates/tracewhy-cli --locked
```

Prebuilt binaries for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`,
with SHA-256 checksums, are attached to each GitHub release.

Check your environment:

```text
$ why doctor
TraceWhy 1.0.0
✓ platform         linux x86_64
• kernel           6.8.0-142-generic
✓ strace           strace 6.8 (/usr/bin/strace)
✓ process tracing  works
✓ ptrace_scope     1 (TraceWhy traces its own children, which works with 0–2)
• docker           available
• compose          available

Ready.
```

In containers, process tracing needs `--cap-add=SYS_PTRACE`.

## Examples

Put `why` in front of any command. Arguments are passed through untouched,
and the command's exit status is preserved:

```sh
why npm run dev
why cargo run
why python app.py "hello world"
why ./server --port 8080
why env DEBUG=1 node server.js
why npm run dev -- --port 3000
```

What it explains today. The most common causes in every family have an
end-to-end fixture in [`fixtures/`](fixtures) (37 scenarios, run in CI); causes
implemented without an end-to-end fixture yet are listed in
[docs/limitations.md](docs/limitations.md).

| Family | Root causes |
|---|---|
| Process | command not on PATH (shell or direct), missing `#!` interpreter or ELF loader, not executable, `noexec` mount, wrong architecture, invalid executable format, crash by signal, killed by another process |
| Filesystem | missing file, missing parent directory, broken symlink, permission denied (with mode/owner/user), unsearchable directory, read-only filesystem, disk full, inodes exhausted, quota, too many open files |
| Network | nothing listening, service listening on another interface, startup race, remote port closed, port already in use (with the holder's pid/command), privileged port, address not local, NXDOMAIN / DNS server failure, unreachable network/host, missing or stale Unix socket |
| Dynamic libraries | library not installed, library outside the loader search path, wrong-architecture library |
| Docker | compose service's container stopped/exited/crashed/restarting, not created, port not published, published on a different host port, port held by a container |
| Node.js / Python | dependencies not installed, package not declared, virtualenv not active, module not installed |

Options: `-v/--verbose` (observations, hypotheses, investigations, facts),
`--json` (stable machine-readable report, see [docs/json-report.md](docs/json-report.md)),
`--no-investigate`, `--color auto|always|never` (`NO_COLOR` is honored),
`-o FILE` (also save a `.whytrace`). Exit codes: the traced command's own
status; `124` unsupported environment; `125` TraceWhy internal error; `2` usage
error ([docs/exit-codes.md](docs/exit-codes.md)).

## `why diff`

Record a working and a broken run, then ask what actually differs:

```sh
why record -o good.whytrace python3 client.py     # on the machine where it works
why record -o bad.whytrace  python3 client.py     # where it doesn't
why diff good.whytrace bad.whytrace
```

```text
TraceWhy Diff
────────────────────────────────────────
WORKING (exit 0)              BROKEN (exit 1)

Environment
env:DB_HOST
  (value A)                   (value B, differs)

Execution
dns:db.invalid
  not reached                 NXDOMAIN
exit:python3
  exited with code 0          exited with code 1

Causal divergence
WORKING
db.invalid
   ↓
not looked up in the working run
   ↓
TCP connect 127.0.0.1:54329
   ↓
success
BROKEN
db.invalid
   ↓
NXDOMAIN
   ↓
db.invalid does not resolve

Likely difference
  db.invalid cannot be resolved in the broken environment. Possibly related: environment variable DB_HOST differs between the runs.

Confidence: HIGH
────────────────────────────────────────
244 raw differences → 4 semantic differences → 2 relevant differences → 1 causal divergence
```

The diff works at three levels — environment, execution (operations keyed
independently of pids and timing) and causal (the first relevant operation that
succeeded in one run and failed in the other) — and down-weights noise such as
procfs, temp files and locale probes. `why show FILE` prints a recorded
conclusion; `why explain FILE` re-runs the analysis on it. The format is
documented in [WHYTRACE_FORMAT.md](WHYTRACE_FORMAT.md) with a
[JSON Schema](schemas/whytrace-v1.schema.json).

## Privacy

- Everything runs locally. Nothing is uploaded; there is no telemetry.
- Reports, JSON output and `.whytrace` files are redacted by default: API
  tokens (GitHub, OpenAI, Anthropic, AWS, Slack, Stripe, Google, npm, JWTs),
  `Authorization`/Bearer values, URL passwords, sensitive query parameters,
  `--password VALUE`-style arguments, `KEY=secret` pairs, private keys,
  long high-entropy strings and home directories.
- Environment variable values are not recorded except for a small allowlist
  (PATH, LANG, ...). Other non-secret names get a short fingerprint so `why diff`
  can tell "changed" from "same".
- `.whytrace` files are written with mode `0600`. Exporting unredacted data
  requires `--unsafe-no-redact`.

Redaction is pattern-based and cannot be perfect; review a trace before
sharing it. See [SECURITY.md](SECURITY.md).

## Architecture

A Rust workspace of small crates: `tracewhy-event` (semantic events, process
tree, backend trait), `tracewhy-tracer-strace`, `tracewhy-core` (observations,
facts, hypotheses, extension traits), `tracewhy-engine` (rules, relevance,
hypotheses, investigation loop, confidence), `tracewhy-graph`,
`tracewhy-investigator-linux`, `tracewhy-investigator-docker`,
`tracewhy-adapter-node`, `tracewhy-adapter-python`, `tracewhy-redact`,
`tracewhy-format`, `tracewhy-diff`, `tracewhy-report` and `tracewhy-cli`.
Everything after the semantic event layer is backend-independent, so eBPF,
ETW or macOS backends can be added without touching the engine.

Performance on this repository's benchmark
(`cargo run --release -p tracewhy-tracer-strace --example bench`): about
1.4 million strace lines per second, linear in trace size. A typical
`why npm run dev` adds roughly 0.3 s, most of it Docker investigation
(`--no-investigate` skips it).

## Contributing

Rules, investigators and runtime adapters are designed to be added without
touching the core. Every bug fix comes with a fixture. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [RULES.md](RULES.md).

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Roadmap

- More investigators (TLS certificates, Redis/MySQL readiness, cgroup OOM kills)
- More runtime adapters (Go, Java, Ruby) and Node native-module checks
- eBPF backend for lower overhead; macOS and Windows backends
- `why last` (explain the previous shell command)
- Optional natural-language rendering of the evidence package by an LLM,
  which may only restate evidence, never add to it

Limitations are listed in [docs/limitations.md](docs/limitations.md).

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
