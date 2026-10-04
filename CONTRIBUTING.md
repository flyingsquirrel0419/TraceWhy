# Contributing to TraceWhy

TraceWhy's value is that its answers can be trusted. Contributions are judged
first on whether they keep conclusions correct and evidence-backed, then on
coverage.

## Build and test

Requirements: Rust 1.85 or newer (workspace `rust-version`), Linux, and
`strace` for the end-to-end fixture tests.

```sh
cargo build --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

All four must pass before a change is merged. Useful variants:

```sh
# Run a single fixture end to end
TRACEWHY_FIXTURE=connection-refused cargo test -p tracewhy-cli --test fixtures -- --nocapture

# Fail instead of skipping fixtures whose requirements are missing
TRACEWHY_REQUIRE_ALL=1 cargo test -p tracewhy-cli --test fixtures -- --nocapture
```

`rustfmt.toml` sets `max_width = 100`.

## Principles

**Precision over recall.** A wrong root cause stated confidently is worse
than "undetermined". When in doubt, lower the score, leave the hypothesis
unresolved, or let the conclusion be undetermined. Every new hypothesis needs
a reason it can be refuted, and HIGH confidence must stay reserved for
causes with direct evidence plus independent corroboration (see the
confidence rules in [ARCHITECTURE.md](ARCHITECTURE.md)).

**Evidence, not guesses.** Every statement in a conclusion must be backed by
an event, an observation or a fact (`EvidenceRef`). Inferred chain steps are
marked `inferred`. Do not add explanations that rely only on heuristics about
names or common setups.

**Determinism.** The engine must reach the same conclusion from the same
events and facts. Avoid ordering that depends on hash iteration, time, or
randomness; break ties explicitly.

**Offline and local.** No network calls to external services, no telemetry,
no LLMs. Investigators read local state only.

**Investigators are read-only.** They may read files, `/proc`, and run
read-only CLI queries with timeouts; they must never change system state.

## Every bug gets a fixture

Any behavior change or bug fix must come with a fixture that fails before
the change and passes after it. False-positive fixes need a fixture where the
wrong cause must *not* be named (`forbidden_root_causes`, or
`"status": "undetermined"`).

### Fixture format

A fixture is a directory `fixtures/<name>/` containing `expected.json` and
any files the scenario needs (scripts, `compose.yaml`, `package.json`, ...).

```json
{
  "description": "Connecting to a local port with no listener.",
  "requires": ["python3"],
  "command": ["python3", "client.py"],
  "env": { "SOME_VAR": "value" },
  "as_user": "nobody",
  "expect": {
    "status": "root_cause",
    "root_cause": "service_not_listening",
    "minimum_confidence": "high",
    "exit_code": 1,
    "required_evidence": ["ECONNREFUSED", "No process is listening on port 47913"],
    "forbidden_root_causes": ["file_missing"],
    "forbidden_output": ["hunter22pw"]
  }
}
```

| Key | Meaning |
|---|---|
| `description` | What the scenario proves. |
| `requires` | Preconditions; the fixture is skipped if one is missing. A tool name checks `PATH`. Special values: `root` and `mount` (running as uid 0), `docker` (CLI, daemon and Compose plugin), `docker-image:<ref>` (image present locally), `port-free:<n>` (port bindable on 127.0.0.1 and 0.0.0.0), `dns-nxdomain` (`probe.tracewhy.invalid` does not resolve). `strace` is always required. |
| `command` | argv passed to `why --json -- <command>`. |
| `env` | Extra environment variables for the run. |
| `as_user` | `"nobody"` runs `why` via `setpriv --reuid=65534 --regid=65534 --clear-groups` (requires `setpriv`). |
| `expect.status` | `succeeded`, `root_cause` or `undetermined`. |
| `expect.root_cause` | Expected `root_cause.kind`. |
| `expect.minimum_confidence` | `low`, `medium` or `high`; higher is accepted. |
| `expect.exit_code` | Expected exit status of `why`. |
| `expect.required_evidence` | Substrings that must appear in the evidence, inferences, contributing items, chain labels, or root-cause title/detail. |
| `expect.forbidden_root_causes` | Kinds that must not be the root cause. |
| `expect.forbidden_output` | Strings that must not appear in the JSON report, the text report, the `why record` report, the `.whytrace` file, or `why show` output. The traced program's own output is excluded from the check. |

How the harness (`crates/tracewhy-cli/tests/fixtures.rs`) runs a fixture:

1. Copy the directory to a temporary working directory.
2. Run `setup.sh` with `sh` in that directory, if present; a failure fails
   the fixture.
3. Run the real `why` binary with `--json` and check the semantic result.
   Assertions are about kinds, confidence, exit status and evidence
   substrings, never exact report text.
4. Run `cleanup.sh` if present (its result is ignored) and delete the
   working directory.

Keep fixtures small, self-contained and fast. Prefer `python3`, `sh` or a
tiny C program built in `setup.sh` (requires `gcc`) over heavy dependencies.
Use high, unusual port numbers so fixtures do not collide with real services.

Parser regressions can also be covered with captured strace output in
`crates/tracewhy-tracer-strace/tests/corpus/` (sanitize paths and user names
before committing).

## Code rules

- **No `unwrap`, `expect` or `panic!` in production code.** The workspace
  denies `clippy::unwrap_used`, `clippy::expect_used` and `clippy::panic`;
  `clippy.toml` allows them in tests only. TraceWhy runs on arbitrary,
  possibly hostile traces and files; malformed input must degrade into a
  diagnostic, never a crash.
- `unsafe_op_in_unsafe_fn` is denied. Keep `unsafe` confined to thin,
  documented libc wrappers (the `sys` modules).
- Bounds-check all parsing (strace lines, DNS packets, ELF headers, `/proc`
  tables, Compose files). Respect the `Limits`.
- Keep runtime knowledge in adapters and system knowledge in investigators;
  the engine stays generic.
- Keep source files reasonably small; split modules rather than growing
  very large files.
- Every string that reaches the terminal goes through the report's
  sanitizer; every exported string goes through the redactor. Do not bypass
  either.

## Dependency discipline

The workspace depends on a deliberately small set of crates, declared once
in `[workspace.dependencies]`: `serde`, `serde_json`, `thiserror`, `regex`
(default features off), `libc`, and `toml` (parser only). There is no async
runtime, no HTTP client and no CLI framework.

New dependencies need a strong justification (security-sensitive parsing,
substantial correctness gain) and must be added at the workspace level,
with minimal features. Prefer a small, well-tested local implementation for
narrow needs (the DNS decoder and ELF reader are examples).

## Pull requests

- One logical change per PR, with its fixture(s).
- Describe the failure scenario, what TraceWhy said before, and what it says
  now.
- If you change rules, hypothesis scores or confidence logic, run the full
  fixture corpus with `TRACEWHY_REQUIRE_ALL=1` on a machine that satisfies
  the requirements, and say which fixtures you could not run.
- Changes to the `.whytrace` format or the JSON report must follow the
  compatibility policies in [WHYTRACE_FORMAT.md](WHYTRACE_FORMAT.md) and
  [docs/json-report.md](docs/json-report.md).
