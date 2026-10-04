# TraceWhy architecture

TraceWhy answers one question: why did this command fail? `why <command>`
runs the command under a trace backend (strace today), turns raw syscall
records into backend-neutral semantic events, extracts failure symptoms,
proposes candidate explanations, actively checks the system to confirm or
refute them, and reports the best-supported cause with an honest confidence.

The analysis is deterministic and offline. There is no LLM, no network
service and no telemetry. Given the same events and the same facts, the
engine reaches the same conclusion.

## Pipeline

```text
 Command (argv, cwd, env)
    |
    |  preflight: is the program resolvable/executable at all?
    v
 Runtime tracing            TraceBackend (tracewhy-tracer-strace)
    |  strace -f -yy -ttt -s 512 -e trace=<TRACE_SET>
    v
 Raw events                 strace text lines -> parsed syscall records
    |
    v
 Semantic events            Event / EventKind (tracewhy-event)   <-- future
    |                       ProcessTree                              backends
    v                                                               plug in here
 Observations               failure symptoms + relevance scores (engine::observe)
    |                       + runtime observations from RuntimeAdapters
    v
 Hypotheses   <-------->    Investigators (tracewhy-investigator-*)
    ^     rules propose     RuntimeAdapters (tracewhy-adapter-*)
    |     evaluators score  produce Facts (FactStore)
    |
    v
 Ranking                    combined score = hypothesis score x observation relevance
    |
    v
 Root cause + confidence    HIGH / MEDIUM / LOW (engine::explain)
    |
    v
 Explanation                Conclusion + CauseGraph -> text / JSON / .whytrace
```

## Crate map

All crates live under `crates/`. Dependencies point downwards in this list
(roughly): nothing in the event or core layers knows about strace, Docker or
the CLI.

| Crate | Responsibility |
|---|---|
| `tracewhy-event` | Backend-neutral `Event`/`EventKind`, `Errno`, `ExitStatus`, `ProcessTree` (rebuilt from fork/clone/exec/exit events, including the failure-propagation chain), and the `TraceBackend` trait with `CommandSpec`, `BackendInfo`, `BackendCapabilities`, `TraceOutput`, `BackendError`. |
| `tracewhy-core` | The reasoning model: `Observation`, `Relevance`, `Fact`/`FactKind`/`FactSource`/`Freshness`, `Hypothesis`, `RootCause`, `Conclusion`, `Confidence`, `EvidenceRef`. Extension traits `Investigator` and `RuntimeAdapter`, `InvestigationTarget`, `InvestigationRecord`, `EnvSnapshot`, and the resource `Limits`. |
| `tracewhy-graph` | `CauseGraph`: typed nodes and edges, each carrying evidence references; append-only, key-indexed, with a node limit. |
| `tracewhy-tracer-strace` | The Linux `StraceBackend`: strace invocation, line parser, streaming normalizer (thread groups, working directories, a small socket table), DNS wire-format decoder. |
| `tracewhy-engine` | Observation extraction and relevance scoring, rule loading/matching, hypothesis evaluators, the investigation loop, the fact store, ranking, confidence and conclusion/graph construction. |
| `tracewhy-investigator-linux` | Read-only investigators: `port`, `path`, `executable`, `filesystem`, `elf`, `library`, `dns`, `network`, `fd_limit`, `privileges`. |
| `tracewhy-investigator-docker` | `docker` (Compose files, services, container state) and `docker_logs` (container log tail), using the `docker` CLI read-only with timeouts. |
| `tracewhy-adapter-node` | Node.js adapter: package.json, package manager, node_modules; `MODULE_NOT_FOUND` observations. |
| `tracewhy-adapter-python` | Python adapter: interpreter, virtualenvs, manifests; `ModuleNotFoundError` observations. |
| `tracewhy-redact` | Secret and home-directory redaction for every string TraceWhy prints or exports. |
| `tracewhy-format` | The `.whytrace` file: `WhyTrace`, versioning, environment fingerprints, size limit, atomic owner-only writes. See [WHYTRACE_FORMAT.md](WHYTRACE_FORMAT.md). |
| `tracewhy-diff` | Environment, execution and causal diff of two `.whytrace` files (`why diff`). |
| `tracewhy-report` | Terminal renderer (with control-character sanitization), diff renderer and the JSON report `tracewhy.report/v1`. See [docs/json-report.md](docs/json-report.md). |
| `tracewhy-cli` | The `why` binary: argument parsing, preflight, wiring backend + engine + investigators + adapters, `record`/`show`/`explain`/`diff`/`doctor`. |

## Reasoning model

The core crate keeps five concepts apart. Mixing them is the main source of
wrong answers in debugging tools, so the separation is enforced by types.

- **Observation** - a failure symptom seen directly in the trace
  (`connect 127.0.0.1:5432 -> ECONNREFUSED`). It is never a root cause by
  itself. Types: `exec_failed`, `file_access_failed`, `connect_failed`,
  `bind_failed`, `dns_failed`, `write_failed`, `resource_limit`,
  `library_load_failed`, `process_crashed`, `runtime`.
- **Fact** - something known to be true about the system, with a source
  (`trace`, `investigator:<id>`, `adapter:<id>`, `preflight`), a freshness
  (`at_failure` or `after_run`) and a collection confidence (1.0 trace,
  0.95 investigator/preflight, 0.9 adapter). A newer fact with the same
  subject key supersedes an older one; identical facts are deduplicated.
- **Hypothesis** - a candidate explanation for one observation, with a kind
  (e.g. `service_not_listening`), status (`candidate`, `supported`,
  `refuted`, `unresolved`), an internal score in `[0, 1]`, facts for and
  against, and open questions.
- **RootCause** - the selected hypothesis (kind, title, detail, hypothesis id,
  observation id).
- **Conclusion** - the user-facing result: status (`succeeded`,
  `root_cause`, `undetermined`), confidence, failing process, causal chain,
  observed evidence, inferences, suggestions, alternatives, contributing
  factors and a stderr excerpt.

Numeric scores stay internal; users see only HIGH/MEDIUM/LOW.

## Preflight

Before tracing, the CLI checks whether the program can be started: an
explicit path must exist, not be a directory and be executable; a bare name
must resolve on `PATH`. If not, the command is not run at all. The engine
receives a preflight observation with relevance 1.0 and the exit status is
127 (not found) or 126 (not executable), matching shell conventions.

## Trace backend and semantic events

`StraceBackend` runs:

```text
strace -f -yy -ttt -s 512 -e trace=%file,%network,%process,write,writev,pwrite64,fchdir,pipe,pipe2,dup,dup2,dup3 -o <tmp>/trace.strace [--seccomp-bpf] -- <program> <args...>
```

`--seccomp-bpf` is added when the detected strace version is 5.3 or newer.
The trace is written to a private (0700) temporary directory that is removed
afterwards. stdin/stderr are inherited; stdout is inherited, or redirected to
stderr with `--json` so stdout stays machine-readable. While tracing, `why`
ignores SIGINT/SIGQUIT so the traced command handles Ctrl-C itself.

The normalizer turns parsed records into `EventKind` variants: process
spawn/exec/exit/kill, exec failures (including shell PATH search attempts),
file open/open-failed, other path operations that failed (`stat`, `access`,
`mkdir`, `rename`, ...), directory changes, connect (pending, succeeded,
failed), bind/listen, DNS queries and answers, program output on fd 1/2,
failed writes, and other failed syscalls with a diagnostically interesting
errno. Relative paths are resolved against the tracked per-process working
directory.

DNS events come from decoding DNS wire-format packets found in
`sendto`/`sendmsg`/`recvfrom`/`recvmsg` buffers on sockets whose peer port
is 53 (UDP or TCP; the TCP length prefix is handled). The decoder is
bounds-checked and extracts the question name/type and, for responses, the
rcode and A/AAAA answers.

Event volume is bounded: at most `max_semantic_events` events (essential
events - failures, process lifecycle, DNS answers - may exceed this up to 2x);
program output is kept per process up to `max_output_text_bytes`, oldest
chunks dropped first; raw input is read up to `max_raw_trace_bytes`. Drops
set `stats.truncated` and produce diagnostics.

## Relevance scoring and false-positive guards

Most failed syscalls are harmless: search-path probes, optional config files,
fallbacks. `engine::observe` gives every observation a base score by type and
errno (for example ENOENT on open 0.2, EACCES 0.35, ECONNREFUSED on TCP 0.5,
ENOSPC write 0.6, SIGSEGV 0.6; `stat`/`access`/`readlink` failures are halved
as existence checks; a few glibc probe paths such as `/etc/ld.so.preload`
are ignored outright). It then adjusts it with these signals, recorded in
`Relevance`:

| Flag | Meaning | Effect |
|---|---|---|
| `on_failure_chain` | The process is on the chain of processes whose failure propagated to the command's exit status. | +0.1 (+0.05 more for the last process in the chain) |
| `reported_on_stderr` | Later output of the process (or of a process on the chain) names the specific resource (path, host, port, ...). An error-class-only mention ("Connection refused") counts when it is the only failure of that class in the process and the type is connect/bind/DNS/write/resource. | +0.35 (a weaker class-only mention: +0.15) |
| `terminal` | The last failure of its process, the process exited unsuccessfully, and the failure was not recovered or a probe. | +0.1 |
| `recovered` | The same operation later succeeded (same file opened, same port connected/bound, a later successful exec). | score x 0.1 |
| `probe` | ENOENT on a file whose basename was later opened from another directory. | score x 0.1 |
| (process succeeded) | The process exited with status 0 and did not report the failure. | score x 0.3 |

The score is clamped to `[0, 1]` and each adjustment adds a human-readable
reason. Identical repeated symptoms (retry loops) are merged. DNS failures
are grouped under the shortest name the program queried (before search-domain
expansion) and dropped if that name resolved later.

Only observations with relevance >= 0.5 (`CANDIDATE_THRESHOLD`) can become
root-cause candidates, and at most the top three are considered. If the
command succeeded, no hypotheses are generated; notable non-fatal failures
(relevance >= 0.3, not recovered) are listed as contributing items.

The failure chain is computed by `ProcessTree::failure_chain`: starting at
the root, it repeatedly picks the non-thread child that failed before its
parent exited, preferring a child whose exit status matches the parent's and
then the most recent failure.

## Rules, hypotheses and the investigation loop

Rules (TOML, see [RULES.md](RULES.md)) map an observation type and error
code to hypothesis kinds and investigation targets. Rules never decide the
cause; each hypothesis kind has an evaluator in `engine::hypotheses` that
inspects the observation and the fact store and returns a score, status,
supporting/contradicting facts, open questions and the investigation targets
that would answer them. Observations produced by runtime adapters bypass the
rule hypotheses and are evaluated by their adapter.

The loop in `engine::investigate`:

1. Evaluate every candidate hypothesis against the current facts.
2. Stop if investigation is disabled (`--no-investigate`, or `why explain`
   without `--investigate`) or the round limit is reached.
3. Collect wanted targets. Round 0 also includes the targets named by
   matching rules. A target's value is the sum over non-refuted hypotheses
   wanting it of `relevance x uncertainty x max(score, 0.2)`, where
   uncertainty is 1.0 for unresolved and 0.5 for supported hypotheses.
4. Pair each target with every investigator that supports it and has not
   already run on it; rank by `value / cost weight`. Cost weight is
   `1 + expected_millis / 50`, doubled for investigators that spawn external
   processes.
5. Run them in order until the execution or time budget is exhausted; the
   rest are recorded with status `skipped`. Facts are stored with source
   `investigator:<id>` and freshness `after_run`.
6. Next round. If a round produced no new facts, re-evaluate once and stop.

Budgets come from `Limits::default()`:

| Limit | Default |
|---|---|
| `max_investigation_depth` (rounds) | 4 |
| `max_investigations` (executions per run) | 24 |
| `max_investigation_millis` (wall clock, shared deadline) | 8000 |
| `max_docker_log_bytes` | 16 KiB |
| `max_raw_trace_bytes` | 1 GiB |
| `max_semantic_events` | 400 000 |
| `max_output_text_bytes` (per process) | 64 KiB |
| `max_graph_nodes` | 20 000 |

Every execution is recorded as an `InvestigationRecord` (investigator,
target, round, status `completed`/`unavailable`/`failed`/`timed_out`/
`skipped`, duration, fact ids, message).

## Ranking and confidence

Only `supported` hypotheses are ranked, by

```text
combined = hypothesis.score x (0.5 + 0.5 x observation.relevance)
```

If no supported hypothesis reaches a combined score of 0.4, the status is
`undetermined`: TraceWhy names the failing process and up to three possible
contributing factors, but no cause.

Confidence (in `engine::explain`), where `gap` is the winner's combined
score minus that of the best competing supported hypothesis with a different
title that is not a less specific restatement of the winner (all of its
supporting facts are also the winner's, same observation), and
`investigated` is the number of supporting facts not derived from the trace
(investigator, adapter or preflight facts):

- **HIGH** if all hold: hypothesis score >= 0.85; observation relevance
  >= 0.7; `investigated` >= 1; corroborations >= 2, where corroborations =
  `investigated` + (reported on stderr ? 1 : 0) + (terminal ? 1 : 0); no
  contradicting facts; `gap` >= 0.15.
- **MEDIUM** otherwise, if hypothesis score >= 0.55, observation relevance
  >= 0.5 and `gap` >= 0.05.
- **LOW** otherwise.

Consequences:

- A suggestion is presented as a fix only at HIGH; otherwise it is downgraded
  to a next step.
- Up to three alternatives are listed (combined score >= 0.3, different
  title, not a restatement of the winner); each is MEDIUM if its combined
  score is >= 0.6, else LOW, and never higher than the winner's confidence.
- Up to two other observations with relevance >= 0.4 (not recovered, not a
  probe) are listed as possible contributing factors.

## Cause graph

`CauseGraph` (crate `tracewhy-graph`) is stored in every `.whytrace`. Nodes
are keyed (re-adding a key merges evidence) and limited to `max_graph_nodes`;
when the limit is hit, `truncated` is set.

Node kinds: `command`, `process`, `file`, `executable`, `socket`, `port`,
`host`, `container`, `service`, `runtime`, `environment_fact`, `failure`,
`observation`, `fact`, `hypothesis`, `cause`.

Edge kinds: `spawned`, `attempted`, `opened`, `resolved_to`, `connected_to`,
`failed_with`, `caused`, `associated_with`, `defined_by`,
`unavailable_because`, `depends_on`, `corroborates`, `contradicts`,
`explains`.

Not every kind is emitted by the current engine: `container`, `service` and
`runtime` nodes and `opened`, `resolved_to`, `connected_to`, `defined_by`,
`depends_on` edges are defined but unused today. The engine builds:

- the command and process tree (`spawned`);
- observations with relevance >= 0.3: the process `attempted` the
  observation, which is `associated_with` the resource it touched (file,
  socket, port, host, executable or library node);
- every fact, and every hypothesis, which `explains` its observation; facts
  `corroborates` or `contradicts` hypotheses;
- the causal chain of the conclusion: observation `failed_with` a failure
  node, `unavailable_because` environment-fact steps, `caused` the cause
  node. The chain shown to users is read back from this path.

Evidence references (`EvidenceRef`) point back to `{"type":"event","seq":N}`,
`{"type":"observation","id":N}` or `{"type":"fact","id":N}`, so every
statement in a conclusion can be traced to the trace or to an investigation.

## Extension points

- **`TraceBackend`** (`tracewhy-event`): `info()` and
  `run(&CommandSpec) -> TraceOutput`. A backend must emit `Event`s with
  monotonically increasing `seq`, and report its capabilities. Future eBPF,
  ETW (Windows) or macOS backends plug in here, before the semantic event
  layer; nothing downstream depends on strace. Only the strace backend
  exists today.
- **`Investigator`** (`tracewhy-core`): `id`, `supports(target)`,
  `cost(target)`, `investigate(ctx) -> Vec<FactKind>`. Investigators must not
  mutate the system and should respect `ctx.deadline`.
- **`RuntimeAdapter`** (`tracewhy-core`): `id`, `detect`, `collect` (facts),
  `observations` (must be `ObservationKind::Runtime`), `evaluate` (returns
  `RuntimeHypothesis` values). Runtime knowledge stays out of the core engine.
- **Rules**: TOML files combining existing observation types, hypothesis
  kinds and investigation targets, built in or loaded from
  `TRACEWHY_RULES_DIR`.

See [RULES.md](RULES.md) for how to choose between them.

## Re-analysis and diff

`why explain FILE` re-runs the engine over the events stored in a
`.whytrace`. Without `--investigate` it reuses the recorded facts and keeps
the recorded investigation records; with `--investigate` it discards them and
probes the current system again. `why diff GOOD BAD` compares two traces at
three levels: environment (variables, PATH, versions, investigated state),
execution (semantic operations keyed independently of pids and timing,
compared by outcome) and causal (the first relevant operation that succeeded
in the good run and failed in the bad one).
