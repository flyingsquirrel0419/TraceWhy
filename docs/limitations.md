# Limitations

TraceWhy explains failures that leave evidence in system calls, in the
program's own error output, and in the state of the machine. It prefers
saying "undetermined" to guessing. This page lists what it cannot see or
may get wrong.

## Platform and backend

- **Linux only.** The only trace backend is strace. The `TraceBackend`
  abstraction allows eBPF, ETW or macOS backends, but none exist yet.
- **strace is required** and must be able to ptrace the command. Tracing
  fails (exit 124) when `kernel.yama.ptrace_scope` is 3, when a seccomp
  policy forbids ptrace, or inside containers without `CAP_SYS_PTRACE`
  (`docker run --cap-add=SYS_PTRACE`). `why doctor` checks this.
- A command that itself uses ptrace (a debugger, strace) cannot be traced.
- Under ptrace, the kernel does not apply setuid/setgid bits for an
  unprivileged tracer, so setuid programs (for example `sudo`) can behave
  differently than without TraceWhy.

## Tracing overhead and coverage

- strace slows syscall-heavy programs considerably. `--seccomp-bpf` is used
  when strace is 5.3 or newer, which reduces but does not remove the cost.
  Timing-dependent failures (races, timeouts, startup ordering) may change
  or disappear under tracing.
- Only these syscalls are traced: `%file`, `%network`, `%process`, `write`,
  `writev`, `pwrite64`, `fchdir`, `pipe`, `pipe2`, `dup`, `dup2`, `dup3`.
  Failures that never surface as a failed syscall from those classes (logic
  errors, wrong output, a non-zero exit after a successful run, memory
  corruption before a crash) usually end as `undetermined` or as a bare
  crash.
- strace's string limit is 512 bytes (`-s 512`): longer writes, paths and
  DNS packets are truncated. Program output is kept up to 64 KiB per process
  (oldest chunks dropped first), and only for writes to fd 1/2 that go to a
  terminal, pipe, socket or `/dev/null` and look like text. A program that
  logs its errors to a file gives TraceWhy no "reported on stderr" signal.
- Large traces are bounded (1 GiB of raw strace output, 400 000 semantic
  events, 20 000 graph nodes). When limits are hit, `stats.truncated` is set
  and the analysis may be incomplete.
- At most the three most relevant observations are considered as
  candidates for the root cause.
- Processes started by the command that detach (double-fork daemons) are
  traced, but the failure-propagation chain only follows children whose
  failure plausibly caused their parent's exit status.

## Investigations happen after the run

Investigators probe the system after the command finished. State can change
in between: a service may start, a file may be created, a disk may be freed,
a DNS record may appear. Facts from investigators are marked
`"freshness": "after_run"`. A few hypotheses model change explicitly
(`path_exists_now`, `port_released`, `disk_was_full`,
`transient_dns_failure`); elsewhere the engine assumes the state it finds is
the state that caused the failure.

Investigations also run as the user running `why`, in `why`'s namespaces,
with `why`'s view of `/proc`:

- The `port` investigator reads `/proc/net/tcp` and `/proc/net/tcp6` only:
  UDP listeners are not checked, and services in another network namespace
  (a container) are invisible except through Docker.
- The `fd_limit` investigator reports the `RLIMIT_NOFILE` of the `why`
  process, not of the failing process; a script that changed its own limit
  (`ulimit -n`) is not reflected. The conclusion therefore only states the
  limit inherited from the shell and that the program may set a lower one.
- The `privileges` investigator reads the process capabilities of the `why`
  process (`/proc/self/status`), which the traced command inherits. The
  kernel does not grant *file* capabilities (`setcap`) to a program traced by
  an unprivileged tracer, so such a binary can fail to bind a privileged port
  only under `why`. TraceWhy detects the `security.capability` attribute on
  the failing executable and says so (MEDIUM confidence) rather than
  suggesting `setcap`.
- Owners of sockets held by other users' processes are usually not visible
  without root; such ports are reported as held by an unknown process.
- Results depend on the time budget (8 s total, 24 investigations, 4
  rounds by default). Skipped investigations are listed with status
  `skipped`.

`--no-investigate` disables the investigation loop; conclusions then rest
only on trace evidence and, usually, lower confidence.

## Environment variables

TraceWhy does not blame an environment variable unless an investigator or
adapter ties it to evidence (for example, the Python adapter comparing the
interpreter that ran with the project's virtualenv). It records the
environment of the `why` process, not variables a script changes before
starting a child. Environment values are not stored in `.whytrace` files
except for an allowlist (see [../WHYTRACE_FORMAT.md](../WHYTRACE_FORMAT.md)).

## DNS

- DNS failures are seen only when the program sends DNS wire-format
  queries to port 53 itself (UDP or TCP) and the packets fit in the traced
  buffers. Lookups done elsewhere are invisible as DNS events: through nscd,
  through systemd-resolved via the `resolve` NSS module (D-Bus/varlink
  rather than port 53), DNS-over-TLS/HTTPS, a resolver in another process,
  or `/etc/hosts`.
- Failures are grouped under the shortest name the program queried, which
  is meant to be the name before search-domain expansion. For single-label
  names, the resolver may try search-domain-expanded names first; if the
  bare name was never sent, the reported hostname is an expanded one.
- The `dns` investigator re-resolves the name with the system resolver
  (`getaddrinfo`), which follows `nsswitch.conf` (hosts file, mDNS, caches).
  "Resolves now" can therefore disagree with what the program's own DNS
  traffic saw, and caches may hide or reproduce a transient failure.
- `hostname_not_found` requires an NXDOMAIN answer in the trace. Other
  rcodes or missing answers lead to weaker hypotheses.

## Docker and Compose

- The Docker investigators need the `docker` CLI and access to the daemon.
  If either is missing, Docker evidence is simply absent.
- Compose files are discovered from `COMPOSE_FILE`, else as `compose.yaml`,
  `compose.yml`, `docker-compose.yaml` or `docker-compose.yml` in the working
  directory and up to six parent directories, stopping at a directory that
  contains `.git`. Compose files elsewhere are not discovered, although a
  running container that publishes the port is still found through
  `docker ps`.
- Without a working `docker compose`, a minimal built-in YAML reader
  extracts services, images, ports, `expose` and healthchecks; anchors,
  extends, includes and interpolation are not supported.
- Only the last 30 log lines (at most 16 KiB) of a container are read.

## Runtime adapters

- Only Node.js (`Cannot find module` / `MODULE_NOT_FOUND`) and Python
  (`ModuleNotFoundError`) have runtime adapters. Other runtimes are analyzed
  only through generic syscall evidence.
- Adapters run the traced interpreter with `--version` (2-second timeout)
  to record its version, only when investigation is enabled.

## Re-analysis of stored traces

- `why explain` works on the redacted data stored in the file: paths under
  `$HOME` appear as `~/...`, other users' home directories as
  `/home/<user>`, and redacted values as `<redacted>`.
- `why explain` without `--investigate` reasons only from the recorded
  events and facts; nothing on the current machine is read.
- `why explain --investigate` probes the current machine using the recorded
  environment, which holds values only for allowlisted variables (`PATH`,
  `VIRTUAL_ENV`, `LD_LIBRARY_PATH`, ...); other variables are missing.

## Hypotheses without an end-to-end fixture

The fixture corpus (37 scenarios in `fixtures/`) does not yet exercise the
following implemented hypothesis kinds end to end. Their evaluators exist
and are reviewed, but conclusions naming them have less real-world
validation:

`noexec_mount`, `wrong_architecture`, `not_an_executable`,
`executable_busy`, `quota_exceeded`, `write_device_error`,
`dns_server_failure`, `transient_dns_failure`, `network_unreachable`,
`host_unreachable`, `connect_timeout`, `no_source_address`,
`socket_stale`, `socket_permission`, `address_not_local`,
`container_not_created`, `port_not_published`, `wrong_published_port`,
`port_held_by_traced_process`, `port_held_by_unknown`, `port_released`,
`killed_externally`,
`library_wrong_architecture`, `ancestor_not_searchable`,
`operation_not_permitted`, `bad_path`, `path_exists_now`, `broken_pipe`,
`system_fd_table_full`.

`startup_race`, `remote_port_closed` and the suggestions for crashed
containers are covered by engine unit tests
(`crates/tracewhy-engine/tests/engine.rs`) rather than fixtures.

## Other

- While a command is being traced, `why` ignores SIGINT and SIGQUIT; Ctrl-C
  goes to the traced command, which decides whether to exit.
- The exit statuses 124, 125, 126, 127 and 2 can be produced either by
  TraceWhy or by the command; see [exit-codes.md](exit-codes.md).
- Redaction is pattern-based and can miss secrets; see
  [../SECURITY.md](../SECURITY.md).
