# Rules, hypotheses, investigators and adapters

Rules are the declarative layer of the engine: they say which hypotheses
could explain an observation and which parts of the system are worth
investigating. Rules never decide the root cause. Every hypothesis kind has
an evaluator in code that scores it against facts; a rule only proposes.

Built-in rules live in `rules/<family>/*.toml` and are embedded into the
binary at build time (`BUILTIN_RULES` in `crates/tracewhy-engine`, module
`rules`). `rules/docker/README.md` is documentation only; Docker hypotheses
are attached to the network rules.

## Rule file format

A rule file contains one or more `[[rule]]` tables. Both the file and each
rule use `deny_unknown_fields`: a misspelled key makes the file (or rule)
invalid.

```toml
[[rule]]
id = "network.connection-refused"        # required, unique, non-empty
description = "A TCP connection was actively refused by the peer."  # optional
observation = "connect_failed"           # required, an observation type
errors = ["ECONNREFUSED"]                # optional; empty = any error code
endpoint = "inet"                        # optional: "inet" or "unix"
protocols = ["tcp"]                      # optional: "tcp", "udp", "unix"
hypotheses = ["service_not_listening"]   # required, hypothesis kinds
investigate = ["port", "docker"]         # optional, investigation target names
```

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Unique rule id. A duplicate id (also against built-ins) is ignored with a warning. |
| `description` | string | Free text. |
| `observation` | string | Observation type the rule applies to (list below). |
| `errors` | list of strings | Error codes that trigger the rule. Empty matches any observation of that type, including ones without an error code. |
| `endpoint` | string | `inet` or `unix`. Only connect/bind observations have an endpoint; other observations never match a rule that sets it. |
| `protocols` | list of strings | `tcp`, `udp`, `unix`. Observations without a protocol count as `other` and never match a non-empty list. |
| `hypotheses` | list of strings | Hypothesis kinds to evaluate (list below). |
| `investigate` | list of strings | Investigation target names (list below). |

Validation (`rules::validate`): `id` must be non-empty, `observation` must be
a known observation type, every hypothesis must be in `KNOWN_HYPOTHESES`,
every target in `KNOWN_TARGETS`, and `endpoint` must be `inet` or `unix`.
Invalid rules and unparsable files are skipped; the warning is included in
the report's `diagnostics`.

## Matching semantics

- A rule matches an observation when the observation type equals
  `observation`, and (if set) its error code is in `errors`, its endpoint
  family equals `endpoint`, and its protocol is in `protocols`.
- All matching rules apply, not just the first. The candidate hypotheses for
  an observation are the union of the `hypotheses` of every matching rule
  (deduplicated); the rule recorded on a hypothesis is the first rule that
  proposed it. Investigation targets are likewise unioned and seed round 0
  of the investigation loop.
- Only observations with relevance >= 0.5 are matched, and only the three
  most relevant ones (see [ARCHITECTURE.md](ARCHITECTURE.md)).
- An evaluator returns nothing when its hypothesis does not apply to the
  observation's specifics. For example `privileged_port` only applies to
  EACCES/EPERM on ports below `net.ipv4.ip_unprivileged_port_start` (1024
  when unknown), and `service_not_listening` only to
  ECONNREFUSED on inet endpoints. Listing a hypothesis in an unrelated rule
  is valid but has no effect.
- Observations produced by runtime adapters (type `runtime`) bypass rule
  hypotheses: the adapter that produced the observation proposes and scores
  them. The built-in `runtime.adapter` rule exists to document this.
  `investigate` entries of a matching rule are still honored, but no target
  name currently maps to anything for a `runtime` observation except
  `network`/`local_addresses` and `privileges`.

## Observation types and their error codes

| Observation type | Error code matched by `errors` |
|---|---|
| `exec_failed` | errno, e.g. `ENOENT`, `EACCES`, `ENOEXEC`, `ETXTBSY` |
| `file_access_failed` | errno, e.g. `ENOENT`, `EACCES`, `EPERM`, `EROFS`, `ENOTDIR`, `ELOOP`, `EISDIR`, `ENAMETOOLONG` |
| `connect_failed` | errno, e.g. `ECONNREFUSED`, `ENETUNREACH`, `EHOSTUNREACH`, `ETIMEDOUT`, `EADDRNOTAVAIL` |
| `bind_failed` | errno, e.g. `EADDRINUSE`, `EACCES`, `EPERM`, `EADDRNOTAVAIL` |
| `dns_failed` | rcode label: `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `FORMERR`, `NOTIMP`, `NOERROR`, `RCODE<n>`; no code when no answer was seen |
| `write_failed` | errno, e.g. `ENOSPC`, `EDQUOT`, `EIO`, `EFBIG`, `EROFS`, `EPIPE`, `ECONNRESET` |
| `resource_limit` | `EMFILE` or `ENFILE` |
| `library_load_failed` | none (a rule with `errors` never matches) |
| `process_crashed` | signal name, e.g. `SIGSEGV`, `SIGKILL` |
| `runtime` | adapter code: `MODULE_NOT_FOUND` (node), `ModuleNotFoundError` (python) |

## Investigation target names

Rules name targets; the engine maps each name to a concrete
`InvestigationTarget` for the observation (`targets_for` in the engine's
`investigate` module). A name that does not fit the observation yields no
target.

| Target name | Applies to | Concrete target | Investigator id |
|---|---|---|---|
| `port` | connect/bind on an inet endpoint | `Port { port, address }` | `port` |
| `docker` | connect/bind | `Docker { port }` | `docker` |
| `local_addresses` | any | `Network` | `network` |
| `network` | any | `Network` | `network` |
| `path` | file access; unix-socket connect; exec of a path containing `/` | `Path { path }` | `path` |
| `elf` | exec of a path containing `/` | `Elf { path }` | `elf` |
| `executable` | exec | `Executable { name }` (basename) | `executable` |
| `filesystem` | file access; exec of a path; write failure (target path, else cwd) | `Filesystem { path }` | `filesystem` |
| `library` | library load | `Library { name, executable }` | `library` |
| `hostname` | DNS failure | `Hostname { name }` | `dns` |
| `fd_limit` | resource limit | `FdLimit` | `fd_limit` |
| `privileges` | any | `Privileges` | `privileges` |

`ContainerLogs { container }` (investigator `docker_logs`) is not available
to rules; hypothesis evaluators request it when a container is known.

The `privileges` investigator records three `property` facts with subject
`current`: `privileges.user` (the user TraceWhy and the command ran as),
`privileges.cap_net_bind_service` (`true`/`false`, from `CapEff` in
`/proc/self/status`) and `privileges.unprivileged_port_start` (from
`/proc/sys/net/ipv4/ip_unprivileged_port_start`). The target is
`Privileges { executable }`; when the failing executable carries a
`security.capability` extended attribute, a fourth fact
`privileges.file_capabilities` (value: the path) is recorded. The built-in
`network.bind-permission` rule requests it. `privileged_port` is refuted
when the process has the capability; when the binary has file capabilities
it explains that Linux ignores them while the program is traced (MEDIUM),
instead of suggesting `setcap`.

## Hypothesis kinds

Every kind rules may reference (`KNOWN_HYPOTHESES`):

- Network: `container_stopped`, `container_not_created`,
  `port_not_published`, `wrong_published_port`, `wrong_interface`,
  `startup_race`, `service_not_listening`, `remote_port_closed`,
  `socket_missing`, `socket_stale`, `socket_permission`,
  `network_unreachable`, `host_unreachable`, `connect_timeout`,
  `no_source_address`, `port_held_by_traced_process`,
  `port_held_by_container`, `port_held_by_process`, `port_held_by_unknown`,
  `port_released`, `privileged_port`, `address_not_local`,
  `hostname_not_found`, `dns_server_failure`, `transient_dns_failure`,
  `broken_pipe`.
- Filesystem: `broken_symlink`, `parent_missing`, `file_missing`,
  `path_exists_now`, `ancestor_not_searchable`, `permission_denied`,
  `operation_not_permitted`, `read_only_filesystem`, `bad_path`,
  `inodes_exhausted`, `disk_full`, `disk_was_full`, `quota_exceeded`,
  `write_device_error`, `fd_limit_reached`, `system_fd_table_full`.
- Process: `missing_interpreter`, `explicit_path_missing`,
  `command_not_in_path`, `is_directory`, `not_executable`, `noexec_mount`,
  `wrong_architecture`, `not_an_executable`, `executable_busy`,
  `killed_by_traced_process`, `process_crashed`, `killed_externally`,
  `library_wrong_architecture`, `library_outside_search_path`,
  `missing_shared_library`.
- Runtime adapters: `adapter` (placeholder that delegates to the adapter).

Adapters report their own kinds, which appear as `root_cause.kind` but cannot
be referenced from rules: `node_module_missing`, `node_module_resolution`,
`node_dependencies_not_installed`, `node_package_not_installed`,
`node_package_not_declared`, `python_import_shadowed`,
`python_venv_not_active`, `python_package_not_installed`,
`python_module_missing`.

## User rules: `TRACEWHY_RULES_DIR`

At startup the engine loads the built-in rules, then every `*.toml` file
directly inside the directory named by `TRACEWHY_RULES_DIR` (not recursive,
in file-name order). User rules can only combine existing observation types,
hypothesis kinds and target names; they cannot override a built-in rule
(duplicate ids are ignored). Problems reading the directory or a file are
reported as diagnostics; they never abort the run.

### Worked example

Goal: when a TCP connection times out, also look at listeners on the port
and at Compose services, not only at routing.

`~/.config/tracewhy-rules/timeout.toml`:

```toml
[[rule]]
id = "local.timeout-check-services"
description = "On connect timeouts, also check the port and Compose services."
observation = "connect_failed"
errors = ["ETIMEDOUT"]
endpoint = "inet"
protocols = ["tcp"]
hypotheses = ["connect_timeout"]
investigate = ["port", "docker"]
```

```sh
TRACEWHY_RULES_DIR=~/.config/tracewhy-rules why -v ./client
```

What happens: the built-in `network.unreachable` rule and this rule both
match an `ETIMEDOUT` connect observation. `connect_timeout` is already
proposed by the built-in rule, so it is not duplicated. The additional
targets `Port` and `Docker` join `Network` in round 0 and are run if the
budget allows. Their facts appear in the verbose output and the `.whytrace`,
and are available to every evaluator. If the rule had a typo (say
`hypothesis = [...]`), the rule would be rejected and a diagnostic would
explain why.

## Choosing an extension point

| You want to... | Add |
|---|---|
| Try existing hypotheses for another error code or observation, or investigate more | A rule (TOML). No code. |
| Recognize a new kind of cause for an existing observation type | A hypothesis evaluator. |
| Know something new about the system | An investigator (and usually a new `FactKind`). |
| Understand a language runtime's own error reporting | A runtime adapter. |
| Observe a new kind of symptom from the trace | A new `ObservationKind` in `tracewhy-core` and extraction in `engine::observe` (rare; discuss first). |

### A new hypothesis evaluator

1. Add the kind to `KNOWN_HYPOTHESES` in the engine's `hypotheses` module.
2. Implement it in the family module (network, filesystem, process, ...):
   match on `(kind, error)` for the observation shape, and return `None`
   when it does not apply. Build an `Eval`: `.fact(id, ctx)` for each
   supporting fact, `.refuted(fact_id)` when a fact contradicts it,
   `.unresolved(score, question, Some(target))` to request an
   investigation, `.supported(score)` when evidence holds, `.step(...)` /
   `.inferred_step(...)` for the causal chain, `.infer(...)` for
   inferences, and `.fix(...)` or `.next(...)` for the suggestion.
3. Reference the kind from a rule in `rules/`.
4. Add a fixture (see [CONTRIBUTING.md](CONTRIBUTING.md)) where it must win,
   and ideally one where it must not.

Score guidance from existing evaluators: unresolved hypotheses that still
need an investigation sit around 0.2-0.6; supported with direct, specific
evidence 0.85-0.95; supported but generic 0.5-0.65. Remember that HIGH
confidence additionally requires a non-trace supporting fact and two
corroborations; do not inflate scores to reach it.

### A new investigator

1. Implement `tracewhy_core::Investigator` (`id`, `supports`, `cost`,
   `investigate`). Read state only; never change the system. Honor
   `ctx.deadline` / `ctx.time_left()` and return
   `InvestigationError::Unavailable` when the environment lacks what you
   need (e.g. a CLI is not installed), `TimedOut` on deadline.
2. Report an honest `InvestigationCost`; set `external_process` if you spawn
   processes.
3. If you need a new target, add an `InvestigationTarget` variant, a name in
   `KNOWN_TARGETS` and a mapping in `targets_for`; or let evaluators request
   it via `wants` only.
4. Register it in the crate's `investigators()` list and in the CLI's
   `engine()` wiring.

### A new runtime adapter

1. Implement `tracewhy_core::RuntimeAdapter`. `detect` should look at the
   process tree (which executables ran). `collect` returns project/runtime
   facts. `observations` must return `ObservationKind::Runtime { adapter,
   code, subject, detail }` and should only fire when both the program's own
   error output and trace evidence agree. `evaluate` returns
   `RuntimeHypothesis` values with fact ids for and against.
2. A runtime hypothesis is `refuted` if it has facts against and none for,
   `supported` if its score is >= 0.5, otherwise `unresolved`.
3. Register it in the CLI's `engine()` wiring and add fixtures.
