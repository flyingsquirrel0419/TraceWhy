# The `.whytrace` format

A `.whytrace` file is a portable, versioned JSON record of one run: the
command and its environment fingerprint, the process tree, semantic events,
observations, facts, investigations, hypotheses, the cause graph and the
conclusion. It is produced by `why record` or `why -o FILE <command>`, and
consumed by `why show`, `why explain` and `why diff`.

The Rust definition is `WhyTrace` in `crates/tracewhy-format`. A JSON
Schema lives in `schemas/` (`schemas/whytrace-v1.schema.json`).

## Identification and versioning

| Field | Value |
|---|---|
| `format` | Always `"whytrace"`. Files without it are rejected. |
| `format_version` | Integer, currently `1`. |
| `tracewhy_version` | Version of the TraceWhy that wrote the file (informational). |

Compatibility policy (as implemented by `WhyTrace::from_json`):

- A reader accepts any file whose `format_version` is between 1 and its own
  `FORMAT_VERSION`. Version 0 and newer versions are rejected with
  "uses format version N; this TraceWhy supports up to M. Upgrade TraceWhy."
- Unknown object fields are ignored; missing optional fields take defaults.
- A breaking change bumps `format_version`.

Caveat: tagged enums (`events[].kind.type`, `facts[].kind.type`,
`observations[].kind.type`, `investigations[].target.type`, ...) are
deserialized strictly. A file containing a variant unknown to the reader
fails to load. New variants must therefore be treated as a breaking change,
or introduced together with a version bump.

## Top-level fields

| Field | Required | Description |
|---|---|---|
| `format` | yes | `"whytrace"` |
| `format_version` | yes | `1` |
| `tracewhy_version` | yes | Writer version string |
| `run` | yes | See below |
| `environment` | no | Environment fingerprint, see below |
| `process_tree` | no | `{ "root": pid?, "processes": { "<pid>": ProcessInfo } }` |
| `events` | no | Semantic events, ordered by `seq` |
| `observations` | no | Failure symptoms with relevance, sorted by relevance; `id` is the index |
| `facts` | no | Facts; `id` is the index |
| `graph` | no | Cause graph `{ nodes, edges, truncated }` |
| `investigations` | no | Investigation audit records |
| `hypotheses` | no | Evaluated hypotheses |
| `conclusion` | yes | The conclusion (only `status` is mandatory inside it) |
| `stats` | no | Trace statistics |
| `redactions` | no | Redaction metadata, see below |
| `diagnostics` | no | Non-fatal problems (`{ "line": N?, "message": "..." }`), including rule-loading warnings |

### `run`

| Field | Description |
|---|---|
| `command` | argv as typed by the user |
| `cwd` | Working directory |
| `platform`, `arch` | `std::env::consts::OS` / `ARCH` of the recording host |
| `kernel` | Contents of `/proc/sys/kernel/osrelease`, if readable |
| `started_at` | Unix time in seconds (float) |
| `duration_ms` | Wall-clock duration of the traced run (0 when preflight prevented the run) |
| `exit` | `{"type":"exited","code":N}` or `{"type":"killed","signal":"SIGSEGV","core_dumped":bool}`; absent if unknown |
| `backend` | `{ "name": "strace", "version": "...", "capabilities": { "processes", "files", "network", "dns_payloads", "output_capture", "timestamps" } }`; absent when the command was never run |

### `events[]`

```json
{ "seq": 42, "ts": 1700000000.123, "pid": 1234, "tgid": 1230,
  "source": { "backend": "strace", "line": 97 },
  "kind": { "type": "connect_failed",
            "endpoint": { "family": "inet", "address": "127.0.0.1", "port": 5432 },
            "protocol": "tcp", "error": "ECONNREFUSED" } }
```

`ts`, `tgid` and `source` are optional. `kind.type` is one of:
`process_spawned`, `process_exec`, `exec_failed`, `process_exited`,
`process_killed`, `signal_received`, `signal_sent`, `file_opened`,
`file_open_failed`, `path_op_failed`, `changed_directory`,
`connect_pending`, `connected`, `connect_failed`, `bound`, `bind_failed`,
`listening`, `dns_query`, `dns_answer`, `output`, `write_failed`,
`syscall_failed`. Errnos are strings (`"ENOENT"`); endpoints are
`{"family":"inet","address":...,"port":...}` or `{"family":"unix","path":...}`.

`output` events hold program text written to stdout/stderr, truncated by
strace's string limit (512 bytes per call) and kept up to 64 KiB per process.

### `stats`

`raw_lines`, `raw_bytes`, `raw_events`, `semantic_events`,
`dropped_events`, `unparsed_lines`, `processes`, `truncated`.

## Environment fingerprint

`environment` records what the environment looked like without storing
secret values:

| Field | Description |
|---|---|
| `variables` | Every environment variable name. The value is recorded only for the allowlist below; all other names map to `null`. |
| `fingerprints` | For names that are neither allowlisted nor secret-looking: an 8-hex-digit fingerprint of the value, so `why diff` can tell "changed" from "same". |
| `path_dirs` | `PATH` split on `:` |
| `user` | Value of `USER` |
| `uid` | Effective uid of the `why` process |

Allowlisted values (`SAFE_ENV_VALUES`): `PATH`, `SHELL`, `TERM`, `LANG`,
`LC_ALL`, `LC_CTYPE`, `TZ`, `CI`, `NODE_ENV`, `NODE_OPTIONS`,
`VIRTUAL_ENV`, `CONDA_DEFAULT_ENV`, `PYTHONPATH`, `PYTHONHOME`,
`LD_LIBRARY_PATH`, `LD_PRELOAD`, `GOPATH`, `CARGO_HOME`,
`RUSTUP_TOOLCHAIN`, `JAVA_HOME`, `DOCKER_HOST`, `COMPOSE_FILE`,
`COMPOSE_PROJECT_NAME`, `HOSTALIASES`, `RES_OPTIONS`, `LOCALDOMAIN`, `PWD`,
`HOME`, `USER`. These values still pass through redaction when written.

Secret-looking names are never fingerprinted: any name containing (case
insensitive) `PASS`, `SECRET`, `TOKEN`, `KEY`, `CREDENTIAL`, `AUTH`,
`COOKIE`, `SESSION`, `PRIVATE`, `SIGNATURE`, `DSN`, `_URL` or `URI`.

The fingerprint is FNV-1a (64-bit) over `name`, a NUL byte and `value`,
truncated to the high 32 bits. It is not a cryptographic hash: a short or
guessable value (`1`, `true`, a port number) can be recovered by brute
force. Only the name-based filter above keeps secrets out of it.

## Redaction metadata

```json
"redactions": { "applied": true, "counts": { "github_token": 1, "cli_flag": 1, "home_dir": 3 } }
```

When a file is written with redaction (the default), every string value and
object key in the document passes through the redactor before
serialization, and `counts` records how many replacements each rule made.
When written with `--unsafe-no-redact`, the field is
`{"applied": false, "counts": {}}` and `why` prints a warning. See
[SECURITY.md](SECURITY.md) for the rules and their limits.

Redaction happens at write time; the in-memory analysis uses unredacted
data. A redacted file is therefore not byte-for-byte what the engine saw,
which matters for `why explain` (paths under `$HOME` become `~/...`).

## Size limit and file permissions

- Readers refuse files larger than `MAX_FILE_BYTES` = 512 MiB.
- Files are written atomically: the JSON is written to a uniquely named
  hidden temporary file next to the target (`.<name>.<pid>-<nanos>.tmp`),
  created exclusively (`O_EXCL`, `O_NOFOLLOW`) with mode `0600`, synced, then
  renamed over the target; the temporary file is removed on failure. A newly created `.whytrace` is therefore readable only by its
  owner.
- Without `-o`, `why record` writes `tracewhy-<unix-seconds>.whytrace` in the
  current directory.

## Example skeleton

```json
{
  "format": "whytrace",
  "format_version": 1,
  "tracewhy_version": "1.0.0",
  "run": {
    "command": ["python3", "client.py"],
    "cwd": "~/project",
    "platform": "linux",
    "arch": "x86_64",
    "kernel": "6.8.0",
    "started_at": 1700000000.0,
    "duration_ms": 41,
    "exit": { "type": "exited", "code": 1 },
    "backend": { "name": "strace", "version": "6.8",
                 "capabilities": { "processes": true, "files": true, "network": true,
                                   "dns_payloads": true, "output_capture": true,
                                   "timestamps": true } }
  },
  "environment": {
    "variables": { "PATH": "/usr/local/bin:/usr/bin:/bin", "DATABASE_HOST": null },
    "fingerprints": { "DATABASE_HOST": "1a2b3c4d" },
    "path_dirs": ["/usr/local/bin", "/usr/bin", "/bin"],
    "user": "alice",
    "uid": 1000
  },
  "process_tree": { "root": 1234, "processes": { "1234": {
    "pid": 1234, "executable": "/usr/bin/python3", "args": ["python3", "client.py"],
    "exit": { "type": "exited", "code": 1 }, "first_seq": 0, "last_seq": 87, "children": [] } } },
  "events": [ "..." ],
  "observations": [ { "id": 0, "kind": { "type": "connect_failed", "...": "..." },
                      "pid": 1234, "events": [61],
                      "relevance": { "score": 1.0, "on_failure_chain": true,
                                     "reported_on_stderr": true, "recovered": false,
                                     "probe": false, "terminal": true, "reasons": ["..."] } } ],
  "facts": [ { "id": 0, "kind": { "type": "port_listeners", "port": 5432, "listeners": [] },
               "source": { "type": "investigator", "id": "port" },
               "collected_at": 1700000000.1, "freshness": "after_run", "confidence": 0.95 } ],
  "graph": { "nodes": [ "..." ], "edges": [ "..." ], "truncated": false },
  "investigations": [ { "investigator": "port", "target": { "type": "port", "port": 5432,
                        "address": "127.0.0.1" }, "round": 0, "status": "completed",
                        "duration_ms": 3, "facts": [0] } ],
  "hypotheses": [ "..." ],
  "conclusion": { "status": "root_cause", "confidence": "high", "root_cause": { "...": "..." },
                  "chain": [], "evidence": [], "inferences": [], "suggestions": [],
                  "alternatives": [], "contributing": [] },
  "stats": { "raw_lines": 120, "raw_bytes": 15000, "raw_events": 118, "semantic_events": 88,
             "dropped_events": 0, "unparsed_lines": 0, "processes": 1, "truncated": false },
  "redactions": { "applied": true, "counts": { "home_dir": 2 } },
  "diagnostics": []
}
```

Values marked `"..."` are elided for brevity; they are not valid content.
