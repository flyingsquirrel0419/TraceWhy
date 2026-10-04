# Exit codes

`why <command>` is designed to be a drop-in prefix: it exits with the traced
command's own status, so scripts and CI keep working. TraceWhy's own
failures use codes that shells already reserve for "could not run".

## `why [OPTIONS] <command> [args...]`

| Situation | Exit status |
|---|---|
| The command exited normally | Its exit code |
| The command was killed by signal N | 128 + N (e.g. 139 for SIGSEGV). Signals TraceWhy does not know by name map to 128. |
| The program was not found (preflight: explicit path missing, or name not on `PATH`) | 127; the command is not run |
| The program exists but is a directory or not executable (preflight) | 126; the command is not run |
| The traced root process never managed to exec (strace reports the exec failure) | 127 for ENOENT, 126 for any other errno |
| The exit status could not be determined | 125 |
| `strace` is not installed, or strace produced no trace (ptrace blocked, seccomp, missing `CAP_SYS_PTRACE`) | 124 |
| TraceWhy internal error (working directory unreadable, strace could not be started, I/O error reading the trace) | 125 |
| Invalid TraceWhy usage | 2 |

With `-o FILE`, a failure to save the trace is reported on stderr and the
exit status is 125 (the report itself was still printed).

The report is printed (text on stdout, or JSON with `--json`) whenever
tracing succeeded, regardless of the command's status. When TraceWhy itself
fails (124, 125, 2), it prints a single `why: ...` message on stderr and no
report.

## Subcommands

| Command | Exit status |
|---|---|
| `why record [-o FILE] <command> ...` | The command's status as above; 125 if the trace file could not be written |
| `why show FILE` | 0; 125 if the file cannot be read or is invalid, too large, or of an unsupported format version |
| `why explain [--investigate] FILE` | 0; 125 if the file cannot be loaded |
| `why diff GOOD BAD` | 0; 125 if either file cannot be loaded |
| `why doctor` | 0 when ready; 124 when a required check fails (not Linux, strace missing, tracing blocked, `ptrace_scope` = 3). Docker checks are informational. |
| `why version`, `why --version`, `why help`, `why --help`, `why` with no arguments | 0 |

Note that `show`, `explain` and `diff` return 0 even when the recorded
command failed; the recorded status is in the report (`exit`, `exit_code`).

## Usage errors (2)

All argument-parsing errors exit with 2, for example:

- an unknown option before the command (use `why -- -cmd` to run a command
  whose name starts with `-`);
- `--color` with a value other than `auto`, `always`, `never`;
- `-o`/`--output` without a file name;
- `why record` without a command;
- `why show` / `why explain` without exactly one file, or with `-o`;
- `why diff` without exactly two files.

## Ambiguity

A traced command can itself exit with 2, 124, 125, 126 or 127. To tell
TraceWhy's own failure apart from the command's:

- TraceWhy's own errors are printed on stderr prefixed with `why:`;
- with `--json`, a report on stdout means tracing succeeded, and its
  `exit_code` field is the command's status (see
  [json-report.md](json-report.md));
- `why record --json` prints `{"saved": "<path>", "exit_code": N}` on
  success.
