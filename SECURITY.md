# Security

TraceWhy observes a command in detail: its arguments, files it touched,
hosts it resolved, what it printed. This document describes what TraceWhy
does with that data, what it protects, and where the protection ends.

## Local-first, no telemetry

- TraceWhy never sends data anywhere. There is no telemetry, no update
  check, no crash reporting and no LLM or remote analysis service. The
  analysis is deterministic and runs entirely on the local machine.
- Nothing is written to disk unless you ask for it (`why record`, or
  `-o/--output`). The raw strace output is written to a private temporary
  directory (mode 0700 under `$TMPDIR`) and deleted when the run finishes.
  If `why` itself is killed with SIGKILL, that directory can be left behind,
  unredacted.

## What runs on your machine

Besides the traced command itself (under `strace`), TraceWhy may, after the
command finishes:

- read `/proc` (`/proc/net/tcp{,6}`, `/proc/*/fd`, `/proc/*/exe`,
  `/proc/*/cmdline`, `/proc/self/mountinfo`, `/proc/self/status`,
  `/proc/sys/net/ipv4/ip_unprivileged_port_start`), `/etc/passwd`,
  `/etc/resolv.conf`, and files and directories related to the failure
  (`stat`, ELF headers, `#!` lines, `package.json`, virtualenvs);
- call `statvfs`, `getrlimit`, `access` and read interface addresses;
- resolve a hostname from a DNS failure with the system resolver
  (`getaddrinfo`). This generates a DNS query to your configured resolver;
- run the `docker` CLI with read-only subcommands: `info`,
  `compose version`, `compose -f <file> config --format json`,
  `compose -f <file> ps -a --format json`, `ps --format '{{json .}}'`,
  `inspect --format '{{.State.OOMKilled}}'`, `logs --tail 30`. Each call has
  a timeout;
- run `<interpreter> --version` (2-second timeout) for a Node.js or Python
  interpreter that appeared in the trace (runtime adapters).

Investigators are designed to be read-only: none of them creates, modifies,
deletes, starts or stops anything. Use `--no-investigate` to skip the
investigation loop and runtime adapters' project inspection entirely.
`why explain FILE` uses only the recorded facts unless `--investigate` is
given.

The traced command runs with your privileges and environment, exactly as if
you had run it directly. TraceWhy adds no isolation.

## Redaction by default

Every string TraceWhy prints or exports passes through the redactor
(`crates/tracewhy-redact`): the text report, the JSON report, `why diff`
output and `.whytrace` files. For JSON and `.whytrace`, every string value
and every object key is redacted. `.whytrace` files record per-rule counts
in `redactions`.

What is redacted (replaced by `<redacted>`):

| Rule | Matches |
|---|---|
| `private_key` | PEM `-----BEGIN ... PRIVATE KEY-----` blocks |
| `auth_header` | `Authorization:` / `Proxy-Authorization:` values |
| `bearer` | `Bearer <token>` |
| `url_password` | the password in `scheme://user:password@host` |
| `query_param` | values of `access_token`, `refresh_token`, `id_token`, `token`, `api_key`, `apikey`, `key`, `secret`, `client_secret`, `password`, `passwd`, `pwd`, `sig`, `signature`, `auth`, `session`, `sessionid`, `code`, `x-amz-signature`, `x-amz-credential` URL parameters |
| `cli_flag` | values after `--password`, `--passwd`, `--pass`, `--token`, `--secret`, `--api-key`, `--apikey`, `--access-key`, `--secret-key`, `--auth-token`, `--client-secret` (with `=` or whitespace; single dash also accepted) |
| `key_value` | `NAME=value` / `name: value` where the name contains `password`, `passwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential(s)`, `auth_key`, `session_key` |
| token formats | AWS access key ids (`AKIA...`, `ASIA...`, `AIDA...`, `AROA...`), GitHub (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`, `github_pat_`), GitLab (`glpat-`), Anthropic (`sk-ant-`), OpenAI (`sk-`, `sk-proj-`, ...), Stripe (`sk_/rk_/pk_` + `live/test`), Slack (`xox?-`), Google API keys (`AIza...`), npm (`npm_`), JWTs (`eyJ...`) |
| `high_entropy` | tokens of 32-512 characters mixing letters and digits that are not pure hex digests, not path components or file names, and not `SNAKE_CASE` identifiers |
| `home_dir` | your `$HOME` prefix becomes `~` |
| `other_home_dir` | `/home/<name>` and `/Users/<name>` become `/home/<user>` |

Argument-aware redaction: in any JSON array (argv of the command and of
every traced `exec`), the element following a secret flag (`--password`,
`--passwd`, `--pass`, `--token`, `--secret`, `--api-key`, `--apikey`,
`--api_key`, `--access-key`, `--secret-key`, `--auth-token`,
`--client-secret`, `--access-token`, `--private-key`, `--pw`, with one or
two dashes) is replaced entirely unless it starts with `-`.

The environment is not stored verbatim: only variable names, the values of
an allowlist of non-secret variables, and short fingerprints of other
non-secret-looking variables are recorded (see
[WHYTRACE_FORMAT.md](WHYTRACE_FORMAT.md)).

### `--unsafe-no-redact`

`--unsafe-no-redact` disables redaction for reports and exported files.
`why` prints a warning when it writes a `.whytrace` this way, and the file
records `"redactions": {"applied": false}`. Use it only for local debugging
of TraceWhy itself; never share such files.

### Known limits of redaction

Redaction is pattern-based and favors precision, so it will miss things:

- Secrets in unrecognized formats that are short, low-entropy, or look like
  words (for example `password123` passed positionally, or `-p secret`).
- Values after flags not in the lists above, and in the text report the
  argv-aware rule does not apply (only the regex `cli_flag` rule, which has a
  shorter flag list).
- Secrets embedded in file paths or hostnames that the program accessed.
- Sensitive but non-secret data: file names, directory layout, hostnames,
  ports, container names, the names of all environment variables, and up to
  64 KiB of each process's output are recorded.
- Fingerprints of non-secret-looking environment variables are 32 bits of a
  64-bit FNV-1a hash, not cryptographic; short values can be brute-forced.
- Redaction is applied when writing. A `.whytrace` written with
  `--unsafe-no-redact` and later shown with `why show` is redacted on
  display, but the file itself keeps the secrets.
- The traced program's own stdout/stderr are passed through to your
  terminal untouched; TraceWhy cannot redact them.

Review a `.whytrace` before sharing it.

## Untrusted input

`.whytrace` files may come from someone else and are treated as untrusted:

- Files larger than 512 MiB are refused; the format and version are checked
  before parsing.
- Report text derived from traces and files (paths, program output, labels)
  is sanitized before printing: ANSI CSI/OSC escape sequences and other
  control characters (except newline and tab) are removed, so a crafted
  trace or program output cannot rewrite your terminal title, move the
  cursor or hide text. JSON output escapes control characters.
- Parsers (strace lines, DNS packets, ELF headers, `/proc` tables, Compose
  files) are bounds-checked, and production code denies `unwrap`, `expect`
  and `panic!` so malformed input degrades into diagnostics.
- `why explain --investigate FILE` probes the *current* machine for the
  paths, ports and hosts named in the file. It does not execute anything
  from the file, but it can trigger a DNS lookup of a hostname chosen by
  whoever produced the file. Do not use `--investigate` on untrusted files
  if that matters to you.
- `TRACEWHY_RULES_DIR` rules can only combine built-in hypotheses and
  read-only investigations; they cannot run commands.

## Output files

`.whytrace` files are written atomically (temporary file, then rename) and
created with mode `0600`, readable only by the owner.

## Reporting a vulnerability

Please do not open a public issue for security problems. Open a private
security advisory on the project's GitHub repository ("Security" tab,
"Report a vulnerability"). Include the TraceWhy version (`why version`),
your platform, and a minimal reproduction, preferably a `.whytrace` file or
command line that triggers the problem. Remove any real secrets from what
you send.
