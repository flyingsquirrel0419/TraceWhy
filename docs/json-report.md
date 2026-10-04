# JSON report (`tracewhy.report/v1`)

`why --json <command>`, `why show --json FILE` and `why explain --json FILE`
print one JSON object on stdout. With `--json`, the traced command's stdout
is redirected to stderr so stdout contains only the report.

The report is built by `tracewhy_report::json::report` (crate
`tracewhy-report`). It is a stable, condensed view of the conclusion; the
full data (events, facts, hypotheses, graph) is in the `.whytrace` file (see
[../WHYTRACE_FORMAT.md](../WHYTRACE_FORMAT.md)).

## Compatibility

The `schema` field identifies the report schema. Within `v1`, fields are
only ever added, never removed or changed in meaning. Consumers should
ignore unknown fields. A breaking change would use a new schema id.

All string values (not object keys) pass through the redactor unless
`--unsafe-no-redact` is given (see [../SECURITY.md](../SECURITY.md)).

## Fields

| Field | Type | Description |
|---|---|---|
| `schema` | string | Always `"tracewhy.report/v1"`. |
| `tracewhy_version` | string | Version that produced the analysis (for `show`, the version that recorded the file). |
| `command` | array of strings | The command's argv. |
| `cwd` | string | Working directory. |
| `duration_ms` | integer | Wall-clock duration of the traced run; 0 if the command was not run (preflight). |
| `exit` | object or null | `{"type":"exited","code":N}` or `{"type":"killed","signal":"SIGSEGV","core_dumped":bool}`; null if unknown. |
| `exit_code` | integer or null | Shell-style status: the exit code, or 128 + signal number. |
| `status` | string | `"succeeded"`, `"root_cause"` or `"undetermined"`. |
| `root_cause` | object or null | Present when `status` is `root_cause`. |
| `root_cause.kind` | string | Stable hypothesis kind, e.g. `service_not_listening`, `python_venv_not_active`. See [../RULES.md](../RULES.md). |
| `root_cause.title` | string | One-line statement of the cause. |
| `root_cause.detail` | string or null | Additional detail, when the evaluator provides one. |
| `confidence` | string or null | `"high"`, `"medium"` or `"low"`; null unless `status` is `root_cause`. |
| `failing_process` | integer or null | pid of the process whose failure propagated to the exit status (last process of the failure chain). |
| `chain` | array | Causal chain, in order. |
| `chain[].kind` | string | `process`, `action`, `failure`, `fact` or `cause`. |
| `chain[].label` | string | Short label. |
| `chain[].inferred` | boolean | True when the step was inferred rather than directly observed. |
| `evidence` | array of strings | Directly observed statements backing the conclusion ("Observed"). For `undetermined`, the failing process and its exit. |
| `inferences` | array of strings | What TraceWhy concluded from the evidence ("Inference"). |
| `suggestions` | array | At most one today. |
| `suggestions[].kind` | string | `"fix"` (only at HIGH confidence) or `"next_step"`. |
| `suggestions[].text` | string | What to do. |
| `suggestions[].command` | string | Optional; a command line to run. Omitted when absent. |
| `alternatives` | array | Up to three competing explanations. |
| `alternatives[].kind` | string | Hypothesis kind. |
| `alternatives[].title` | string | Statement. |
| `alternatives[].confidence` | string | `"medium"` or `"low"`, never above the main `confidence`. |
| `contributing` | array of strings | Failures that may have contributed but are not proven causes. On success: notable non-fatal failures prefixed `Non-fatal:`. |
| `stderr_excerpt` | string or null | Last lines (up to 6) of the captured stdout/stderr output of the failing process, or of the nearest process up the failure chain that wrote something. Null when the command succeeded. |
| `stats` | object | See below. |
| `investigations` | array | Every investigation the engine ran or skipped. |
| `investigations[].investigator` | string | `port`, `path`, `executable`, `filesystem`, `elf`, `library`, `dns`, `network`, `fd_limit`, `privileges`, `docker`, `docker_logs`. |
| `investigations[].target` | object | Tagged by `type`: `port` (`port`, optional `address`), `path` (`path`), `executable` (`name`), `hostname` (`name`), `library` (`name`, optional `executable`), `filesystem` (`path`), `elf` (`path`), `docker` (optional `port`), `container_logs` (`container`), `fd_limit`, `network`, `privileges`. |
| `investigations[].status` | string | `completed`, `unavailable`, `failed`, `timed_out` or `skipped` (budget exhausted). |
| `investigations[].duration_ms` | integer | Time spent. |
| `diagnostics` | array of strings | Non-fatal problems: unparsed trace lines, truncation, rule-loading warnings. |

### `stats`

| Field | Description |
|---|---|
| `raw_events` | Raw syscall records read from the backend. |
| `semantic_events` | Semantic events produced. |
| `facts` | Number of facts. |
| `observations` | Number of observations (all relevance levels). |
| `hypotheses` | Number of evaluated hypotheses. |
| `processes` | Processes seen in the trace. |
| `truncated` | True when limits caused events or raw input to be dropped; the analysis may be incomplete. |

## Example

```json
{
  "schema": "tracewhy.report/v1",
  "tracewhy_version": "1.0.0",
  "command": ["python3", "client.py"],
  "cwd": "~/project",
  "duration_ms": 41,
  "exit": { "type": "exited", "code": 1 },
  "exit_code": 1,
  "status": "root_cause",
  "root_cause": {
    "kind": "service_not_listening",
    "title": "...",
    "detail": null
  },
  "confidence": "high",
  "failing_process": 1234,
  "chain": [
    { "kind": "process", "label": "python3 client.py", "inferred": false },
    { "kind": "action", "label": "...", "inferred": false },
    { "kind": "failure", "label": "ECONNREFUSED", "inferred": false },
    { "kind": "cause", "label": "...", "inferred": false }
  ],
  "evidence": ["...", "No process is listening on port 47913"],
  "inferences": ["..."],
  "suggestions": [ { "kind": "fix", "text": "..." } ],
  "alternatives": [],
  "contributing": [],
  "stderr_excerpt": "ConnectionRefusedError: [Errno 111] Connection refused\n",
  "stats": { "raw_events": 118, "semantic_events": 88, "facts": 3, "observations": 1,
             "hypotheses": 8, "processes": 1, "truncated": false },
  "investigations": [
    { "investigator": "port", "target": { "type": "port", "port": 47913, "address": "127.0.0.1" },
      "status": "completed", "duration_ms": 3 }
  ],
  "diagnostics": []
}
```

Strings shown as `"..."` are elided; exact wording of titles, labels and
evidence is not part of the contract. Match on `status`, `root_cause.kind`,
`confidence` and `exit_code`.

## Other JSON outputs

These are not part of `tracewhy.report/v1`:

- `why record --json`: `{"saved": "<path>", "exit_code": N}` (the report
  itself is not printed).
- `why doctor --json`: `{"tracewhy_version", "ready", "checks": [{"name",
  "ok", "detail"}]}`, where `ok` is `true`, `false` or `null`
  (informational).
- `why diff --json GOOD BAD`: the serialized `TraceDiff` from
  `crates/tracewhy-diff` (`good_command`, `bad_command`, `good_exit`,
  `bad_exit`, `environment[]`, `execution[]`, optional `divergence`, `stats`,
  `notes`). It has no schema id yet and may change.
