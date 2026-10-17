# rev-angr usage, output, and interpretation

Detailed reference for `scripts/solve.py`. Read [SKILL.md](../SKILL.md) first for
scope, the approval workflow, and the honest limits of the technique.

## 1. Pick the interpreter

The supervisor is stdlib-only and runs anywhere with `os.waitid`. The **worker**
imports angr, so the interpreter you launch with must be the one that has angr:

```sh
python-with-angr -c 'import angr; print(angr.__version__)'
```

The supervisor passes `sys.executable` to the worker, so both halves use the same
interpreter. Nothing is installed or upgraded automatically.

## 2. Invocation

```sh
python-with-angr scripts/solve.py SAMPLE --output NEWDIR --authorized \
  [--find TARGET ...] [--avoid TARGET ...] --input argv:N|stdin:N \
  [--charset any|printable|alnum] [--timeout S] [--memory-mib M] \
  [--max-steps K] [--max-active A] [--max-input-mib X]
```

* `SAMPLE` — path to the sample. It may be absolute or relative; an absolute path
  is recommended. It is opened read-only and hashed before and after the run; a
  changed digest aborts the run.
* `--output NEWDIR` — must **not** exist. It is created with mode 0700 and every
  file inside with mode 0600. An existing path is refused rather than reused, so a
  previous run is never overwritten; a symlink to an existing directory is refused
  for the same reason, and a dangling symlink fails at creation.
* `--authorized` — required by design. It records that you attest you may analyse
  this sample. It grants nothing and enforces nothing.
* `--find` is required at least once; `--find` and `--avoid` accept up to 64
  targets each.

### Targets

| Form | Rules |
| --- | --- |
| `0xADDR` | an address inside an executable section of the main object; anything else fails |
| `sym:NAME` | resolved with the main object's symbol table; an absent name fails the run |
| `stdout:TEXT` | printable ASCII, compared against the state's modelled stdout |

`stdout:` targets are the most expensive: every active state that is not already
at a matching address has its modelled stdout materialised. Prefer `sym:` or a
plain address when the program prints its result through a known function.

`--avoid` takes precedence over `--find`, matching the behaviour of angr's own
explorer.

### Input modelling

* `argv:N` models a single symbolic argument of exactly N bytes (entry state
  `args=['./sample', <symbolic>]`). `strlen` on it therefore sees N.
* `stdin:N` models N symbolic bytes on stdin through a `SimFile` with an end.
* `--charset` constrains every byte: `printable` = 0x20..0x7e, `alnum` = digits and
  ASCII letters, `any` = unconstrained. Hex-looking inputs (keys, digests) usually
  need `any` plus a matching length.

## 3. Limits and budget reasons

| Flag | Default | Meaning |
| --- | --- | --- |
| `--timeout` | 120 | wall clock; on expiry the worker's process group is killed (exit 124) |
| `--memory-mib` | 4096 | `RLIMIT_AS` for the worker, applied before angr is imported |
| `--max-steps` | 2000 | simulated steps in one search |
| `--max-active` | 256 | active states kept; surplus states go to the `pruned_budget` stash |
| `--max-input-mib` | 256 | largest sample accepted |

The worker also starts with `RLIMIT_CORE` 0 (no core dumps) and `RLIMIT_FSIZE` 256 MiB.
The worker stops exploring 4 s before the deadline so it can still write a report.

When a search stops on a limit, `exploration.budget_reason` is `max_steps`,
`max_active`, or `time`, and the status is `not_found_budget`. Note that hitting
`max_active` is recorded but does not by itself stop the search; the search stops
at `max_steps` or the deadline.

## 4. What the run writes

```
NEWDIR/
  request.json         the exact parameters, written before the worker starts
  report.json          the supervisor's verdict (read this first)
  worker-report.json   the worker's raw findings, validated by the supervisor
  diagnostics.log      worker stderr (angr warnings live here)
  worker-stdout.log    worker stdout (normally empty; angr logs to stderr)
```

`report.json` carries the sample digest, the parameters, the limits, the exit
status of the worker, and either `result` (the validated worker report) or a
`message`. When the status is `found`, the solution is also copied to the top
level:

```json
{
  "status": "found",
  "executed_natively": false,
  "solution": {"hex": "4b3376764c5d", "text": "K3vvL]", "matched_target": "sym:win"},
  "result": {"validation": {"constraints_satisfied": true, "replay_in_simulation": true},
             "exploration": {"steps": 20, "budget_hit": false, "states": {"found": 1},
                             "replay_steps": 41}}
}
```

`solution.hex` is always the canonical form; `solution.text` escapes bytes outside
0x20..0x7e as `<xx>` so it is safe to print.

## 5. Statuses and exit codes

| Status | Exit | Meaning |
| --- | --- | --- |
| `found` | 0 | an input reached a find target, and replaying it in the model reached it too |
| `not_found_exhausted` | 1 | the model ran out of states without hitting a limit |
| `not_found_budget` | 1 | a limit stopped the search |
| `error` | 2 | invalid arguments, a failing target, an unusable worker report, or a worker crash |
| `timeout` | 124 | the wall-clock deadline expired and the worker group was killed |
| `interrupted` | 130 | Ctrl-C |

## 6. Interpreting results

`validation.constraints_satisfied` confirms the returned bytes satisfy the declared
charset. `validation.replay_in_simulation` confirms a second, independent
simulation starting from the concrete input reaches the same target. Both are
simulation evidence. To prove the input works against the real program, run it
separately, with approval, in a disposable environment — never as part of this
Skill's run.

For negatives, raise one bound at a time (`--max-steps`, then `--max-active`, then
`--timeout`) and record what changed. An answer of `not_found_exhausted` for a
target that is guarded by an unreachable condition is the expected, useful result.

## 7. Troubleshooting

* `unicorn support disabled` — angr logs an error line about `unicornlib.so` when
  the unicorn extension is not installed. It is harmless for this workflow and
  appears in `diagnostics.log`, not in `report.json`.
* `MemoryError` / the worker dying — raise `--memory-mib`. angr plus the solver can
  need several GiB on larger samples.
* `no such symbol: ...` — the symbol is absent, stripped, or dynamic-only. Use the
  address from your own static analysis instead.
* `address is not inside an executable section: ...` — the address is wrong, or it
  points at data, a PLT stub in another object, or an unmapped region.
* `unusable worker report: ...` — the worker crashed or wrote an incomplete
  report. The supervisor refuses to guess; read `diagnostics.log`. A report that
  repeats a JSON field name is rejected as well, because a duplicated field could
  otherwise hide a tampered status.
* `exploration.errors` — angr could not model some path (unsupported instruction,
  oversized symbolic operation). It is reported, never hidden, and does not by
  itself invalidate a found solution.

## 8. Security and privacy notes

* Resource limits and process-group cleanup are reliability features, **not** a
  sandbox. angr does not execute the sample, but it does parse untrusted input
  with native code.
* The output directory is private by construction; do not loosen its permissions
  or copy results into a shared location without approval.
* Results can contain key material derived from a sample. Handle them as
  sensitive, and do not paste them into tickets, chat, or public issues.
* The supervisor signals the worker's process group only while the group leader
  is unreaped — normally still running, since the timeout path fires precisely
  because it has not exited, though the Ctrl-C path can also catch a leader that
  has exited but is not yet reaped — and never signals a numeric pid or pgid after
  reaping; a group that survives SIGKILL is reported as an error.

## 9. Related tooling

angr ships an official MCP server (`python -m angr.mcp`) that exposes static
analysis over MCP: loading binaries, CFG, function listing, decompilation, xrefs,
strings, imports and exports. That server has no symbolic-execution tool, which is
exactly the gap this Skill fills. Use them together if you like, but this Skill
has no MCP dependency and works on its own.
