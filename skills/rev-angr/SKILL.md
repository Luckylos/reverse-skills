---
name: rev-angr
description: Use when authorized offline analysis needs a bounded angr search for an input that reaches a chosen target (password, key, flag, reachability).
license: MIT
---

# Bounded angr path solving

Use this self-contained Skill to solve for an input, not to decompile, patch, or
decide whether a binary is safe to run. It answers one question: within clearly
stated bounds, does angr's model reach the target, and if so, with which input?
No sibling Skill or client-specific configuration is required.

Neither this Skill nor angr executes the sample natively. A candidate input is
produced from the symbolic model and then replayed through a second simulated
run, which is still not native execution. Never claim that a solved input was
verified on real hardware or against the real runtime environment.

## Workflow

1. Obtain explicit approval for the **target, the analysis, and a new output
   directory**. Treat samples, inputs, and results as potentially sensitive.
   `--authorized` records an attestation; it does not grant permission and is not
   a security boundary.
2. Select an **existing configured and verified Python interpreter that imports
   angr** (`import angr; print(angr.__version__)`). An environment may provide a
   `reverse-python` adapter, but do not assume it exists. Do not install or
   upgrade dependencies automatically. For static triage (functions, CFG,
   decompilation, xrefs, strings) an official angr MCP server or angr's Python
   API is often the better first step; this Skill does not depend on either.
3. Run the supervisor with an absolute sample path and a nonexistent output
   directory whose parent already exists:

   ```sh
   python-with-angr scripts/solve.py '/absolute/path/to/approved-sample' \
     --output '/absolute/path/to/new-private-results' --authorized \
     --find sym:win --avoid stdout:BAD --input argv:16 --charset printable \
     --timeout 120 --max-steps 2000 --max-active 256 --memory-mib 4096
   ```

   `python-with-angr` is a placeholder, not a supplied executable. Resolve the
   script relative to this Skill's directory, not a client's working directory.
4. Read the exit code **and** `report.json`. Only exit 0 with status `found` is a
   solved input. Exit 1 is a bounded negative (a real answer of "not within these
   bounds", not a proof of impossibility); 124 is the wall-clock deadline; 2 is an
   error; 130 is interruption.
5. Report the input, the matched target, the limits used, and the caveats
   together. Never present `not_found_exhausted` as "the target is unreachable",
   or a simulated replay as runtime verification. Keep diagnostics private.

POSIX process groups, `os.waitid` with `WNOWAIT`/`WNOHANG`, and per-run resource
limits are required; Linux is tested, macOS and native Windows are not. Address
space and file-size limits plus subprocess isolation are **not an OS sandbox**.
For hostile samples use a separately approved isolation environment.

## Targets

| Form | Meaning |
| --- | --- |
| `0x401136` | an address inside an executable section of the main object |
| `sym:win` | an address by symbol name, resolved in the main object |
| `stdout:TEXT` | the modelled stdout of a state contains TEXT |

`--avoid` takes the same forms and wins over `--find`: a state at an avoided
address is discarded even when it also matches a find target.

## Limits

| Flag | Default | Allowed |
| --- | --- | --- |
| `--input` | required | `argv:N` or `stdin:N`, N = 1..4096 |
| `--charset` | `printable` | `any`, `printable`, `alnum` |
| `--timeout` | 120 s | 10..3600 |
| `--memory-mib` | 4096 | 1024..16384 (worker address space) |
| `--max-steps` | 2000 | 1..200000 |
| `--max-active` | 256 | 1..4096 |
| `--max-input-mib` | 256 | 64..1024 (sample size) |

## Honest limits

angr approximates the program: library calls are sim-procedures, libs are not
loaded, and the environment, heap layout, and timing are not modelled. A positive
answer means a concrete input satisfies the model's path to the target. A
negative answer means only that no path was found within these bounds — raise the
bounds deliberately, one at a time, before concluding anything stronger.

Read [usage and report details](references/usage.md) before interpreting output.

Module/subtree import reference (not a claim of UI installation):
https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-angr

This new module is original MIT-licensed code; see [LICENSE](LICENSE).
The external angr runtime is independently BSD-2-Clause licensed and is not
bundled or relicensed here.
