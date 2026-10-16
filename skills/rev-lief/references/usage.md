# Usage, boundaries, and evidence

## Runtime and output

Use an existing verified Python interpreter with the official `lief` package;
no installation is performed. Run `scripts/inspect_binary.py`, not the private
worker directly. The parent is stdlib-only and invokes its sibling worker using
`sys.executable`, an argv list, `shell=False`, and a new process session. It
checks dependency presence without importing the native SDK itself. Import
failures still fail in the worker and appear in private diagnostics.

The input must be an absolute, readable regular file, with size greater than
zero. Paths containing spaces or shell metacharacters are passed literally.
The output must not exist (even as a dangling symlink); its parent must exist.
No existing output is overwritten or deleted. Validation of authorization,
arguments, dependency presence, input size, and output availability precedes
output creation. An input symlink is resolved to its approved regular target;
this is not protection from concurrent hostile filesystem changes.

A new output directory is mode `0700`; files created by the runner are `0600`:

- `request.json`: fixed private worker request, input identity and limits.
- `diagnostics.log`: native stdout/stderr and worker exception tracebacks.
- `worker-report.json`: fixed worker metadata artifact when available.
- `report.json`: parent-validated result, including partial results when usable.

Some failures occur before a report can exist. Retain the directory for private
inspection; choose a different new directory for a retry. Never infer success
from the existence of files or from the worker exit code alone. The supervisor
checks input hashes before/after parsing, strict schema/types/limits, report
size, nonempty architecture coverage, native diagnostics, and worker exit.
A worker report alone is not a verified final result.

Exit **0**: scoped metadata verified; intentional truncation may still be present.
Exit **1**: validation, dependency, native error/crash, or partial result.
Argument-parser errors may exit **2**. Exit **124**: wall-clock deadline.
Exit **130**: interrupted by SIGINT (owned-group cleanup still runs).
Any captured native stdout/stderr conservatively makes the final report
`partial` and returns nonzero; logging is not disabled or silently discarded.
A parse exception/crash may leave only diagnostic artifacts, not usable metadata.

## Limits and isolation

All limit options are positive integers; duplicate singleton flags are rejected.

| Option | Default | Maximum |
|---|---:|---:|
| `--max-items` | 256 | 4096 |
| `--max-slices` | 8 | 64 |
| `--timeout` (seconds) | 30 | 300 |
| `--max-input-mib` | 128 | 1024 |
| `--memory-mib` | 1024 | 16384 |

Each metadata collection is clipped independently. Names are limited to 512
Unicode code points. JSON uses escaped Unicode, and report reads/writes are
limited to 8 MiB. Large configured collection limits can exceed that report
budget, causing an explicit failure, not a silently incomplete success.

Before native import, the worker disables normal core dumps with `RLIMIT_CORE`
and sets `RLIMIT_AS` to the requested address-space cap, clamped to the inherited
hard limit. It sets `RLIMIT_FSIZE` to at most 8 MiB, also clamped, bounding each
regular file it writes, including diagnostics. Unsupported resource controls
fail clearly. A file-size limit is per file, not a whole-directory disk quota;
it does not constrain an arbitrary compromised process creating many files.
The fixed runner writes only the named artifacts above. The parent also bounds
serialized reports before writing; the worker's resource cap protects native
log growth independently of the report read cap.

The supervisor observes worker exit with POSIX `waitid(WNOWAIT | WNOHANG)`:
no polling/reaping API discards the direct-child identity before cleanup. It
kills its entire owned process group on **every** terminal path, including early
worker success/failure and deadline, then reaps its direct child once. The live
or unreaped leader pins the numeric PID/PGID until that last group signal; the
supervisor never signals the numeric group again after reaping. SIGINT is
ignored only during this cleanup. Before creating output or spawning a worker,
the standalone CLI checks non-reaping wait support and resets its own SIGCHLD
disposition to default so inherited SIG_IGN cannot auto-reap the leader.
Missing/unusable `waitid`/`WNOWAIT` support fails closed, with no unsafe fallback.
This cannot stop a compromised child that deliberately escapes the group.
No network restriction, filesystem sandbox, syscall filter, or aggregate memory
quota is provided. SDK loading can consume much of a small address-space limit;
raise a limit only with approval. POSIX runner: Linux tested, macOS not yet
validated, native Windows unsupported. Hash checks detect ordinary changes but
do not create an immutable snapshot or defeat malicious change-and-restore races.

## JSON schema version 1 and interpretation

Top level: `schema_version`, `status` (`ok`/`partial`), `input` (original `sha256`
and byte `size`), dynamic `sdk_version`, effective requested `limits`, `family`
(`ELF`, `PE`, `MachO`), and `slices`. Partial native diagnostics add a relative
`diagnostics` reference. `limits.memory_mib` is the requested ceiling; an inherited
hard resource limit may lower the worker's actual ceiling.

Each collection uses `{items, total, truncated}`. `total` is the native collection
count observed, not a proof that every encoded record in the file was recognized.
Each slice has `architecture`, required native `header` facts, an explicit
`entrypoint` field, `sections`, `libraries`, `imports`, and `exports`. Missing
SDK metadata is an error, not an empty header or inferred entrypoint. Required
header fields are ELF `file_type`/`class`/`endianness` (nonempty strings), PE
`optional_magic` (nonempty string) plus `characteristics`/`imagebase` (hex
strings), and Mach-O `file_type` (nonempty string)/`cpu_subtype` (hex string).
ELF/PE entrypoints require structured VA/RVA values, including legitimate
`0x0`; only Mach-O permits explicit null under the native no-entrypoint contract
below. This checks emitted metadata shape, not complete binary validity.
Every retained name has a corresponding
`name_truncated` flag. PE DLL/forwarder strings similarly have
`library_truncated`/`forwarder_truncated`. Count clipping is intentional and
compatible with scoped success, never with claiming full-file coverage.

All addresses, RVAs, symbol values, sizes, and file offsets are lowercase `0x`
hexadecimal **strings**, retaining unsigned 64-bit precision in JSON clients.
Counts/ordinals/input byte size are bounded JSON integers below `2^53`.

- **ELF:** architecture from `header.machine_type`; class/endianness/file type
  from the header; entrypoint from `header.entrypoint`, explicitly **VA**.
  Imports/exports use native `imported_symbols`/`exported_symbols`, including
  symbols beyond function-only abstractions. Symbol `value` is the native symbol
  value, not a promise of a callable absolute address (undefined/TLS/relocatable
  semantics vary). Libraries use the native library list.
- **PE:** architecture from `header.machine`; header reports optional-header
  magic, image base, and characteristics. `optional_header.addressof_entrypoint`
  is **RVA**, not VA. Imports preserve DLL association and either a name or an
  ordinal (the other is null). Exports come from `get_export().entries`, including
  unnamed ordinal entries; each has ordinal, **RVA** `address`, and a nullable
  forwarder. These are **export-table entries**, not necessarily functions:
  data and forwarded exports are possible. No signature checking is done.
- **Mach-O:** uses `MachO.parse` and enumerates its `FatBinary`, retaining each
  slice's CPU architecture up to the disclosed slice cap. Thin input has one
  slice. File type and CPU subtype are retained. `entrypoint` is null when the
  native `has_entrypoint` property is false, including the tested object fixture;
  otherwise it is native `entrypoint` as **VA**. Libraries use dylib command
  names; imports/exports use native symbol collections, not only functions.

Sections retain native `name`, `virtual_address` as `address` (**RVA** for PE,
**VA** otherwise), `offset`, and `size`. These are metadata, not a promise that
`offset + size` lies within the file: BSS/zerofill and virtual sections need not
be file-backed. No section content or whole-binary strings are dumped.

## Tests and coverage limits

From the repository root, with an existing verified adapter/interpreter:

```sh
PYTHONDONTWRITEBYTECODE=1 reverse-python -m unittest discover \
  -s skills/rev-lief/tests -p 'test_*.py' -v
```

Here `reverse-python` is an optional host adapter, not a runtime requirement.
Tests create temporary owned fixtures under the checkout's approved scratch
ancestor. ELF compilation uses an existing `cc`, links imported `puts` and an
exported `helper`, and **never executes the sample**. PE bytes are generated
with stdlib `struct` and cover a named import, ordinal import, named export,
unnamed ordinal export, entrypoint RVA, and section facts. Thin x86-64 and
universal x86-64/ARM64 Mach-O object bytes cover slices/sections/no entrypoint.
No SDK write/build/patch API is used. Fake workers/SDKs exercise negative
boundaries and cleanup, not real format success. Controlled SIGKILL models a
native crash without generating a host core dump.

Lifecycle tests require Linux `/proc`, `os.pidfd_open`, and
`signal.pidfd_send_signal`; unsupported hosts fail up front rather than skip.
Failure cleanup verifies a per-case unique child argv marker between two live
pidfd checks, signals only that handle, and closes it; it never falls back to a
numeric PID. Confirmed gone/zombie children are not signalled again.

Not validated by these fixtures: forwarded/data PE exports as independent
examples, delayed imports, 32-bit/big-endian variants, Mach-O dyld/chained-fixup
symbol coverage, ELF TLS/versioning edge cases, macOS resource behavior, or
all malformed binary structures. Native table APIs can omit information they
do not decode; no missing property is silently converted into an empty table.
Metadata success is not full binary validity, signature authenticity,
exploitability, or semantic equivalence.

## Official sources and integration decision

- Project and license: https://github.com/lief-project/LIEF
- Python API and installation background (no auto-install):
  https://lief.re/doc/latest/installation.html#python
- ELF: https://lief.re/doc/latest/formats/elf/python.html
- PE: https://lief.re/doc/latest/formats/pe/python.html
- Mach-O: https://lief.re/doc/latest/formats/macho/python.html
- Official readers at audited commit:
  https://github.com/lief-project/LIEF/blob/5416ff2e2fcda29924c2f868a7249b4318359c41/api/python/examples/pe_reader.py
  and https://github.com/lief-project/LIEF/blob/5416ff2e2fcda29924c2f868a7249b4318359c41/api/python/examples/macho_reader.py

The complete official README and tracked-tree filename audit at that commit
provided no official MCP server evidence. That bounded finding motivates using
the official SDK here, not a global claim that no official MCP can exist.
There are no configured MCP endpoints or bridges. This module is independently
original MIT code, Copyright (c) 2026 Luckylos; external LIEF is Apache-2.0.
Subtree reference: https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-lief
No client UI installation is implied.
