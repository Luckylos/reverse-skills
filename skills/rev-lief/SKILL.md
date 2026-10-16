---
name: rev-lief
description: Use when authorized read-only ELF, PE, or Mach-O inspection needs bounded headers, architectures, sections, libraries, imports, or exports through the official LIEF Python SDK, without executing or modifying the target.
license: MIT
---

# Read-only LIEF inspection

Use this self-contained Skill for bounded binary metadata, not decompilation,
patching, signature validation, or determining whether a binary is safe to run.
No sibling Skill or client-specific configuration is required.

## Workflow

1. Obtain explicit approval for the **target, read-only action, and new output
   directory**. Treat binaries and results as potentially sensitive. The
   `--authorized` flag records an attestation; it does not grant permission or
   provide a security boundary.
2. Select an **existing configured and verified Python interpreter that imports
   `lief`**. Verify its SDK availability/version with a small metadata-only probe
   (`import lief; print(lief.__version__)`). An environment may provide a
   `reverse-python` adapter, but do not assume it exists. Do not install or
   upgrade dependencies automatically, especially in system Python. If the SDK
   is unavailable, stop and ask for an approved interpreter.
3. Use that same interpreter to run the script, with an absolute input path and
   a nonexistent output directory whose parent already exists:

   ```sh
   python-with-lief scripts/inspect_binary.py '/absolute/path/to/approved sample' \
     --output '/absolute/path/to/new-private-results' --authorized \
     --max-items 256 --max-slices 8 --timeout 30 \
     --max-input-mib 128 --memory-mib 1024
   ```

   `python-with-lief` is a placeholder, not a supplied executable. Resolve the
   script relative to this Skill's directory, not a client's working directory.
4. Check the exit code **and** `report.json` status/truncation markers. Only exit
   0 means a verified scoped metadata result. Nonzero means error/partial;
   124 means deadline. Keep diagnostics private; do not paste binary names,
   paths, imports, exports, or diagnostic contents without approval.
5. Explain collection and name clipping, address coordinates, SDK table
   semantics, and any partial result. Never describe bounded metadata as full
   binary validity, signature authenticity, exploitability, or semantic
   equivalence. Never execute the target to confirm metadata.

The runner requires POSIX process groups and resource limits. Linux is tested;
macOS is not yet tested; native Windows is unsupported. Address-space/file-size
limits and subprocess isolation are **not an OS sandbox**. For hostile inputs,
use a separately approved isolation environment and least privilege.

Read [usage and schema details](references/usage.md) before interpreting output.
Only the official Python SDK is used: no MCP endpoint, bridge, or third-party
server is configured. A bounded audit of the official README and tracked tree at
commit `5416ff2e2fcda29924c2f868a7249b4318359c41` found no official MCP server
evidence; this is not a universal absence claim.

Module/subtree import reference (not a claim of UI installation):
https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-lief

This new module is original MIT-licensed code; see [LICENSE](LICENSE).
The external LIEF runtime is independently Apache-2.0 licensed.
