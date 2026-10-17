# Runtime selection and Frida 17 evidence

## Select an existing runtime first

1. Locate the already-provisioned CLI and Python SDK, then choose explicitly which
   environment to use. Do not assume the shell's first `frida` and `python` belong
   together. Keep specialized environments (for example, iOS dumping) separate;
   their existence does not establish device connectivity or iOS compatibility.
2. Read local versions without connecting to targets. For example, in the chosen
   environment (POSIX shell):

   ```bash
   command -v frida
   command -v python
   frida --version
   PYTHONDONTWRITEBYTECODE=1 nice -n 10 python -c 'import sys, frida; print(sys.executable); print(frida.__version__)'
   PYTHONDONTWRITEBYTECODE=1 nice -n 10 python -c 'from importlib.metadata import version; print(version("frida-tools"))'
   ```

   The `frida` binding/core and `frida-tools` have independent version numbering;
   their numbers need not match. If a package is absent, report it and request
   approval for any dependency change. Do not install or upgrade automatically.
3. Choose the backend for the authorized target: local attach, frida-server, or
   Gadget. Explicitly verify target OS, CPU, process bitness/ABI, backend build and
   permissions. A host architecture check is not a target ABI check. Server and
   Gadget artifacts must fit the target, not merely the host machine.
4. Prefer pinning the host binding and server/Gadget to the same full version as
   a **conservative reproducibility policy**, not a universal official protocol
   requirement. Record the actual versions and verify compatibility for the
   selected workflow. Do not try to make frida-tools match the binding number.
5. Request approval before device enumeration, any `adb` command, attach, spawn,
   or load. `frida-ps -U` interacts with a target; it is not a local version check.
   Do not download/deploy/launch servers, invoke sudo, relax Yama/ptrace policy,
   disable platform protections, or change global configuration automatically.
   If attachment is denied, report the bounded error and stop, without bypassing it.

Attach and hook installation change target memory. Obtain authorization even for
an observation-only hook. Detach removes session instrumentation but does not
mean resume or kill; explicitly track spawned/paused processes and their ownership.
Never kill a process just because an old numeric PID still exists.

## Bridges: CLI convenience versus custom agents

Frida 17 removed Java/ObjC bridges from bare GumJS. The official REPL and
frida-trace bundle bridges for convenience; this does not mean arbitrary SDK
scripts have those globals. A Python `session.create_script(source)` using bare
source does not automatically import them.

A guard such as `typeof Java !== "undefined" && Java.available` avoids an error
when the bridge is missing. It neither loads the bridge nor proves a VM exists.
The corresponding rule applies to ObjC. Check availability before using classes,
then verify target-specific class/method names and signatures.

For a custom agent needing either bridge, obtain approval for a project-local
compiler/dependency setup, reuse existing packages when possible, and declare
only the required `frida-java-bridge` / `frida-objc-bridge` dependency. Do not
install anything automatically. Agent entry-point imports are explicit:

```javascript
import Java from 'frida-java-bridge';
import ObjC from 'frida-objc-bridge';
// Include only the bridge(s) needed; then use the guarded examples in SKILL.md.
```

With the approved dependencies and compatible official compiler already available:

```bash
frida-compile agent.ts -o agent.js
```

Pass the compiled bundle's text to Python `session.create_script()` and load it
only in the approved session. Do not pass raw package imports to a bare script
and expect package resolution. No bridge install, device connection, or custom
service is implied by this build flow.

## Bounded regression checks

Run the commands below from the self-contained Skill directory (`skills/rev-frida`
in the repository), not the repository root. The default suite checks the actual
documented code blocks and workflow contracts without connecting to targets:

```bash
PYTHONDONTWRITEBYTECODE=1 nice -n 10 python -W always::ResourceWarning -m unittest discover -s tests -p test_frida_skill.py -v
```

The Linux native check is skipped unless explicitly authorized and opted in:

```bash
FRIDA_TEST_NATIVE=1 PYTHONDONTWRITEBYTECODE=1 nice -n 10 python -W always::ResourceWarning -m unittest discover -s tests -p test_frida_skill.py -v
```

Use an existing Python environment containing the Frida SDK. This opt-in attaches
only to one dedicated, nonsensitive local Python child created by the test. It
loads the **exact native observer block from SKILL.md**, triggers `getpid`, checks
the hook event, explicitly stops observer/listener, checks the hook stays silent,
exercises the actual Java/ObjC examples without bridges, unloads, detaches, and
ends/reaps its child. SDK waits use cancellables/timers; messages and process
waits have deadlines. Cleanup uses a pidfd plus a unique argv marker to confirm
exit before reaping. If pidfd acquisition fails, it aborts before attach and
cleans up only the still-unreaped child. It never signals a numeric PID after
reaping. An enabled failure is not skipped or
worked around with security changes. No USB/remote enumeration, server, Gadget,
sample execution, physical device, Java VM, or Objective-C runtime is covered.
Real-device Java/ObjC variants require separate approval and validation.

## Official-only integration boundary and sources

The bounded checked official docs and the two repository snapshots below did
**not establish an official Frida MCP**. This is not a claim of global
nonexistence. Retain the official CLI/Python SDK workflow; do not substitute a
third-party MCP or create a self-built service.

- [JavaScript API](https://frida.re/docs/javascript-api/): module-instance lookup,
  global exports, module observers, listener detach, bridge availability.
- [Frida 17 migration](https://frida.re/news/2025/05/17/frida-17-0-0-released/):
  removed static Module APIs and bridge packaging changes.
- [Android setup](https://frida.re/docs/android/) and
  [troubleshooting](https://frida.re/docs/troubleshooting/): platform/backend
  prerequisites; commands remain subject to target approval.
- [frida-tools application.py at 19048c41ce0e307b5eb60a912ab7fec15e919966](https://github.com/frida/frida-tools/blob/19048c41ce0e307b5eb60a912ab7fec15e919966/frida_tools/application.py):
  `-n` process name, `-N` app identifier, `-p` PID, `-f` spawn.
- [frida-tools repl.py at the same commit](https://github.com/frida/frida-tools/blob/19048c41ce0e307b5eb60a912ab7fec15e919966/frida_tools/repl.py):
  `--pause`, default resume, and REPL bridge/compilation handling.
- [Official frida tree at 2ff8f72375c8d3d5e53bb3ad250ba240964a4a39](https://github.com/frida/frida/tree/2ff8f72375c8d3d5e53bb3ad250ba240964a4a39)
  and the fixed frida-tools tree were the bounded repository evidence, not an
  exhaustive search of all possible integrations.
