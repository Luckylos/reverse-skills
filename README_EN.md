English | [中文](README.md)

# Reverse Engineering Skills

Reverse engineering analysis skills, supporting 40+ AI coding agents.

**Designed to work with [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP)** - Export IDA decompilation results, then analyze with your AI coding agent.

## Skills Included

| Skill | Description |
|-------|-------------|
| `rev-symbol` | Analyze function symbols from exports/imports or decompiled code |
| `rev-struct` | Reconstruct data structures from decompiled functions |
| `rev-frida` | Generate Frida hook scripts using modern Frida API |
| `rev-unicorn-debug` | Debug specific code snippets using Unicorn emulator with environment simulation |
| `rev-dex-dumper` | Dump DEX files from a running Android app's memory for unpacking |
| `rev-u3d-dump` | Extract C# symbols from Unity IL2CPP builds, generate IDA/Ghidra import scripts |
| `rev-idapython` | IDAPython / IDALib script reference covering debugging, memory ops, decompiler API, obfuscation helpers, and batch analysis |
| `rev-ios-dump` | Dump decrypted iOS app binaries from jailbroken devices using frida-ios-dump for security analysis |
| `rev-lief` | Read-only ELF/PE/Mach-O structure, libraries, imports/exports and architecture inspection through the official LIEF Python SDK |
| `rev-angr` | Bounded argv/stdin solving through angr with candidate replay in the model; no native sample execution |

### Read-only LIEF extension in this fork

`rev-lief` works independently of IDA-NO-MCP. It is not a decompiler or binary patcher. Use an existing verified Python environment that imports `lief`; the Skill does not install dependencies, modify samples, or connect to third-party MCP servers.

In magpie's App Library, import the subtree URL and select `rev-lief`:

```text
https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-lief
```

Install this new Skill separately; updating existing entries does not add it automatically. On Pi, invoke `/skill:rev-lief` with your task. Explicit approval of target, read-only action and new output directory is still required. The runner targets POSIX: Linux tested, native Windows unsupported, macOS untested. See [usage and limitations](skills/rev-lief/references/usage.md).

### Bounded angr solving extension in this fork

`rev-angr` adds symbolic path solving, which the official angr MCP does not expose. It runs independently of MCP and IDA-NO-MCP. Use the official angr MCP for static analysis; this Skill needs an existing verified Python environment that imports `angr`. It does not install dependencies or change client configuration.

Search is bounded by time, memory, steps and active-state count; candidate inputs must pass replay in the model. Simulation is not native execution validation, a negative result does not prove unreachability, and resource limits are not a security sandbox.

In magpie's App Library, import the subtree URL and select `rev-angr` for separate installation:

```text
https://github.com/Luckylos/reverse-skills/tree/main/skills/rev-angr
```

Updating existing entries does not add this Skill automatically. On Pi, invoke `/skill:rev-angr` with your task. Explicit approval of target, analysis action and new output directory is still required. The runner targets POSIX: Linux tested, native Windows unsupported, macOS untested. See [usage and report interpretation](skills/rev-angr/references/usage.md).

## Installation

```bash
npx skills add Luckylos/reverse-skills
```

### Update & Remove

```bash
# Check for updates
npx skills check

# Update
npx skills update

# Remove
npx skills remove rev-symbol rev-struct
```

## License

MIT
