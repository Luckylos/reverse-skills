---
name: rev-frida
description: Generate Frida hook scripts using modern Frida API. Activate when the user wants to write Frida scripts, hook functions at runtime, trace calls or arguments or return values, intercept native or ObjC or Java methods, dump memory or exports, or handle native module load timing for Android and other targets.
---

# rev-frida - Frida Script Generator

## Runtime preflight

Select an existing runtime before generating or running scripts; see [runtime selection and official evidence](references/runtime.md). Reuse provisioned CLI/SDK tools, keeping specialized environments (such as iOS dumping) separate. Check the host binding, target backend, OS/CPU/ABI, and bridge delivery explicitly. An available CLI proves none of these.

Local version checks do not connect to devices. Device enumeration (including `frida-ps -U`), `adb` commands, attach, spawn, and script loading are target interactions requiring approval. Instrumentation changes target memory; it is **not read-only**. Do not install, download, launch a server, connect, elevate privileges, or change security settings automatically.

Generate Frida instrumentation scripts for dynamic analysis, hooking, and runtime inspection.

## Overview

Use Frida for:
- native export hooks
- Java or ObjC method hooks
- runtime tracing
- argument or return-value capture
- memory dumping
- loader-aware native instrumentation

## Important: Modern Frida CLI

Use these only after approval for the selected target. The current REPL automatically resumes a spawned process after loading the script; `--pause` deliberately leaves it paused. Do not use the obsolete `--no-pause` flag.

```bash
# Spawn an app (-f); -U selects a USB device
frida -U -f com.example.app -l hook.js

# Attach by process name (-n), app identifier (-N), or PID (-p)
frida -U -n ExampleProcess -l hook.js
frida -U -N com.example.app -l hook.js
frida -U -p 1234 -l hook.js

# Deliberately pause the spawned app; resume with %resume when ready
frida -U -f com.example.app -l hook.js --pause
```

Detach releases instrumentation; it is not a resume or kill operation. Track whether you spawned/paused the target and explicitly decide its final state. Avoid eternalizing scripts; release listeners/observers and detach the session when finished.

## Modern API Reference

### Module & Symbol Lookup

```javascript
const mod = Process.getModuleByName("libssl.so");

mod.name;
mod.base;
mod.size;
mod.path;

const ptr = mod.getExportByName("SSL_read");

Process.enumerateModules();
mod.enumerateExports();
mod.enumerateImports();

// Only when the owning module is unknown; global lookup can be costly.
const addr = Module.findGlobalExportByName("open");
if (addr === null) {
    console.log("open export unavailable");
}
```

Known module preferred: use `Process.findModuleByName(name)` and check for `null`, then `mod.findExportByName(name)` and check for `null`. The `get` counterparts throw on absence. Use `mod.base` for a base address, not removed static Module methods. The following API fragments are independent; verify the actual signature and module on the selected platform.

### Interceptor

```javascript
Interceptor.attach(ptr, {
    onEnter(args) {
        console.log("arg0:", args[0].toInt32());
        try {
            console.log("arg1 str:", args[1].isNull() ? null : args[1].readUtf8String(128));
        } catch (e) {
            console.log("unreadable argument:", String(e));
        }
    },
    onLeave(retval) {
        console.log("ret:", retval.toInt32());
    }
});

Interceptor.replace(ptr, new NativeCallback(function (a0, a1) {
    console.log("replaced");
    return 0;
}, "int", ["pointer", "int"]));
```

### NativeFunction & NativeCallback

```javascript
// Android example: choose the actual libc module name for your target.
const libc = Process.getModuleByName("libc.so");
const open = new NativeFunction(
    libc.getExportByName("open"),
    "int",
    ["pointer", "int"]
);

const fd = open(Memory.allocUtf8String("/etc/hosts"), 0);

const cb = new NativeCallback(function (arg) {
    console.log("called with:", arg);
    return 0;
}, "int", ["int"]);
```

### Memory Operations

Validate addresses, readable ranges, lengths, and the actual ABI first; catch read faults. Bound dumps/scans to the approved region and avoid logging secrets. Writes/replacements require explicit authorization; do not combine the attach and replace fragments indiscriminately. Keep listener handles for `detach()` and undo replacements with `Interceptor.revert(target)`.

```javascript
ptr(addr).readByteArray(size);
ptr(addr).readUtf8String(128);
ptr(addr).readU32();
ptr(addr).readPointer();

ptr(addr).writeByteArray(bytes);
ptr(addr).writeUtf8String("hello");
ptr(addr).writeU32(0x41414141);

const buf = Memory.alloc(256);
const str = Memory.allocUtf8String("hello");

Memory.scan(mod.base, mod.size, "48 89 5C 24 ?? 48 89 6C", {
    onMatch(address, size) {
        console.log("found at:", address);
    },
    onComplete() {}
});
```

### ObjC

```javascript
if (typeof ObjC !== "undefined" && ObjC.available) {
    const hook = ObjC.classes.ClassName["- methodName:"];
    Interceptor.attach(hook.implementation, {
        onEnter(args) {
            const selfObj = new ObjC.Object(args[0]);
            const param = new ObjC.Object(args[2]);
            console.log(selfObj.toString());
            console.log(param.toString());
        }
    });
}
```

### Java

```javascript
if (typeof Java !== "undefined" && Java.available) {
    Java.perform(function () {
        const Activity = Java.use("android.app.Activity");
        Activity.onCreate.implementation = function (bundle) {
            console.log("onCreate called");
            return this.onCreate(bundle);
        };
    });
}
```

Frida 17 bare GumJS does not include these bridges. The `typeof` guards prevent a missing-global error; they do **not** load a bridge. REPL/frida-trace bridge convenience differs from a Python `create_script()` agent. For custom agents use explicit imports and an approved compiler/dependency flow in [runtime.md](references/runtime.md). Class/method names remain target-specific; verify them before hooking.

## Script Generation Guidelines

When generating Frida scripts:

1. Always use the modern API such as `Process.getModuleByName()` and `mod.getExportByName()`.
2. Do not use `--no-pause`.
3. Prefer load-event-driven native hooking over polling.
4. Print pointers and buffers in readable form.
5. Wrap risky hooks in `try/catch`.
6. Use `hexdump()` for binary inspection.

### Handle Native Module Load Timing

Use `Process.attachModuleObserver()` normally, not duplicate `dlopen` interceptors or unbounded polling. It immediately reports existing modules and synchronously reports newly loaded modules before the application uses them. This is **not a guarantee of pre-constructor timing**. Investigate initialization timing separately only when evidence requires it.

### Native observer example

Complete Linux example for an approved local target: observe the known libc module and hook the benign `getpid` export. Change only the module/export to ones verified for your target. An absent module leaves the observer waiting; an absent export reports the condition without attaching. Existing modules are handled by the same callback, without a separate racy lookup. Keep this heading stable: the regression test executes this exact block.

```javascript
const moduleName = "libc.so.6";
const exportName = "getpid";
let listener = null;
let hookedBase = null;

let observer = Process.attachModuleObserver({
    onAdded(mod) {
        if (mod.name !== moduleName || listener !== null) return;
        try {
            const address = mod.findExportByName(exportName);
            if (address === null) {
                send({ event: "missing-export", name: exportName });
                return;
            }
            listener = Interceptor.attach(address, {
                onEnter() {
                    send({ event: "hook", name: exportName });
                }
            });
            hookedBase = mod.base;
        } catch (e) {
            send({ event: "error", message: String(e) });
        }
    },
    onRemoved(mod) {
        if (hookedBase === null || !mod.base.equals(hookedBase)) return;
        try {
            if (listener !== null) listener.detach();
        } catch (e) {
            send({ event: "error", message: String(e) });
        } finally {
            listener = null;
            hookedBase = null;
        }
    }
});
send({ event: "ready", hooked: listener !== null });

recv("stop", function () {
    observer.detach();
    observer = null;
    if (listener !== null) listener.detach();
    listener = null;
    hookedBase = null;
    Interceptor.flush();
    send({ event: "stopped", observer: observer !== null, hooks: listener === null ? 0 : 1 });
});
```

The SDK host sends `script.post({"type": "stop"})` and waits for `stopped` before unloading the script and detaching the session. Do not ignore `error` messages: stop and diagnose, without changing security settings. Scope this one-module example to a single verified module; it does not manage multiple same-named copies. Removal clears the listener so a later reload can be hooked. Set a bounded host-side observation deadline; on timeout stop the observer/listener even if no module/export appeared. Script unload/session detach is final cleanup if explicit cleanup fails. No constructor or real-device coverage is implied.

### Do Not Blindly Hook init Series Functions

Do not tell the user to hook `.init`, `.init_array`, constructors, or `JNI_OnLoad` blindly.

These are fragile points:
- many libraries perform one-time setup there
- bad hooks can crash the process before the real target logic runs
- early hooks can change timing and hide the behavior the user wants to study
- constructor code often fans out into many unrelated helpers

Before suggesting an init-stage hook:
1. identify why early hooking is required
2. identify the exact module and exact initialization routine
3. confirm whether the target symbol or behavior only exists before normal exports are reachable
4. prefer a later stable hook if it gives the same visibility

Prefer this order:
1. hook a stable exported function after module load
2. hook `RegisterNatives`, `dlsym`, or the first real business function
3. hook `JNI_OnLoad` only if native registration or anti-debug setup happens there
4. hook constructors or `.init_array` only if there is strong evidence that the critical logic is there

If proposing an early init hook, state:
- why the normal export hook is insufficient
- what exact function or address should be hooked
- what failure mode to expect
- how to verify the hook did not break initialization

Bad advice: attach to an unverified `mod.base.add(offset)` merely because it resembles an initialization routine.

Better advice:
- wait for module load
- confirm the constructor target by symbols, xrefs, strings, or trace evidence
- attach only after identifying the exact initialization function
- explain the risk to the user before using an init-stage hook

### Prefer Constructor Dispatchers Over Blind init Hooks

If anti-debug logic is suspected inside the constructor chain, prefer observing or hooking the dispatcher first instead of attaching blindly to raw `.init_array` entries.

Useful higher-level targets include:
- `call_constructors`
- `call_array`
- linker-side constructor walkers
- app-side wrapper functions that iterate constructor tables

Why this is safer:
- one hook can reveal the full constructor sequence
- you can see which constructor runs immediately before termination or anti-debug setup
- it reduces blind patching of unrelated initialization code
- it lets you log constructor targets first and patch only the offending one later

Recommended workflow:
1. hook module load
2. identify whether the process terminates during constructor execution
3. if yes, hook `call_constructors` or `call_array` when available
4. log each constructor target as it is dispatched
5. identify the exact constructor that performs anti-debug checks
6. patch or hook that constructor, or patch the specific anti-debug branch inside it

Only suggest `call_constructors` or `call_array` when:
- the target platform or linker build exposes those functions
- symbols, traces, or disassembly indicate they are actually used
- the user needs visibility into constructor-time anti-debug behavior

Warn about these constraints:
- these functions are loader or linker internals and names may vary by Android version, vendor build, or platform
- they may not be exported and may require symbol recovery or offset-based attachment
- hooking them too early can affect every library load, so scope logging carefully
- use them for discovery first, not as a default permanent bypass

Good guidance:
- “The process dies during native library initialization. First hook the constructor dispatcher such as `call_constructors` or `call_array` if present, log the constructor targets, then move to the exact offending constructor.”

Bad guidance:
- “Hook every `.init_array` entry and patch until it stops crashing.”

### Pointer and Buffer Logging

```javascript
console.log(args[0]);
console.log(args[0].toString());
console.log(hexdump(args[0], {
    offset: 0,
    length: 64,
    header: true,
    ansi: false
}));
```
