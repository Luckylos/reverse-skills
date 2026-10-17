"""Portable documentation checks; native opt-in instruments only one owned Python child."""

import contextlib
import importlib.metadata
import io
import os
from pathlib import Path
import queue
import re
import selectors
import shlex
import signal
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import Mock, patch
import uuid


SKILL = Path(__file__).resolve().parents[1] / "SKILL.md"
RUNTIME = SKILL.parent / "references/runtime.md"


def example(heading):
    text = SKILL.read_text(encoding="utf-8")
    section = text.split(heading + "\n", 1)
    if len(section) != 2:
        raise AssertionError("Missing documented example: " + heading)
    match = re.search(r"```javascript\n(.*?)\n```", section[1], re.S)
    if match is None:
        raise AssertionError("Missing JavaScript under " + heading)
    return match[1]


class DocumentationTests(unittest.TestCase):
    def test_no_removed_static_module_calls(self):
        text = SKILL.read_text(encoding="utf-8")
        code = "\n".join(re.findall(r"```javascript\n(.*?)\n```", text, re.S))
        self.assertNotRegex(code, r"\bModule\.(?:get|find)(?:ExportByName|BaseAddress)\s*\(")

    def test_missing_bridges_short_circuit(self):
        for bridge in ("Java", "ObjC"):
            with self.subTest(bridge=bridge):
                code = example("### " + bridge)
                self.assertRegex(
                    code, rf"typeof {bridge} !== ['\"]undefined['\"] && {bridge}\.available"
                )

    def test_native_example_owns_observer_and_listener(self):
        code = example("### Native observer example")
        for api in ("Process.attachModuleObserver(", "mod.findExportByName(", "listener.detach()",
                    "observer.detach()", 'recv("stop"', "onRemoved(mod)"):
            self.assertIn(api, code)
        self.assertNotRegex(code, r"\bdlopen\b|setInterval\(")
        self.assertIn("try {", code)
        self.assertIn("catch (", code)

    def test_cli_uses_explicit_selectors(self):
        text = SKILL.read_text(encoding="utf-8")
        commands = [shlex.split(line) for line in text.splitlines() if line.startswith("frida ")]
        for selector in ("-n", "-N", "-p", "-f", "--pause"):
            with self.subTest(selector=selector):
                self.assertTrue(any(selector in command for command in commands))
        self.assertTrue(all("--no-pause" not in command for command in commands))

    def test_runtime_has_portable_bridge_and_source_guidance(self):
        self.assertTrue(RUNTIME.is_file(), "Missing runtime reference")
        text = RUNTIME.read_text(encoding="utf-8")
        for bridge in ("java", "objc"):
            self.assertIn("from 'frida-" + bridge + "-bridge'", text)
        for term in ("create_script", "frida-compile", "conservative", "ABI", "MCP",
                     "19048c41ce0e307b5eb60a912ab7fec15e919966",
                     "2ff8f72375c8d3d5e53bb3ad250ba240964a4a39"):
            with self.subTest(term=term):
                self.assertIn(term, text)

    def test_no_host_inventory_or_automatic_security_changes(self):
        text = SKILL.read_text(encoding="utf-8")
        if RUNTIME.exists():
            text += RUNTIME.read_text(encoding="utf-8")
        self.assertNotRegex(text, r"/root/|/opt/|\b\d+\.\d+\.\d+\b|127\.0\.0\.1")
        shell = "\n".join(re.findall(r"```bash\n(.*?)\n[ \t]*```", text, re.S))
        self.assertNotRegex(shell, r"\bsudo\b|ptrace_scope|\bnpm install\b|\bpip install\b")
        self.assertIn("FRIDA_TEST_NATIVE=1", text)


def attach_ready_child(test, child, argv, read_line, sdk, get_local_device):
    test.assertEqual(read_line(child.stdout), "ready")
    test.assertEqual(Path(f"/proc/{child.pid}/cmdline").read_bytes().split(b"\0")[:-1],
                     [os.fsencode(arg) for arg in argv])
    device = sdk(get_local_device)
    return sdk(device.attach, child.pid)


class ReadinessTests(unittest.TestCase):
    def test_ready_is_consumed_before_identity_and_attach(self):
        self.check_attachment(b"ready\n", None, True)

    def test_invalid_ready_or_full_argv_never_attaches(self):
        for ready, identity in ((b"wrong\n", None), (b"ready\n", b""),
                                (b"ready\n", b"/owned/python\0"),
                                (b"ready\n", b"/owned/python\0-c\0owned target\0unique-marker\0extra\0")):
            with self.subTest(ready=ready, identity=identity):
                self.check_attachment(ready, identity, False)

    def check_attachment(self, ready, identity, succeeds):
        argv = ["/owned/python", "-c", "owned target", "unique-marker"]
        get_device = Mock()
        with io.BytesIO(ready) as stdout:
            child = Mock(pid=1234, stdout=stdout)

            def cmdline(path):
                self.assertEqual(path, Path("/proc/1234/cmdline"))
                if not stdout.tell():
                    return b""  # Simulate startup identity being unavailable before the ready handshake.
                return b"/owned/python\0-c\0owned target\0unique-marker\0" if identity is None else identity

            with patch.object(Path, "read_bytes", autospec=True, side_effect=cmdline):
                args = (self, child, argv, lambda stream: stream.readline().decode().strip(),
                        lambda operation, *args: operation(*args), get_device)
                if succeeds:
                    self.assertIs(attach_ready_child(*args), get_device.return_value.attach.return_value)
                    get_device.return_value.attach.assert_called_once_with(child.pid)
                else:
                    with self.assertRaises(AssertionError):
                        attach_ready_child(*args)
                    get_device.assert_not_called()
                    get_device.return_value.attach.assert_not_called()


@unittest.skipUnless(os.environ.get("FRIDA_TEST_NATIVE") == "1", "native attach requires explicit opt-in")
class NativeSmokeTest(unittest.TestCase):
    def test_documented_hook_bridge_guards_detach_and_child_cleanup(self):
        # Importing/getting the LOCAL device does not enumerate USB or remote devices.
        import frida

        self.assertEqual(sys.platform, "linux", "Native opt-in is limited to Linux")
        self.assertTrue(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"),
                        "Native opt-in requires pidfd support; no unsafe fallback")
        native = example("### Native observer example")
        bridges = "\n".join(example("### " + name) for name in ("Java", "ObjC"))
        events = queue.Queue()
        detached = threading.Event()
        timers = []

        def sdk(operation, *args):
            cancellable = frida.Cancellable()
            timer = threading.Timer(5, cancellable.cancel)
            timer.daemon = True
            timers.append(timer)
            timer.start()
            try:
                with cancellable:
                    return operation(*args)
            finally:
                timer.cancel()
                timer.join(timeout=1)
                self.assertFalse(timer.is_alive(), "SDK cancellation timer did not stop")

        def message(value, data):
            events.put(value)

        def event(expected):
            value = events.get(timeout=5)
            self.assertEqual(value.get("type"), "send", value)
            payload = value["payload"]
            self.assertEqual(payload.get("event"), expected, payload)
            return payload

        def line(stream):
            deadline = time.monotonic() + 5
            data = b""
            with selectors.DefaultSelector() as selector:
                selector.register(stream, selectors.EVENT_READ)
                while b"\n" not in data:
                    remaining = deadline - time.monotonic()
                    self.assertGreater(remaining, 0, "Child output deadline exceeded")
                    self.assertTrue(selector.select(remaining), "Child output timed out")
                    chunk = os.read(stream.fileno(), 1024)
                    self.assertTrue(chunk, "Child exited before response")
                    data += chunk
                    self.assertLessEqual(len(data), 1024)
            return data.decode().strip()

        def command(value):
            child.stdin.write((value + "\n").encode())
            child.stdin.flush()
            self.assertEqual(line(child.stdout), "called")

        # The pidfd and unique argv marker bind cleanup to this child, never a recycled PID.
        marker = "frida-skill-test-" + uuid.uuid4().hex
        target = (
            "import os, sys\n"
            "print('ready', flush=True)\n"
            "for command in sys.stdin:\n"
            "    if command.strip() == 'exit': break\n"
            "    if command.strip() == 'call':\n"
            "        os.getpid()\n"
            "        print('called', flush=True)\n"
        )
        self.assertEqual(signal.getsignal(signal.SIGCHLD), signal.SIG_DFL, "A reaper would break ownership")
        # Do not copy host credentials, Python startup hooks, or the working directory into the target.
        env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "LC_ALL": "C"}
        argv = [sys.executable, "-I", "-S", "-B", "-u", "-c", target, marker]
        child = subprocess.Popen(
            argv, env=env, cwd="/", bufsize=0,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        pidfd = None
        session = None
        scripts = []
        try:
            pidfd = os.pidfd_open(child.pid)
            session = attach_ready_child(self, child, argv, line, sdk, frida.get_local_device)
            session.on("detached", lambda *args: detached.set())
            script = sdk(session.create_script, native)
            scripts.append(script)
            script.on("message", message)
            sdk(script.load)
            self.assertTrue(event("ready")["hooked"], "Linux libc/getpid hook was not installed")
            command("call")
            self.assertEqual(event("hook")["name"], "getpid")
            sdk(script.post, {"type": "stop"})
            self.assertEqual(event("stopped"), {"event": "stopped", "observer": False, "hooks": 0})
            command("call")
            # A subsequent in-agent call and message flush prove the stopped hook stays silent.
            probe = sdk(session.create_script, bridges + "\n" + """
const getpid = new NativeFunction(Module.getGlobalExportByName('getpid'), 'int', []);
getpid();
send({event: 'checked', java: typeof Java, objc: typeof ObjC});
""")
            scripts.append(probe)
            probe.on("message", message)
            sdk(probe.load)
            self.assertEqual(event("checked"), {"event": "checked", "java": "undefined", "objc": "undefined"})
            for loaded in scripts:
                sdk(loaded.unload)
                self.assertTrue(loaded.is_destroyed, "Unloaded agent still exists")
            scripts.clear()
            sdk(session.detach)
            self.assertTrue(detached.wait(5), "Detach notification timed out")
            self.assertTrue(session.is_detached)
            session = None
            command("call")
            with self.assertRaises(queue.Empty):
                events.get(timeout=0.2)
            print("native: binding=" + frida.__version__ + ", tools="
                  + importlib.metadata.version("frida-tools")
                  + "; hook observed; stopped hook silent; bare bridges absent; detached", flush=True)
        finally:
            try:
                if session is not None:
                    try:
                        for loaded in scripts:
                            sdk(loaded.unload)
                    finally:
                        sdk(session.detach)
            finally:
                try:
                    with contextlib.suppress(BrokenPipeError):
                        child.stdin.write(b"exit\n")
                        child.stdin.flush()
                    if pidfd is None:
                        # Acquisition failed BEFORE attach/any wait: only this unreaped child is owned.
                        child.kill()
                    else:
                        with selectors.DefaultSelector() as selector:
                            selector.register(pidfd, selectors.EVENT_READ)
                            if not selector.select(timeout=3):
                                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            self.assertTrue(selector.select(timeout=3), "Owned child did not exit")
                    # Confirm actual exit via pidfd before wait: a ptrace stop is not process exit.
                    child.wait(timeout=3)
                finally:
                    if pidfd is not None:
                        os.close(pidfd)
                    for stream in (child.stdin, child.stdout, child.stderr):
                        stream.close()
                self.assertIsNotNone(child.returncode)
                self.assertTrue(all(not timer.is_alive() for timer in timers))
                print("native cleanup: pidfd confirmed exit; owned child reaped; timers stopped", flush=True)


if __name__ == "__main__":
    unittest.main()
