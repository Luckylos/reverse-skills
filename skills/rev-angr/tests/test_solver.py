"""Tests for the rev-angr supervisor and worker.

The fixtures are compiled C programs that the tests never execute: the solver only models them.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

import fixtures

HERE = Path(__file__).resolve().parent
SOLVER = HERE.parent / 'scripts' / 'solve.py'
WORKER = HERE.parent / 'scripts' / 'angr_worker.py'
INTERPRETER = sys.executable


def load_supervisor():
    spec = importlib.util.spec_from_file_location('rev_angr_solve', SOLVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SUPERVISOR = load_supervisor()


def found_worker_report():
    return {'status': 'found', 'executed_natively': False, 'angr_version': 'test',
            'binary': {'path': './sample', 'sha256': 'a' * 64},
            'input': {'mode': 'argv', 'length': 6, 'charset': 'any',
                      'sha256': hashlib.sha256(b'ABCDEF').hexdigest()},
            'resolved_targets': {'find': [{'target': 'stdout:WIN', 'kind': 'stdout', 'text': 'WIN'}],
                                 'avoid': []},
            'limits': {'timeout': 120, 'memory_mib': 4096, 'max_steps': 2000,
                       'max_active': 256, 'max_input_mib': 256},
            'exploration': {'steps': 1, 'budget_hit': False, 'budget_reason': None,
                            'states': {'found': 1}, 'errors': [], 'replay_steps': 1},
            'caveats': ['simulation only'], 'elapsed_seconds': 0.1, 'message': '',
            'solution': {'hex': '414243444546', 'text': 'ABCDEF', 'matched_target': 'stdout:WIN'},
            'validation': {'constraints_satisfied': True, 'replay_in_simulation': True}}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def processes_with(marker):
    found = []
    for entry in os.listdir('/proc'):
        if not entry.isdigit():
            continue
        try:
            with open('/proc/' + entry + '/cmdline', 'rb') as stream:
                if marker.encode() in stream.read():
                    found.append(entry)
        except OSError:
            continue
    return found


class SolverCase(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='rev-angr-test-'))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)

    def build(self, name):
        return fixtures.build(self.work, name)

    def run_cli(self, *arguments, timeout=600):
        return subprocess.run([INTERPRETER, str(SOLVER), *[str(item) for item in arguments]],
                              capture_output=True, text=True, timeout=timeout)

    def run_search(self, binary, *extra, find=('sym:win',), spec='argv:6', name='out'):
        output = self.work / name
        arguments = [binary, '--output', output, '--authorized', '--input', spec]
        for target in find:
            arguments += ['--find', target]
        arguments += list(extra)
        completed = self.run_cli(*arguments)
        path = output / 'report.json'
        report = json.loads(path.read_text()) if path.is_file() else None
        return completed, output, report

    def test_argv_search_finds_a_valid_input(self):
        binary = self.build('argv')
        before = digest(binary)
        completed, output, report = self.run_search(binary)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report['status'], 'found')
        self.assertIs(report['executed_natively'], False)
        solution = bytes.fromhex(report['solution']['hex'])
        self.assertEqual(len(solution), 6)
        self.assertEqual(fixtures.weight(solution), fixtures.TARGET_WEIGHT)
        self.assertTrue(report['result']['validation']['constraints_satisfied'])
        self.assertTrue(report['result']['validation']['replay_in_simulation'])
        self.assertEqual(report['solution']['matched_target'], 'sym:win')
        self.assertEqual(digest(binary), before)

    def test_stdin_search_finds_a_valid_input(self):
        binary = self.build('stdin')
        completed, output, report = self.run_search(binary, spec='stdin:6')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(report['status'], 'found')
        solution = bytes.fromhex(report['solution']['hex'])
        self.assertEqual(fixtures.weight(solution), fixtures.TARGET_WEIGHT)
        self.assertTrue(report['result']['validation']['replay_in_simulation'])

    def test_avoided_target_is_not_the_one_reached(self):
        binary = self.build('argv')
        completed, output, report = self.run_search(binary, '--avoid', 'sym:win')
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertIn(report['status'], ('not_found_exhausted', 'not_found_budget'))
        self.assertNotIn('solution', report)

    def test_unreachable_target_reports_exhaustion(self):
        binary = self.build('argv')
        completed, output, report = self.run_search(binary, find=('sym:never_called',))
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(report['status'], 'not_found_exhausted')
        self.assertIn('no path was found', report['result']['caveats'][-1])

    def test_step_budget_is_reported_not_hidden(self):
        binary = self.build('argv')
        completed, output, report = self.run_search(binary, '--max-steps', '5')
        self.assertEqual(completed.returncode, 1, completed.stderr)
        self.assertEqual(report['status'], 'not_found_budget')
        self.assertEqual(report['result']['exploration']['budget_reason'], 'max_steps')
        self.assertTrue(report['result']['exploration']['budget_hit'])

    def test_output_directory_is_private_and_files_are_bounded(self):
        binary = self.build('argv')
        completed, output, report = self.run_search(binary)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for name in ('request.json', 'report.json', 'worker-report.json'):
            self.assertEqual(stat.S_IMODE((output / name).stat().st_mode), 0o600, name)

    def test_existing_output_is_never_overwritten(self):
        binary = self.build('argv')
        output = self.work / 'taken'
        output.mkdir()
        marker = output / 'marker'
        marker.write_text('keep')
        completed = self.run_cli(binary, '--output', output, '--authorized', '--find', 'sym:win',
                                 '--input', 'argv:6')
        self.assertEqual(completed.returncode, 2)
        self.assertIn('output already exists', completed.stderr)
        self.assertEqual(marker.read_text(), 'keep')
        self.assertEqual(os.listdir(output), ['marker'])

    def test_output_symlink_is_rejected(self):
        binary = self.build('argv')
        real = self.work / 'real'
        real.mkdir()
        link = self.work / 'link'
        link.symlink_to(real)
        completed = self.run_cli(binary, '--output', link, '--authorized', '--find', 'sym:win',
                                 '--input', 'argv:6')
        self.assertEqual(completed.returncode, 2)
        self.assertIn('output already exists', completed.stderr)
        self.assertEqual(os.listdir(real), [])

    def test_authorization_flag_is_required(self):
        binary = self.build('argv')
        completed = self.run_cli(binary, '--output', self.work / 'out', '--find', 'sym:win',
                                 '--input', 'argv:6')
        self.assertEqual(completed.returncode, 2)
        self.assertFalse((self.work / 'out').exists())

    def test_unknown_symbol_is_an_error(self):
        binary = self.build('argv')
        completed, output, report = self.run_search(binary, find=('sym:no_such_function',))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report['status'], 'error')
        self.assertIn('no such symbol', report['message'])

    def test_address_outside_executable_section_is_an_error(self):
        binary = self.build('argv')
        completed, output, report = self.run_search(binary, find=('0xdeadbeef',))
        self.assertEqual(completed.returncode, 2)
        self.assertEqual(report['status'], 'error')
        self.assertIn('executable section', report['message'])

    def test_input_length_is_bounded(self):
        binary = self.build('argv')
        completed = self.run_cli(binary, '--output', self.work / 'out', '--authorized',
                                 '--find', 'sym:win', '--input', 'argv:5000')
        self.assertEqual(completed.returncode, 2)
        self.assertIn('between', completed.stderr)

    def test_invalid_target_syntax_is_rejected(self):
        binary = self.build('argv')
        completed = self.run_cli(binary, '--output', self.work / 'out', '--authorized',
                                 '--find', 'stdout:with\ttab', '--input', 'argv:6')
        self.assertEqual(completed.returncode, 2)

    def test_worker_report_schema_is_enforced(self):
        good = {'status': 'not_found_exhausted', 'executed_natively': False, 'angr_version': 'x',
                'binary': {'sha256': 'a' * 64}, 'input': {}, 'limits': {}, 'elapsed_seconds': 1.0,
                'caveats': [], 'exploration': {'steps': 0, 'budget_hit': False, 'states': {}}}
        self.assertIs(SUPERVISOR.validate_worker_report(good), good)
        for mutation in ({'executed_natively': True},
                         {'status': 'maybe'},
                         {'exploration': {'steps': 1, 'budget_hit': 'yes'}},
                         {'caveats': 'none'},
                         {'elapsed_seconds': True}):
            broken = dict(good, **mutation)
            with self.assertRaises(ValueError, msg=str(mutation)):
                SUPERVISOR.validate_worker_report(broken)
        for mutation in ({'solution': None}, {'validation': {'constraints_satisfied': False,
                                                            'replay_in_simulation': True}}):
            broken = dict(good, status='found', **mutation)
            with self.assertRaises(ValueError, msg=str(mutation)):
                SUPERVISOR.validate_worker_report(broken)

    def test_valid_found_worker_report_is_accepted(self):
        report = found_worker_report()
        self.assertIs(SUPERVISOR.validate_worker_report(report), report)

    def test_found_worker_report_requires_both_validations_to_be_true(self):
        good = found_worker_report()
        for field in ('constraints_satisfied', 'replay_in_simulation'):
            for value in (False, None, 0, 1, 'true', 'false', [], {}, 'missing'):
                with self.subTest(field=field, value=value):
                    report = copy.deepcopy(good)
                    if value == 'missing':
                        del report['validation'][field]
                    else:
                        report['validation'][field] = value
                    with self.assertRaises(ValueError):
                        SUPERVISOR.validate_worker_report(report)

    def test_main_rejects_invalid_replay_with_error_exit_two(self):
        binary = self.work / 'sample'
        binary.write_bytes(b'never executed')
        before = digest(binary)
        for index, value in enumerate((True, False, None, 0, 1, 'true', 'missing')):
            with self.subTest(replay=value):
                worker_report = found_worker_report()
                if value == 'missing':
                    del worker_report['validation']['replay_in_simulation']
                else:
                    worker_report['validation']['replay_in_simulation'] = value
                output = self.work / ('out-' + str(index))

                def emit_report(command, timeout, stdout, stderr):
                    SUPERVISOR.private_json(output / 'worker-report.json', worker_report)
                    return {'outcome': 'ok', 'exit_code': 0}

                with mock.patch.object(SUPERVISOR, 'run_worker', side_effect=emit_report), \
                        contextlib.redirect_stdout(io.StringIO()):
                    code = SUPERVISOR.main([str(binary), '--output', str(output), '--authorized',
                                            '--find', 'stdout:WIN', '--input', 'argv:6',
                                            '--charset', 'any'])
                report = json.loads((output / 'report.json').read_text())
                self.assertIs(report['executed_natively'], False)
                if value is True:
                    self.assertEqual(code, 0)
                    self.assertEqual(report['status'], 'found')
                    self.assertEqual(report['result'], worker_report)
                    self.assertEqual(report['solution'], worker_report['solution'])
                else:
                    self.assertEqual(code, 2)
                    self.assertEqual(report['status'], 'error')
                    self.assertIsNone(report['result'])
                    self.assertNotIn('solution', report)
                    self.assertIn('replay_in_simulation', report['message'])
        self.assertEqual(digest(binary), before)

    def test_worker_replay_failure_and_budget_exhaustion_are_errors(self):
        spec = importlib.util.spec_from_file_location('rev_angr_worker', WORKER)
        worker = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', list(sys.path)), \
                mock.patch.dict(sys.modules, {'solve': SUPERVISOR}):
            spec.loader.exec_module(worker)
        binary = self.work / 'sample'
        binary.write_bytes(b'never executed')
        before = digest(binary)
        request = {'binary': str(binary), 'input_spec': 'argv:6', 'charset': 'any',
                   'find': ['stdout:WIN'], 'avoid': [], 'timeout': 120, 'memory_mib': 4096,
                   'max_steps': 2000, 'max_active': 256, 'max_input_mib': 256}
        found = SimpleNamespace(addr=0, solver=SimpleNamespace(eval=lambda *a, **kw: b'ABCDEF'),
                                posix=SimpleNamespace(dumps=lambda fd: b'WIN'))
        initial = SimpleNamespace(stashes={'found': [found]}, errored=[])
        # Only the expensive search and angr construction are faked; replay, solve, and main run.
        project = SimpleNamespace(factory=SimpleNamespace(entry_state=lambda **kw: object()))
        fake_angr = SimpleNamespace(__version__='test', Project=lambda *a, **kw: project,
                                    claripy=SimpleNamespace(BVS=lambda *a: object()))
        cases = (('success', True, None), ('failed', False, None),
                 ('steps', False, 'max_steps'), ('active', False, 'max_active'), ('time', False, 'time'))
        for name, replayed, reason in cases:
            with self.subTest(replay=name):
                output = self.work / name
                output.mkdir()
                request_path = output / 'request.json'
                SUPERVISOR.private_json(request_path, request)
                replay_stashes = {'found': [found]} if replayed else {'deadended': [object()]}
                replay_result = SimpleNamespace(stashes=replay_stashes, errored=[])
                searches = [(initial, 1, None), (replay_result, 1, reason)]
                argv = [str(WORKER), '--request', str(request_path), '--output', str(output)]
                with mock.patch.dict(sys.modules, {'angr': fake_angr}), \
                        mock.patch.object(worker, 'run_search', side_effect=searches), \
                        mock.patch.object(worker, 'restrict'), mock.patch.object(sys, 'argv', argv), \
                        contextlib.redirect_stderr(io.StringIO()):
                    code = worker.main()
                report = json.loads((output / 'worker-report.json').read_text())
                self.assertIs(report['executed_natively'], False)
                if replayed:
                    self.assertEqual(code, 0)
                    self.assertEqual(report['status'], 'found')
                    self.assertEqual(report['validation'], {'constraints_satisfied': True,
                                                            'replay_in_simulation': True})
                    SUPERVISOR.validate_worker_report(report)
                else:
                    self.assertEqual(code, 1)
                    self.assertEqual(report['status'], 'error')
                    self.assertNotIn('solution', report)
                    self.assertIn('replay', report['message'])
                    self.assertLessEqual(len(report['message']), 550)
        self.assertEqual(digest(binary), before)

    def test_unusable_worker_report_fails_closed(self):
        output = self.work / 'out'
        output.mkdir()
        broken = output / 'worker-report.json'
        valid = json.dumps({'status': 'not_found_exhausted', 'executed_natively': False,
                            'angr_version': 'x', 'binary': {'sha256': 'a' * 64},
                            'input': {}, 'limits': {}, 'elapsed_seconds': 1.0, 'caveats': [],
                            'exploration': {'steps': 0, 'budget_hit': False, 'states': {}}})
        # Duplicated field names are accepted last-value-wins by default, so a tampered report
        # could rewrite `status` to `found`. This injection repeats `angr_version` so that,
        # without the hook, the document would still validate as a whole; the hook itself is
        # key-agnostic and covers `status` too.
        duplicated = '{"angr_version": "y", ' + valid[1:]
        for payload in ('{"status": "found"}', 'not json', '[]',
                        '{"status": "found", "solution": {"hex": "zz"}}', duplicated):
            broken.write_text(payload)
            with self.assertRaises(ValueError, msg=payload):
                SUPERVISOR.read_worker_report(output)
        broken.write_text('0' * (SUPERVISOR.REPORT_BYTES + 1))
        with self.assertRaises(ValueError):
            SUPERVISOR.read_worker_report(output)

    def test_run_worker_kills_the_whole_group_on_timeout(self):
        marker = 'revangr-' + uuid.uuid4().hex
        stub = ('import subprocess, sys, time; '
                'subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", '
                '"%s-kid"]); time.sleep(30)') % marker
        started = time.monotonic()
        record = SUPERVISOR.run_worker([INTERPRETER, '-c', stub, marker], 1,
                                       self.work / 'stdout.log', self.work / 'stderr.log')
        elapsed = time.monotonic() - started
        self.assertEqual(record['outcome'], 'timeout')
        self.assertTrue(record['reaped'])
        self.assertTrue(record['signalled'])
        self.assertEqual(record['exit_code'], -signal.SIGKILL)
        self.assertLess(elapsed, 10)
        deadline = time.monotonic() + 5
        while processes_with(marker) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(processes_with(marker), [])
        self.assertEqual(stat.S_IMODE((self.work / 'stdout.log').stat().st_mode), 0o600)

    def test_run_worker_reports_the_real_exit_status(self):
        record = SUPERVISOR.run_worker([INTERPRETER, '-c', 'raise SystemExit(3)'], 30,
                                       self.work / 'stdout.log', self.work / 'stderr.log')
        self.assertEqual(record['outcome'], 'ok')
        self.assertEqual(record['exit_code'], 3)
        self.assertFalse(record['signalled'])

    def test_signalling_after_reaping_is_refused(self):
        child = subprocess.Popen([INTERPRETER, '-c', 'import time; time.sleep(30)'],
                                 start_new_session=True)
        pgid = os.getpgid(child.pid)
        try:
            os.waitpid(child.pid, 0)
            record = {'reaped': True, 'signalled': False}
            with self.assertRaises(ValueError):
                SUPERVISOR.kill_group(child.pid, pgid, record)
            self.assertFalse(record['signalled'])
        finally:
            if child.poll() is None:
                os.killpg(pgid, signal.SIGKILL)
                child.wait()

    def test_unrelated_pid_is_not_signalled(self):
        child = subprocess.Popen([INTERPRETER, '-c', 'import time; time.sleep(30)'],
                                 start_new_session=True)
        try:
            self.assertNotEqual(os.getpgid(child.pid), os.getpgid(0))
            record = {'reaped': False, 'signalled': False}
            with self.assertRaises(ValueError):
                SUPERVISOR.kill_group(child.pid, os.getpgid(0), record)
            self.assertIsNone(child.poll())
        finally:
            os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            child.wait()


if __name__ == '__main__':
    unittest.main()
