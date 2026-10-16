import copy
import hashlib
import importlib.util
import json
import os
import re
import select
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock
from urllib.parse import urlparse

from fixtures import elf, pe, macho, fat_macho

MODULE = Path(__file__).resolve().parents[1]
CLI = MODULE / 'scripts' / 'inspect_binary.py'
SCRATCH = Path(__file__).resolve().parents[4]


class InspectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Fail before spawning children; lifecycle tests deliberately have no PID fallback.
        if (sys.platform != 'linux' or not Path('/proc/self/cmdline').is_file()
                or not hasattr(os, 'pidfd_open')
                or not hasattr(signal, 'pidfd_send_signal')):
            raise RuntimeError('lifecycle tests require Linux /proc and stdlib pidfd APIs')
        fd = os.pidfd_open(os.getpid())
        os.close(fd)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='lief-test-', dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sample = self.root / 'sample ; $ with spaces'
        self.sample.write_bytes(pe())
        self.output = self.root / 'private output'

    def invoke(self, *args, cli=CLI, authorized=True):
        self.assertTrue(cli.is_file(), 'missing read-only inspector implementation')
        cmd = [sys.executable, str(cli), str(self.sample), '--output', str(self.output)]
        if authorized:
            cmd.append('--authorized')
        return subprocess.run(cmd + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=15)

    def read_report(self):
        return json.loads((self.output / 'report.json').read_text())

    def successful(self, blob=None, *args):
        if blob is not None:
            self.sample.write_bytes(blob)
        before = hashlib.sha256(self.sample.read_bytes()).hexdigest()
        result = self.invoke(*args)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        report = self.read_report()
        self.assertEqual(report['input']['sha256'], before)
        self.assertEqual(hashlib.sha256(self.sample.read_bytes()).hexdigest(), before)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['schema_version'], 1)
        self.assertTrue(report['sdk_version'])
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        return report

    def test_real_pe_named_ordinal_and_export_table(self):
        r = self.successful()['slices']['items'][0]
        self.assertEqual(r['entrypoint'], {'value': '0x1000', 'coordinate': 'RVA'})
        imports = r['imports']['items']
        self.assertTrue(any(x['name'] == 'NamedImport' and x['library'] == 'KERNEL32.dll' for x in imports))
        self.assertTrue(any(x['ordinal'] == 7 and x['name'] is None for x in imports))
        exports = r['exports']['items']
        self.assertTrue(any(x['name'] == 'ExportedHelper' for x in exports))
        self.assertTrue(any(x['name'] is None and x['ordinal'] == 2 for x in exports))
        self.assertEqual(exports[0]['address_coordinate'], 'RVA')
        self.assertEqual(r['sections']['items'][0]['name'], '.rdata')

    def test_real_elf_native_symbol_tables(self):
        self.sample = elf(self.root)
        r = self.successful()
        self.assertEqual(r['family'], 'ELF')
        sl = r['slices']['items'][0]
        self.assertEqual(sl['entrypoint']['coordinate'], 'VA')
        self.assertTrue(any(x['name'] == 'puts' for x in sl['imports']['items']))
        self.assertTrue(any(x['name'] == 'helper' for x in sl['exports']['items']))

    def test_real_thin_macho_no_entrypoint(self):
        r = self.successful(macho())
        self.assertEqual(r['family'], 'MachO')
        sl = r['slices']['items'][0]
        self.assertIn('X86_64', sl['architecture'])
        self.assertIsNone(sl['entrypoint'])
        self.assertEqual(sl['sections']['items'][0]['name'], '__text')

    def test_real_fat_macho_all_slices(self):
        r = self.successful(fat_macho())
        self.assertEqual(len(r['slices']['items']), 2)
        self.assertFalse(r['slices']['truncated'])
        self.assertIn('ARM64', r['slices']['items'][1]['architecture'])

    def test_disclosed_count_clipping(self):
        r = self.successful(fat_macho(), '--max-slices', '1', '--max-items', '1')
        self.assertTrue(r['slices']['truncated'])
        self.assertEqual(r['slices']['total'], 2)

    def test_item_clipping(self):
        r = self.successful(None, '--max-items', '1')
        self.assertTrue(r['slices']['items'][0]['imports']['truncated'])

    def test_no_authorization_no_writes(self):
        self.assertNotEqual(self.invoke(authorized=False).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_existing_output_never_overwritten(self):
        self.output.mkdir()
        marker = self.output / 'marker'
        marker.write_text('preserve')
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(marker.read_text(), 'preserve')
        self.assertEqual(list(self.output.iterdir()), [marker])

    def test_symlink_output_rejected(self):
        self.output.symlink_to(self.root / 'nonexistent', target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse((self.root / 'nonexistent').exists())

    def test_invalid_limits_duplicate_flags_no_writes(self):
        for args in [('--max-items', '0'), ('--max-items', 'true'), ('--timeout', '-1'),
                     ('--memory-mib', '0'), ('--max-slices', '999999'),
                     ('--output', str(self.root / 'other')), ('--authorized',)]:
            with self.subTest(args=args):
                self.assertNotEqual(self.invoke(*args).returncode, 0)
                self.assertFalse(self.output.exists())

    def test_invalid_input_no_writes(self):
        self.sample = self.root
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.output.exists())

    def test_size_limit_no_writes(self):
        with self.sample.open('wb') as f:
            f.truncate(2*1024*1024)
        self.assertNotEqual(self.invoke('--max-input-mib', '1').returncode, 0)
        self.assertFalse(self.output.exists())

    def test_unknown_and_truncated_input(self):
        for blob in [b'unknown', b'\x7fELF', b'MZ', b'\xcf\xfa\xed\xfe']:
            with self.subTest(blob=blob):
                self.sample.write_bytes(blob)
                self.output = self.root / ('out' + str(len(list(self.root.iterdir()))))
                self.assertNotEqual(self.invoke().returncode, 0)

    def copied_cli(self, code):
        self.assertTrue(CLI.is_file(), 'missing read-only inspector implementation')
        scripts = self.root / 'scripts'
        scripts.mkdir()
        shutil.copyfile(CLI, scripts / CLI.name)
        (scripts / 'lief_worker.py').write_text(code)
        return scripts / CLI.name

    def fake_prefix(self):
        return '''import json, pathlib, sys, os, time, signal
q=json.loads(pathlib.Path(sys.argv[1]).read_text())
o=pathlib.Path(q['output'])
r={'schema_version':1,'status':'ok','input':q['input'],'limits':q['limits'],
'sdk_version':'test','family':'PE','slices':{'total':1,'truncated':False,'items':[
{'architecture':'TEST','header':{'characteristics':'0x2022','optional_magic':'PE32_PLUS','imagebase':'0x140000000'},
'entrypoint':{'value':'0x0','coordinate':'RVA'},
'sections':{'total':0,'truncated':False,'items':[]},
'libraries':{'total':0,'truncated':False,'items':[]},
'imports':{'total':0,'truncated':False,'items':[]},
'exports':{'total':0,'truncated':False,'items':[]}}]}}
'''

    def test_worker_crash(self):
        cli = self.copied_cli('import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n')
        self.assertNotEqual(self.invoke(cli=cli).returncode, 0)

    def test_missing_sdk_is_explicit_failure(self):
        self.assertTrue(CLI.is_file(), 'missing read-only inspector implementation')
        scripts = self.root / 'scripts'
        shutil.copytree(MODULE / 'scripts', scripts)
        (scripts / 'lief.py').write_text('raise ImportError("controlled missing SDK")\n')
        result = self.invoke(cli=scripts / CLI.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'controlled missing SDK', (self.output / 'diagnostics.log').read_bytes())

    def test_worker_malformed_reports(self):
        mutations = ["r['input']['sha256']='0'*64", "r['schema_version']=True",
                     "r['slices']['items']=[]", "r['slices']['items'][0]['architecture']=''",
                     "r['limits']['max_items']=True", "r['slices']['total']=True",
                     "r['slices']['items'][0]['entrypoint']={'coordinate':'VA','value':9007199254740993}",
                     "r['slices']['items'][0]['sections']['items']=[{'name':'x'}]",
                     "r['status']='partial'", "r['family']='UNKNOWN'"]
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation):
                # Independent copy; never overwrite a live output or helper.
                case = self.root / str(index)
                case.mkdir()
                cli = case / CLI.name
                shutil.copyfile(CLI, cli) if CLI.exists() else self.assertTrue(False, 'missing implementation')
                (case / 'lief_worker.py').write_text(self.fake_prefix() + mutation +
                    "\n(o/'worker-report.json').write_text(json.dumps(r))\n")
                self.output = case / 'output'
                self.assertNotEqual(self.invoke(cli=cli).returncode, 0)

    def test_oversized_report(self):
        cli = self.copied_cli(self.fake_prefix() + "(o/'worker-report.json').write_bytes(b' '* (8*1024*1024+1))\n")
        self.assertNotEqual(self.invoke(cli=cli).returncode, 0)

    def test_native_diagnostics_mean_partial(self):
        cli = self.copied_cli(self.fake_prefix() + "print('native parser warning',file=sys.stderr)\n(o/'worker-report.json').write_text(json.dumps(r))\n")
        self.assertNotEqual(self.invoke(cli=cli).returncode, 0)
        self.assertEqual(self.read_report()['status'], 'partial')
        self.assertIn(b'native parser warning', (self.output / 'diagnostics.log').read_bytes())

    def test_input_change_is_failure(self):
        cli = self.copied_cli(self.fake_prefix() + "pathlib.Path(q['path']).write_bytes(b'changed')\n(o/'worker-report.json').write_text(json.dumps(r))\n")
        self.assertNotEqual(self.invoke(cli=cli).returncode, 0)

    def test_cleanup_case_never_signals_known_gone_pid(self):
        for identity in ('gone', 'zombie'):
            with self.subTest(identity=identity):
                self._mock_cleanup_identity(identity, successful=True)

    def test_cleanup_case_rejects_unknown_or_dead_identity(self):
        for identity in ('missing', 'zero', 'absent', 'reused', 'mismatched',
                         'unreadable', 'exited-during-check'):
            with self.subTest(identity=identity):
                self._mock_cleanup_identity(identity)

    def test_cleanup_case_signals_only_verified_pidfd_on_failure(self):
        self._mock_cleanup_identity('owned')

    def test_cleanup_case_timeout_still_cleans_verified_child(self):
        self._mock_cleanup_identity('owned', timeout=True)

    def _mock_cleanup_identity(self, identity, successful=False, timeout=False):
        # All process operations are mocked: never send a real signal or reuse a PID.
        pid, fd, marker = 987654321, 71, 'unique-test-child-marker'
        pidfile = self.output / 'child.pid'
        self.output.mkdir(exist_ok=True)
        if identity != 'missing':
            pidfile.write_text('0' if identity == 'zero' else str(pid))
        elif pidfile.exists():
            pidfile.unlink()
        original_exists = Path.exists
        original_read_text = Path.read_text

        def exists(path):
            if str(path).startswith('/proc/'):
                return identity != 'gone'
            return original_exists(path)

        def read_text(path, *args, **kwargs):
            if str(path).startswith('/proc/'):
                state = 'Z' if identity == 'zombie' else 'S'
                return f'{pid} (python) {state} 1 1 1'
            return original_read_text(path, *args, **kwargs)

        polls = ([[(fd, select.POLLIN)]] if identity == 'reused' else
                 [[], [(fd, select.POLLIN)]] if identity == 'exited-during-check'
                 else [[], []])
        with mock.patch.object(self, 'copied_cli', return_value=CLI), \
             mock.patch.object(self, 'invoke',
                 side_effect=subprocess.TimeoutExpired('controlled CLI', 15) if timeout else None,
                 return_value=subprocess.CompletedProcess(
                     [], 0 if successful else 9, b'', b'controlled assertion failure')), \
             mock.patch.object(Path, 'exists', exists), \
             mock.patch.object(Path, 'read_text', read_text), \
             mock.patch.object(Path, 'read_bytes',
                 side_effect=FileNotFoundError() if identity == 'unreadable' else None,
                 return_value=(b'python\0-c\0child\0someone-else\0' if identity == 'mismatched'
                               else b'python\0-c\0child\0unique-test-child-marker\0')), \
             mock.patch.object(uuid, 'uuid4', return_value=mock.Mock(hex=marker)), \
             mock.patch.object(os, 'pidfd_open', return_value=fd,
                 side_effect=ProcessLookupError() if identity == 'absent' else None) as opened, \
             mock.patch.object(select, 'poll') as poll, \
             mock.patch.object(signal, 'pidfd_send_signal') as send, \
             mock.patch.object(os, 'close') as close, \
             mock.patch.object(os, 'kill') as raw_kill:
            poll.return_value.poll.side_effect = polls
            if successful:
                self.cleanup_case('', 0)
            else:
                with self.assertRaises(subprocess.TimeoutExpired if timeout else AssertionError):
                    self.cleanup_case('', 0)
            raw_kill.assert_not_called()
            if identity == 'owned':
                send.assert_called_once_with(fd, signal.SIGKILL)
            else:
                send.assert_not_called()
            if identity in ('gone', 'zombie', 'missing', 'zero'):
                opened.assert_not_called()
                close.assert_not_called()
            elif identity != 'absent':
                opened.assert_called_once_with(pid)
                close.assert_called_once_with(fd)

    def cleanup_owned_child(self, pid, marker):
        if pid is None or pid <= 0:
            return
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            poll = select.poll()
            poll.register(fd, select.POLLIN)
            if poll.poll(0):
                return
            try:
                argv = (Path('/proc') / str(pid) / 'cmdline').read_bytes().split(b'\0')
            except OSError:
                return
            # A live handle on both sides of the read binds this unique argv marker
            # to the handle, not to a possibly reused numeric PID or starttime.
            if marker.encode() not in argv or poll.poll(0):
                return
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
        finally:
            os.close(fd)

    def cleanup_case(self, ending, expected):
        marker = uuid.uuid4().hex
        child = '''import os, pathlib, signal, sys, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path(sys.argv[2]).write_text(str(os.getpid()))
while True: time.sleep(1)
'''
        code = self.fake_prefix() + f'''import subprocess
subprocess.Popen([sys.executable, '-c', {child!r}, {marker!r}, str(o/'child.pid')])
while not (o/'child.pid').exists(): time.sleep(.01)
'''+ending
        cli = self.copied_cli(code)
        pid = None
        cleaned = False
        try:
            result = self.invoke('--timeout', '1', cli=cli)
            pidfile = self.output / 'child.pid'
            if pidfile.exists():
                pid = int(pidfile.read_text())
            self.assertIsNotNone(pid, result.stderr.decode())
            self.assertGreater(pid, 0, 'invalid controlled child PID')
            self.assertEqual(result.returncode, expected, result.stderr.decode())
            deadline = time.monotonic()+3
            while time.monotonic() < deadline:
                proc = Path('/proc') / str(pid) / 'stat'
                try:
                    gone = not proc.exists() or proc.read_text().split()[2] == 'Z'
                except FileNotFoundError:
                    gone = True
                if gone:
                    cleaned = True
                    break
                time.sleep(.03)
            else:
                self.fail('same-group stubborn child survived terminal cleanup')
        finally:
            if not cleaned:
                if pid is None and (self.output / 'child.pid').exists():
                    pid = int((self.output / 'child.pid').read_text())
                self.cleanup_owned_child(pid, marker)

    def test_deadline_stubborn_child_cleanup(self):
        self.cleanup_case('time.sleep(20)\n', 124)

    def test_early_success_stubborn_child_cleanup(self):
        self.cleanup_case("(o/'worker-report.json').write_text(json.dumps(r))\n", 0)

    def test_early_failure_stubborn_child_cleanup(self):
        self.cleanup_case('sys.exit(3)\n', 1)

    def test_missing_report_stubborn_child_cleanup(self):
        self.cleanup_case('sys.exit(0)\n', 1)

    def test_invalid_report_stubborn_child_cleanup(self):
        self.cleanup_case("r['slices']['items'][0]['header']={}\n"
                          "(o/'worker-report.json').write_text(json.dumps(r))\n", 1)

    def test_missing_worker_dependency_no_writes(self):
        self.assertTrue(CLI.is_file(), 'missing read-only inspector implementation')
        scripts = self.root / 'scripts'
        scripts.mkdir()
        shutil.copyfile(CLI, scripts / CLI.name)
        self.assertNotEqual(self.invoke(cli=scripts / CLI.name).returncode, 0)
        self.assertFalse(self.output.exists())

    def test_clipped_name_marker_and_precise_large_address(self):
        # A valid real PE section name is only 8 bytes; use a controlled native-like report
        # to exercise the parent boundary without inventing a malformed format fixture.
        cli = self.copied_cli(self.fake_prefix() + '''r['slices']['items'][0]['sections']={'total':1,'truncated':False,'items':[
{'name':'x'*512,'name_truncated':True,'address':'0xffffffffffffffff',
'address_coordinate':'RVA','offset':'0x0','size':'0x0'}]}
(o/'worker-report.json').write_text(json.dumps(r))
''')
        result = self.invoke(cli=cli)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        section = self.read_report()['slices']['items'][0]['sections']['items'][0]
        self.assertTrue(section['name_truncated'])
        self.assertEqual(section['address'], '0xffffffffffffffff')

    def test_worker_limits_before_sdk_import(self):
        self.assertTrue(CLI.is_file(), 'missing read-only inspector implementation')
        scripts = self.root / 'scripts'
        shutil.copytree(MODULE / 'scripts', scripts)
        (scripts / 'lief.py').write_text('''import resource
assert resource.getrlimit(resource.RLIMIT_CORE)[0] == 0
assert resource.getrlimit(resource.RLIMIT_AS)[0] <= 512*1024*1024
assert resource.getrlimit(resource.RLIMIT_FSIZE)[0] <= 8*1024*1024
raise RuntimeError('limits verified before native import')
''')
        result = self.invoke('--memory-mib', '512', cli=scripts / CLI.name)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'limits verified before native import', (self.output / 'diagnostics.log').read_bytes())


class SupervisorContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('tested_inspector', CLI)
        self.inspector = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.inspector)
        self.temp = tempfile.TemporaryDirectory(prefix='lief-contract-', dir=SCRATCH)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sample = self.root / 'input'
        self.sample.write_bytes(b'controlled metadata input')

    def report(self, family='PE'):
        headers = {'ELF': {'file_type': 'EXEC', 'class': 'ELF64', 'endianness': 'LSB'},
                   'PE': {'characteristics': '0x2022', 'optional_magic': 'PE32_PLUS',
                          'imagebase': '0xffffffffffffffff'},
                   'MachO': {'file_type': 'OBJECT', 'cpu_subtype': '0x3'}}
        sl = {'architecture': 'TEST', 'header': headers[family],
              'entrypoint': None if family == 'MachO' else
                  {'value': '0x0', 'coordinate': 'RVA' if family == 'PE' else 'VA'}}
        for kind in ('sections', 'libraries', 'imports', 'exports'):
            sl[kind] = {'items': [], 'total': 0, 'truncated': False}
        return {'schema_version': 1, 'status': 'ok', 'sdk_version': 'test',
                'input': self.inspector.fingerprint(self.sample, 1024),
                'limits': {k: v[0] for k, v in self.inspector.BOUNDS.items()},
                'family': family, 'slices': {'items': [sl], 'total': 1, 'truncated': False}}

    def test_native_required_header_and_entrypoint_contract(self):
        for family in ('ELF', 'PE', 'MachO'):
            valid = self.report(family)
            self.inspector.validate(valid, valid)
            mutations = [('missing header', lambda s: s.pop('header')),
                         ('empty header', lambda s: s.update(header={})),
                         ('wrong header type', lambda s: s.update(header=[])),
                         ('missing entrypoint', lambda s: s.pop('entrypoint')),
                         ('wrong entrypoint type', lambda s: s.update(entrypoint=False)),
                         ('empty entrypoint', lambda s: s.update(entrypoint={})),
                         ('missing entrypoint value', lambda s: s.update(
                             entrypoint={'coordinate': 'RVA' if family == 'PE' else 'VA'})),
                         ('numeric entrypoint value', lambda s: s.update(
                             entrypoint={'coordinate': 'RVA' if family == 'PE' else 'VA', 'value': 0})),
                         ('null entrypoint value', lambda s: s.update(
                             entrypoint={'coordinate': 'RVA' if family == 'PE' else 'VA', 'value': None})),
                         ('wrong entrypoint coordinate', lambda s: s.update(
                             entrypoint={'coordinate': 'file-offset', 'value': '0x0'}))]
            if family != 'MachO':
                mutations.append(('null entrypoint', lambda s: s.update(entrypoint=None)))
            for key in valid['slices']['items'][0]['header']:
                mutations.extend([
                    ('missing '+key, lambda s, k=key: s['header'].pop(k)),
                    ('empty '+key, lambda s, k=key: s['header'].update({k: ''})),
                    ('blank '+key, lambda s, k=key: s['header'].update({k: '   '})),
                    ('numeric '+key, lambda s, k=key: s['header'].update({k: 1})),
                    ('bool '+key, lambda s, k=key: s['header'].update({k: True}))])
                if key in ('characteristics', 'imagebase', 'cpu_subtype'):
                    mutations.append(('invalid hex '+key,
                                      lambda s, k=key: s['header'].update({k: 'not-hex'})))
            for name, mutate in mutations:
                with self.subTest(family=family, mutation=name):
                    broken = copy.deepcopy(valid)
                    mutate(broken['slices']['items'][0])
                    with self.assertRaises(ValueError):
                        self.inspector.validate(broken, valid)

    def test_cleanup_pins_group_until_single_reap_on_all_terminal_paths(self):
        # All process operations are faked: never signal a real numeric PID/PGID.
        for outcome, expected in [('success', 0), ('nonzero', 1), ('missing', 1),
                                  ('invalid', 1), ('timeout', 124), ('interrupt', 130),
                                  ('observe-error', 1), ('hash-error', 1), ('report-error', 1)]:
            with self.subTest(outcome=outcome):
                output = self.root / outcome
                events = []
                report = self.report()
                report['limits']['timeout'] = 1
                if outcome == 'invalid':
                    report['slices']['items'][0]['header'] = {}
                reaped = False

                def launch(*args, **kwargs):
                    self.assertEqual(self.inspector.signal.getsignal(signal.SIGCHLD), signal.SIG_DFL)
                    if outcome != 'missing':
                        (output / 'worker-report.json').write_text(json.dumps(report))
                    return child

                def observe(which, pid, flags):
                    if pid == os.getpid():
                        raise ChildProcessError('capability probe: not a child')
                    events.append('observe')
                    self.assertEqual((which, pid), (os.P_PID, 424242))
                    self.assertTrue(flags & os.WNOWAIT)
                    self.assertTrue(flags & os.WNOHANG)
                    self.assertTrue(flags & os.WEXITED)
                    self.assertFalse(reaped)
                    if outcome == 'interrupt':
                        raise KeyboardInterrupt
                    if outcome == 'observe-error':
                        raise OSError('controlled observation failure')
                    return None if outcome == 'timeout' else mock.Mock(si_pid=424242)

                def kill_group(pid, sig):
                    events.append('kill')
                    self.assertEqual((pid, sig), (424242, signal.SIGKILL))
                    self.assertFalse(reaped, 'stale PGID signalled after reap')

                def reap(*args, **kwargs):
                    nonlocal reaped
                    events.append('reap')
                    self.assertIn('kill', events, 'leader identity discarded before cleanup')
                    self.assertFalse(reaped, 'direct child reaped twice')
                    reaped = True
                    child.returncode = 3 if outcome == 'nonzero' else 0
                    return child.returncode

                child = mock.Mock(pid=424242, returncode=None)
                child.wait.side_effect = reap
                child.poll.side_effect = AssertionError('poll would reap before owned-group cleanup')
                real_fingerprint = self.inspector.fingerprint
                hashes = [report['input'], ValueError('controlled hash failure')]
                real_write = self.inspector.private_json

                def write(path, value):
                    if outcome == 'report-error' and path.name == 'report.json':
                        raise OSError('controlled report write failure')
                    real_write(path, value)

                with mock.patch.object(self.inspector.subprocess, 'Popen', side_effect=launch), \
                     mock.patch.object(self.inspector.os, 'waitid', side_effect=observe), \
                     mock.patch.object(self.inspector.os, 'killpg', side_effect=kill_group), \
                     mock.patch.object(time, 'monotonic', side_effect=[0, 2]), \
                     mock.patch.object(self.inspector, 'private_json', side_effect=write), \
                     mock.patch.object(self.inspector, 'fingerprint',
                         side_effect=hashes if outcome == 'hash-error' else real_fingerprint):
                    result = self.inspector.main([str(self.sample), '--output', str(output),
                                                  '--authorized', '--timeout', '1'])
                self.assertEqual(result, expected)
                self.assertEqual(events.count('kill'), 1)
                self.assertEqual(events.count('reap'), 1)
                self.assertIn('observe', events)
                self.assertEqual(events[-2:], ['kill', 'reap'])

    def test_missing_nonreaping_capability_fails_before_writes(self):
        output = self.root / 'unsupported'
        with mock.patch.object(self.inspector.os, 'waitid', None):
            self.assertNotEqual(self.inspector.main([str(self.sample), '--output', str(output),
                                                    '--authorized']), 0)
        self.assertFalse(output.exists())

    def test_unusable_nonreaping_capability_fails_before_writes(self):
        output = self.root / 'unimplemented'
        with mock.patch.object(self.inspector.os, 'waitid', side_effect=NotImplementedError):
            self.assertNotEqual(self.inspector.main([str(self.sample), '--output', str(output),
                                                    '--authorized']), 0)
        self.assertFalse(output.exists())

    def test_inherited_ignored_sigchld_cannot_autoreap_worker(self):
        helper = InspectorTests()
        helper.root, helper.sample, helper.output = self.root, self.sample, self.root / 'ignored'
        cli = helper.copied_cli(helper.fake_prefix() +
                               "assert signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL\n" +
                               "(o/'worker-report.json').write_text(json.dumps(r))\n")
        # Only this controlled standalone process changes its own signal disposition.
        wrapper = ('import os,signal,sys; signal.signal(signal.SIGCHLD,signal.SIG_IGN); '
                   'os.execv(sys.executable,[sys.executable]+sys.argv[1:])')
        result = subprocess.run([sys.executable, '-c', wrapper, str(cli), str(self.sample),
                                 '--output', str(helper.output), '--authorized'],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_official_reader_links_use_verified_source_paths(self):
        usage = (MODULE / 'references' / 'usage.md').read_text()
        urls = re.findall(r'https://github.com/lief-project/LIEF/blob/[^\s]+', usage)
        paths = {urlparse(url).path for url in urls}
        prefix = '/lief-project/LIEF/blob/5416ff2e2fcda29924c2f868a7249b4318359c41/api/python/examples/'
        self.assertEqual(paths, {prefix+'pe_reader.py', prefix+'macho_reader.py'})


if __name__ == '__main__':
    unittest.main()
