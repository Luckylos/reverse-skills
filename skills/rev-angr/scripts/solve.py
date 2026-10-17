#!/usr/bin/env python3
"""Bounded angr path-solver supervisor. angr itself is imported only by the worker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

REPORT_BYTES = 8 * 1024 * 1024
TEXT_LENGTH = 256
KILL_GRACE_SECONDS = 5.0
POLL_SECONDS = 0.05
WORKER_SOFT_GRACE = 4.0
BOUNDS = {'timeout': (10, 3600), 'memory_mib': (1024, 16384), 'max_steps': (1, 200000),
          'max_active': (1, 4096), 'max_input_mib': (64, 1024)}
LENGTH_BOUNDS = (1, 4096)
TARGET_LIMIT = 64
TARGET_PATTERN = re.compile(r'(0x[0-9a-fA-F]{1,16}|sym:[A-Za-z0-9_.$@+-]{1,256}|stdout:[ -~]{1,256})\Z')
STATUSES = ('found', 'not_found_exhausted', 'not_found_budget', 'error')
EXIT_CODES = {'found': 0, 'not_found_exhausted': 1, 'not_found_budget': 1, 'error': 2,
              'timeout': 124, 'interrupted': 130}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def boundary(name, value):
    low, high = BOUNDS[name]
    require(low <= value <= high, name + ' must be between ' + str(low) + ' and ' + str(high))
    return value


def fingerprint(path, maximum):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), 'input is not a regular file')
        require(info.st_size <= maximum, 'input is larger than the allowed maximum')
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    require(size == info.st_size, 'input size changed while reading')
    return digest.hexdigest()


def private_write(path, payload):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(payload)


def private_json(path, payload):
    private_write(path, (json.dumps(payload, indent=1, sort_keys=True) + '\n').encode('utf-8'))


def require_supported_lifecycle():
    require(hasattr(os, 'waitid'), 'this supervisor needs os.waitid')
    require(hasattr(os, 'WNOWAIT') and hasattr(os, 'WNOHANG'), 'this supervisor needs WNOWAIT and WNOHANG')
    require(hasattr(os, 'killpg'), 'this supervisor needs os.killpg')


def observe_unreaped(pid, timeout):
    """Wait for the child without reaping it. Returns the waitid result once it has exited
    and is still a zombie, or None on timeout. Raises if somebody else reaped it."""
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        try:
            info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        except ChildProcessError as exc:
            raise RuntimeError('the worker was reaped outside this supervisor; not signalling it') from exc
        if info is not None:
            return info
        if time.monotonic() >= deadline:
            return None
        time.sleep(POLL_SECONDS)


def reap_once(pid, record):
    require(not record['reaped'], 'the worker was already reaped')
    _, status = os.waitpid(pid, 0)
    record['reaped'] = True
    return os.waitstatus_to_exitcode(status)


def kill_group(pid, pgid, record):
    """Signal the worker's process group while its leader is still an unreaped zombie, so the
    group cannot be recycled. Never signal a numeric pid or pgid after reaping."""
    require(not record['reaped'], 'refusing to signal a worker that was already reaped')
    require(pgid == pid, 'worker process group does not match its leader')
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    record['signalled'] = True


def run_worker(command, timeout, stdout_path, stderr_path):
    out = os.fdopen(os.open(stdout_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb')
    err = os.fdopen(os.open(stderr_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb')
    record = {'outcome': 'ok', 'exit_code': None, 'reaped': False, 'signalled': False}
    process = None
    info = None
    try:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                   start_new_session=True, close_fds=True)
        pid = process.pid
        pgid = os.getpgid(pid)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            info = observe_unreaped(pid, max(remaining, 0.0))
            if info is not None or remaining <= 0:
                break
        if info is None:
            record['outcome'] = 'timeout'
            kill_group(pid, pgid, record)
            info = observe_unreaped(pid, KILL_GRACE_SECONDS)
            require(info is not None, 'the worker process group survived SIGKILL')
    except KeyboardInterrupt:
        record['outcome'] = 'interrupted'
        if info is None:
            kill_group(pid, pgid, record)
            info = observe_unreaped(pid, KILL_GRACE_SECONDS)
    finally:
        if info is not None:
            record['exit_code'] = reap_once(pid, record)
        out.close()
        err.close()
    if process is not None and record['exit_code'] is not None:
        # The child was reaped with os.waitpid above; keep the Popen object consistent so its
        # finaliser does not warn about a child that is long gone.
        process.returncode = record['exit_code']
    return record


def parse_input_spec(spec):
    require(spec.count(':') == 1, 'input must look like argv:N or stdin:N')
    mode, _, length = spec.partition(':')
    require(mode in ('argv', 'stdin'), 'input mode must be argv or stdin')
    require(length.isdigit(), 'input length must be a decimal number')
    number = int(length)
    require(LENGTH_BOUNDS[0] <= number <= LENGTH_BOUNDS[1],
            'input length must be between ' + str(LENGTH_BOUNDS[0]) + ' and ' + str(LENGTH_BOUNDS[1]))
    return mode, number


def check_targets(values, label):
    require(len(values) <= TARGET_LIMIT, label + ' accepts at most ' + str(TARGET_LIMIT) + ' targets')
    for value in values:
        require(TARGET_PATTERN.match(value), 'invalid ' + label + ' target: ' + value)


def validate_worker_report(report):
    require(isinstance(report, dict), 'the worker report must be a JSON object')
    status = report.get('status')
    require(status in STATUSES, 'unknown worker status: ' + repr(status))
    require(report.get('executed_natively') is False, 'the worker must report executed_natively false')
    for key in ('angr_version', 'binary', 'input', 'exploration', 'limits', 'elapsed_seconds', 'caveats'):
        require(key in report, 'the worker report is missing ' + key)
    require(isinstance(report['binary'], dict) and isinstance(report['binary'].get('sha256'), str),
            'the worker report must describe the binary digest')
    require(isinstance(report['input'], dict), 'the worker report must describe the input')
    require(isinstance(report['limits'], dict), 'the worker report must describe the limits')
    require(isinstance(report['caveats'], list), 'the worker report must list caveats')
    elapsed = report['elapsed_seconds']
    require(isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool),
            'elapsed_seconds must be a number')
    exploration = report['exploration']
    require(isinstance(exploration, dict), 'exploration must be an object')
    states = exploration.get('states')
    require(isinstance(states, dict), 'exploration.states must be an object')
    for key, value in states.items():
        require(re.fullmatch(r'[a-z_]{1,32}', key) and isinstance(value, int) and not isinstance(value, bool),
                'exploration.states entries must be small integers: ' + str(key))
    for key in ('steps', 'budget_hit'):
        require(key in exploration, 'exploration is missing ' + key)
    require(isinstance(exploration['steps'], int) and not isinstance(exploration['steps'], bool),
            'exploration.steps must be an integer')
    require(isinstance(exploration['budget_hit'], bool), 'exploration.budget_hit must be a boolean')
    errors = exploration.get('errors', [])
    require(isinstance(errors, list) and all(isinstance(item, str) and len(item) <= 512 for item in errors),
            'exploration.errors must be short strings')
    if status == 'found':
        solution = report.get('solution')
        require(isinstance(solution, dict), 'a found report needs a solution object')
        require(re.fullmatch(r'[0-9a-f]{0,8192}', solution.get('hex', '')) is not None,
                'solution.hex must be lowercase hex')
        require(isinstance(solution.get('text'), str) and len(solution['text']) <= 8192,
                'solution.text must be a bounded string')
        require(solution.get('matched_target') is not None, 'a found report must name the matched target')
        validation = report.get('validation')
        require(isinstance(validation, dict), 'a found report needs a validation object')
        require(validation.get('constraints_satisfied') is True,
                'a found report must show that the solution satisfies the constraints')
        require(validation.get('replay_in_simulation') is True,
                'a found report must show a successful replay_in_simulation')
    return report


def reject_repeated_fields(pairs):
    """JSON object hook that refuses a repeated field name, so a tampered report cannot
    hide a second value for `status` behind the last-value-wins default."""
    seen = set()
    for key, _ in pairs:
        require(key not in seen, 'the worker report repeats the field ' + str(key)[:TEXT_LENGTH])
        seen.add(key)
    return dict(pairs)


def read_worker_report(output):
    path = output / 'worker-report.json'
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode), 'the worker report is not a regular file')
    require(info.st_size <= REPORT_BYTES, 'the worker report is too large')
    with path.open('rb') as stream:
        payload = stream.read(REPORT_BYTES + 1)
    require(len(payload) <= REPORT_BYTES, 'the worker report is too large')
    try:
        return validate_worker_report(json.loads(payload, object_pairs_hook=reject_repeated_fields))
    except json.JSONDecodeError as exc:
        raise ValueError('the worker report is not valid JSON') from exc


def build_parser():
    parser = argparse.ArgumentParser(
        description='Search for an input that reaches a target, using angr and fixed bounds. '
                    'Nothing is executed natively.')
    parser.add_argument('binary', help='path to the sample to analyse (opened read-only)')
    parser.add_argument('--output', required=True, help='directory to create for this run')
    parser.add_argument('--authorized', action='store_true', required=True,
                        help='declare that you are authorized to analyse this sample')
    parser.add_argument('--find', action='append', required=True, default=[],
                        help='target to reach: 0xADDR, sym:NAME or stdout:TEXT (repeatable)')
    parser.add_argument('--avoid', action='append', default=[],
                        help='target to avoid, same syntax as --find (repeatable)')
    parser.add_argument('--input', required=True, help='symbolic input: argv:N or stdin:N')
    parser.add_argument('--charset', choices=('any', 'printable', 'alnum'), default='printable',
                        help='constrain the input bytes (default: printable)')
    parser.add_argument('--timeout', type=int, default=120, help='wall-clock seconds (10-3600)')
    parser.add_argument('--memory-mib', type=int, default=4096,
                        help='worker address-space limit in MiB (1024-16384)')
    parser.add_argument('--max-steps', type=int, default=2000, help='simulation steps per search (1-200000)')
    parser.add_argument('--max-active', type=int, default=256, help='active states kept per search (1-4096)')
    parser.add_argument('--max-input-mib', type=int, default=256, help='largest sample accepted (64-1024)')
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    output = Path(args.output)
    try:
        require_supported_lifecycle()
        require(args.authorized, '--authorized is required')
        mode, length = parse_input_spec(args.input)
        check_targets(args.find, '--find')
        check_targets(args.avoid, '--avoid')
        for name in ('timeout', 'memory_mib', 'max_steps', 'max_active', 'max_input_mib'):
            boundary(name, getattr(args, name))
        source = Path(args.binary)
        require(source.exists() and not source.is_dir(), 'sample does not exist: ' + str(source))
        limit = args.max_input_mib * 1024 * 1024
        before = fingerprint(source, limit)
        require(not output.exists(), 'output already exists: ' + str(output))
        output.mkdir(mode=0o700)
        worker = Path(__file__).resolve().parent / 'angr_worker.py'
        require(worker.is_file(), 'the worker is missing next to this supervisor')
        request = {'schema': 'rev-angr/request/1', 'binary': str(source), 'input_spec': args.input,
                   'find': args.find, 'avoid': args.avoid, 'charset': args.charset,
                   'timeout': args.timeout, 'memory_mib': args.memory_mib, 'max_steps': args.max_steps,
                   'max_active': args.max_active, 'max_input_mib': args.max_input_mib}
        private_json(output / 'request.json', request)
        command = [sys.executable, str(worker), '--request', str(output / 'request.json'),
                   '--output', str(output)]
        started = time.monotonic()
        record = run_worker(command, args.timeout, output / 'worker-stdout.log', output / 'diagnostics.log')
        elapsed = round(time.monotonic() - started, 3)
        require(fingerprint(source, limit) == before, 'the sample changed during the run')
        report = {'schema': 'rev-angr/report/1', 'binary': {'path': str(source), 'sha256': before},
                  'input_spec': {'mode': mode, 'length': length, 'charset': args.charset},
                  'limits': {'timeout': args.timeout, 'memory_mib': args.memory_mib,
                             'max_steps': args.max_steps, 'max_active': args.max_active},
                  'executed_natively': False, 'elapsed_seconds': elapsed,
                  'worker': {'outcome': record['outcome'], 'exit_code': record['exit_code'],
                             'report': 'worker-report.json',
                             'logs': ['worker-stdout.log', 'diagnostics.log']}}
        if record['outcome'] != 'ok':
            report['status'] = record['outcome']
            report['result'] = None
            report['message'] = ('the worker exceeded its time budget and was killed'
                                 if record['outcome'] == 'timeout' else 'the run was interrupted')
        else:
            try:
                result = read_worker_report(output)
            except (ValueError, OSError) as exc:
                report['status'] = 'error'
                report['result'] = None
                report['message'] = 'unusable worker report: ' + str(exc)
            else:
                report['status'] = result['status']
                report['result'] = result
                report['message'] = result.get('message', '')
                if result['status'] == 'found':
                    report['solution'] = result['solution']
        private_json(output / 'report.json', report)
        status = report['status']
        for line in (['status: ' + status, 'report: ' + str(output / 'report.json')]
                     + (['solution: ' + json.dumps(report['solution'])] if status == 'found' else [])
                     + ([report['message']] if report.get('message') else [])):
            print(line)
        return EXIT_CODES.get(status, 2)
    except KeyboardInterrupt:
        print('Search interrupted', file=sys.stderr)
        return 130
    except Exception as exc:
        print('Search failed: ' + str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
