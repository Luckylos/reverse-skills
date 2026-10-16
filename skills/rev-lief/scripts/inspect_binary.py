#!/usr/bin/env python3
"""Read-only POSIX supervisor. Native LIEF is imported only by the worker."""
import argparse
import hashlib
import importlib.util
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
NAME_LENGTH = 512
BOUNDS = {'max_items': (256, 4096), 'max_slices': (8, 64), 'timeout': (30, 300),
          'max_input_mib': (128, 1024), 'memory_mib': (1024, 16384)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fingerprint(path, maximum):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode), 'input must be a regular readable file')
        require(0 < info.st_size <= maximum, 'input size outside limit')
        size = 0
        while True:
            block = stream.read(min(1024*1024, maximum-size+1))
            if not block:
                break
            size += len(block)
            require(size <= maximum, 'input grew beyond size limit')
            digest.update(block)
        require(size == info.st_size, 'input changed while hashing')
    return {'sha256': digest.hexdigest(), 'size': size}


def private_json(path, value):
    payload = json.dumps(value, ensure_ascii=True, allow_nan=False, indent=2).encode('utf-8')
    require(len(payload) <= REPORT_BYTES, 'report exceeds byte limit')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(payload)


def integer(value):
    return type(value) is int and 0 <= value <= (1 << 53)-1


def text(value, nullable=False):
    require((nullable and value is None) or
            (type(value) is str and len(value) <= NAME_LENGTH), 'invalid bounded text')


def address(value):
    require(type(value) is str and re.fullmatch(r'0x[0-9a-f]{1,16}', value) is not None,
            'address/offset must be an exact hexadecimal string')


def collection(value, cap):
    require(type(value) is dict and type(value.get('items')) is list, 'invalid collection')
    require(integer(value.get('total')), 'invalid collection total')
    require(type(value.get('truncated')) is bool, 'invalid truncation flag')
    count = len(value['items'])
    require(count == min(value['total'], cap), 'collection count mismatch')
    require(value['truncated'] == (value['total'] > count), 'incorrect truncation flag')
    return value['items']


def validate(report, request):
    require(type(report) is dict, 'invalid report')
    require(type(report.get('schema_version')) is int and report['schema_version'] == 1,
            'unsupported schema version')
    require(report.get('status') in ('ok', 'partial'), 'invalid report status')
    identity = report.get('input')
    require(type(identity) is dict and integer(identity.get('size')) and
            type(identity.get('sha256')) is str and
            re.fullmatch('[0-9a-f]{64}', identity['sha256']) is not None and
            identity == request['input'], 'input identity mismatch')
    limits = report.get('limits')
    require(type(limits) is dict and set(limits) == set(request['limits']) and
            all(type(limits[k]) is int and limits[k] == v for k, v in request['limits'].items()),
            'limits mismatch')
    text(report.get('sdk_version'))
    require(bool(report['sdk_version']), 'missing SDK version')
    family = report.get('family')
    require(family in ('ELF', 'PE', 'MachO'), 'unknown format')
    slices = collection(report.get('slices'), limits['max_slices'])
    require(bool(slices), 'empty architecture report')
    if family != 'MachO':
        require(report['slices']['total'] == 1, 'unexpected slices')
    for sl in slices:
        require(type(sl) is dict, 'invalid slice')
        text(sl.get('architecture'))
        require(bool(sl['architecture']) and 'UNKNOWN' not in sl['architecture'].upper() and
                sl['architecture'] not in ('0', 'NONE'), 'missing/unknown architecture')
        header = sl.get('header')
        require(type(header) is dict, 'missing header')
        for key, value in header.items():
            text(key)
            text(value)
        text_fields, hex_fields = {
            'ELF': (('file_type', 'class', 'endianness'), ()),
            'PE': (('optional_magic',), ('characteristics', 'imagebase')),
            'MachO': (('file_type',), ('cpu_subtype',)),
        }[family]
        for key in text_fields:
            text(header.get(key))
            require(bool(header[key].strip()), 'missing native header field: '+key)
        for key in hex_fields:
            address(header.get(key))
        require('entrypoint' in sl, 'missing native entrypoint field')
        ep = sl['entrypoint']
        require(ep is not None or family == 'MachO', 'missing native ELF/PE entrypoint')
        if ep is not None:
            require(type(ep) is dict and ep.get('coordinate') == ('RVA' if family == 'PE' else 'VA'),
                    'incorrect entrypoint coordinates')
            address(ep.get('value'))
        for kind in ('sections', 'libraries', 'imports', 'exports'):
            for item in collection(sl.get(kind), limits['max_items']):
                require(type(item) is dict, 'invalid metadata item')
                text(item.get('name'), nullable=kind in ('imports', 'exports'))
                require(type(item.get('name_truncated')) is bool, 'missing name truncation flag')
                if kind == 'sections':
                    for field in ('address', 'offset', 'size'):
                        address(item.get(field))
                    require(item.get('address_coordinate') == ('RVA' if family == 'PE' else 'VA'),
                            'incorrect section address coordinate')
                elif kind in ('imports', 'exports'):
                    if family == 'PE':
                        ordinal = item.get('ordinal')
                        require(ordinal is None or (integer(ordinal) and ordinal <= 65535), 'invalid ordinal')
                        if kind == 'imports':
                            text(item.get('library'))
                            require(type(item.get('library_truncated')) is bool, 'missing DLL truncation')
                            require((item['name'] is None) != (ordinal is None), 'ambiguous PE import')
                        else:
                            address(item.get('address'))
                            require(item.get('address_coordinate') == 'RVA', 'incorrect export coordinate')
                            text(item.get('forwarder'), nullable=True)
                            require(type(item.get('forwarder_truncated')) is bool, 'missing forwarder truncation')
                    else:
                        address(item.get('value'))
    return report


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('input')
    parser.add_argument('--output', required=True)
    parser.add_argument('--authorized', action='store_true', required=True)
    for name, (default, maximum) in BOUNDS.items():
        parser.add_argument('--'+name.replace('_', '-'), type=int, default=default,
                            help=f'positive integer <= {maximum} (default {default})')
    seen = set()
    for arg in argv:
        if arg.startswith('--'):
            flag = arg.split('=', 1)[0]
            require(flag not in seen, 'duplicate singleton flag: '+flag)
            seen.add(flag)
    args = parser.parse_args(argv)
    for name, (_, maximum) in BOUNDS.items():
        require(1 <= getattr(args, name) <= maximum, 'invalid limit: '+name)
    return args


def prepare_child_observation():
    require(os.name == 'posix', 'POSIX resource/process support required; native Windows unsupported')
    require(callable(getattr(os, 'waitid', None)) and
            all(hasattr(os, key) for key in ('P_PID', 'WEXITED', 'WNOHANG', 'WNOWAIT')),
            'non-reaping POSIX waitid/WNOWAIT support required')
    # Probe kernel support without creating or consuming any child (self is not a child).
    try:
        os.waitid(os.P_PID, os.getpid(), os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        pass
    except (OSError, NotImplementedError) as exc:
        raise ValueError('non-reaping POSIX waitid/WNOWAIT unavailable') from exc
    # This standalone CLI owns its children; inherited SIG_IGN must not auto-reap them.
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def observe_child(process, timeout):
    deadline = time.monotonic() + timeout
    while True:
        if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            return False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        time.sleep(min(.02, remaining))


def cleanup_child(process):
    # A live or unreaped leader pins its PID/PGID until the final group signal.
    handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    finally:
        signal.signal(signal.SIGINT, handler)


def main(argv=None):
    try:
        args = arguments(sys.argv[1:] if argv is None else argv)
        prepare_child_observation()
        require(importlib.util.find_spec('resource') is not None, 'resource limits unavailable')
        require(importlib.util.find_spec('lief') is not None,
                'LIEF unavailable: select an existing verified Python interpreter; no automatic installation')
        worker = Path(__file__).resolve().with_name('lief_worker.py')
        require(worker.is_file(), 'missing worker dependency')
        source = Path(args.input)
        require(source.is_absolute(), 'input must be an absolute path')
        source = source.resolve(strict=True)
        maximum = args.max_input_mib*1024*1024
        identity = fingerprint(source, maximum)
        output = Path(os.path.abspath(args.output))
        require(not os.path.lexists(output), 'output must be new, including no symlink')
        require(output.parent.is_dir(), 'output parent must already exist')
        limits = {name: getattr(args, name) for name in BOUNDS}
        # mkdir is atomic: existing paths (including dangling links) never get reused.
        os.mkdir(output, 0o700)
        os.chmod(output, 0o700)
        request = {'path': str(source), 'output': str(output), 'input': identity, 'limits': limits}
        request_path = output / 'request.json'
        private_json(request_path, request)
        logpath = output / 'diagnostics.log'
        fd = os.open(logpath, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        deadline = False
        with os.fdopen(fd, 'wb') as diagnostics:
            process = subprocess.Popen([sys.executable, str(worker), str(request_path)],
                                       stdin=subprocess.DEVNULL, stdout=diagnostics,
                                       stderr=diagnostics, shell=False, start_new_session=True)
            try:
                deadline = observe_child(process, args.timeout)
            finally:
                # Never poll/wait before group cleanup, nor signal this PGID after reaping.
                cleanup_child(process)
        if deadline:
            print('deadline exceeded; private partial artifacts retained', file=sys.stderr)
            return 124
        require(fingerprint(source, maximum) == identity, 'input changed during analysis')
        report_path = output / 'worker-report.json'
        info = report_path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_size <= REPORT_BYTES, 'invalid/oversized worker report')
        with report_path.open('rb') as stream:
            payload = stream.read(REPORT_BYTES+1)
        require(len(payload) <= REPORT_BYTES, 'oversized report')
        report = validate(json.loads(payload), request)
        if logpath.stat().st_size:
            report['status'] = 'partial'
            report['diagnostics'] = 'diagnostics.log (native output or worker errors; inspect privately)'
        if process.returncode != 0:
            report['status'] = 'partial'
        private_json(output / 'report.json', report)
        require(report['status'] == 'ok' and process.returncode == 0,
                'partial result; inspect private report and diagnostics')
        print('Verified scoped metadata: '+str(output / 'report.json'))
        return 0
    except KeyboardInterrupt:
        print('Inspection interrupted; private artifacts retained if created', file=sys.stderr)
        return 130
    except Exception as exc:
        print('Inspection failed: '+str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
