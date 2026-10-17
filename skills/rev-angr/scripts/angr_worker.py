#!/usr/bin/env python3
"""Private angr worker: invoked by solve.py, not a public CLI.

angr is imported only after the resource limits are in place. Neither this worker nor angr runs
the sample natively: the symbolic model produces a candidate input, and that candidate is then
replayed through a second simulated run (still not native execution).
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from solve import fingerprint, private_json, require

CAVEATS = [
    'angr models execution symbolically; the sample itself is never executed natively',
    'library calls are handled by angr sim-procedures and auto_load_libs is off',
    'the process environment, heap layout and timing are not modelled',
    'a negative result only means no path was found within the declared bounds',
]
ERROR_LIMIT = 5
SOFT_GRACE_SECONDS = 4.0


def restrict(memory_mib):
    """Apply limits before importing angr. These are limits, not a sandbox."""
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    limit = memory_mib * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    resource.setrlimit(resource.RLIMIT_FSIZE, (256 * 1024 * 1024,) * 2)


def in_executable_section(project, address):
    for section in getattr(project.loader.main_object, 'sections', []):
        if getattr(section, 'is_executable', False) and section.min_addr <= address < section.max_addr:
            return True
    return False


def resolve_targets(project, specs):
    addresses = set()
    texts = []
    resolved = []
    for spec in specs:
        if spec.startswith('sym:'):
            name = spec[4:]
            symbol = project.loader.main_object.get_symbol(name)
            require(symbol is not None and symbol.rebased_addr, 'no such symbol: ' + name)
            addresses.add(symbol.rebased_addr)
            resolved.append({'target': spec, 'kind': 'symbol', 'address': hex(symbol.rebased_addr)})
        elif spec.startswith('stdout:'):
            texts.append(spec[7:].encode())
            resolved.append({'target': spec, 'kind': 'stdout', 'text': spec[7:]})
        else:
            address = int(spec, 16)
            require(in_executable_section(project, address),
                    'address is not inside an executable section: ' + spec)
            addresses.add(address)
            resolved.append({'target': spec, 'kind': 'address', 'address': hex(address)})
    return resolved, addresses, texts


def build_matcher(addresses, texts):
    if not addresses and not texts:
        return None
    if addresses and not texts:
        return lambda state: state.addr in addresses

    def matcher(state):
        if state.addr in addresses:
            return True
        for text in texts:
            try:
                if text in state.posix.dumps(1):
                    return True
            except Exception:
                return False
        return False

    return matcher


def charset_expression(byte, charset, claripy):
    if charset == 'printable':
        return claripy.And(byte >= 0x20, byte <= 0x7e)
    return claripy.Or(claripy.And(byte >= 0x30, byte <= 0x39),
                      claripy.And(byte >= 0x41, byte <= 0x5a),
                      claripy.And(byte >= 0x61, byte <= 0x7a))


def found_states(simgr):
    """angr raises for a stash that does not exist yet, so never touch simgr.found directly."""
    return simgr.stashes.get('found') or []


def run_search(project, state, find_target, avoid_target, max_steps, max_active, deadline):
    import angr
    simgr = project.factory.simulation_manager(state)
    simgr.use_technique(angr.exploration_techniques.DFS())
    steps = 0
    budget_reason = None
    while True:
        if found_states(simgr) or not simgr.active:
            break
        if steps >= max_steps:
            budget_reason = 'max_steps'
            break
        if time.monotonic() >= deadline:
            budget_reason = 'time'
            break
        if len(simgr.active) > max_active:
            simgr.stashes['pruned_budget'] = (simgr.stashes.get('pruned_budget', [])
                                              + simgr.active[max_active:])
            simgr.stashes['active'] = simgr.active[:max_active]
            budget_reason = budget_reason or 'max_active'
        simgr.step()
        steps += 1
        # Avoid takes precedence, as in angr's own explorer: an avoided state is discarded even
        # when it would also satisfy a find target.
        if avoid_target is not None:
            simgr.move('active', 'avoided', filter_func=avoid_target)
        if find_target is not None:
            simgr.move('active', 'found', filter_func=find_target)
    return simgr, steps, budget_reason


def stash_counts(simgr):
    return {name: len(stash) for name, stash in simgr.stashes.items() if stash}


def bound_errors(simgr):
    messages = []
    for error in simgr.errored:
        messages.append(str(error.error)[:512])
        if len(messages) >= ERROR_LIMIT:
            break
    return messages


def charset_ok(solution, charset):
    if charset == 'any':
        return True
    if charset == 'printable':
        return all(0x20 <= byte <= 0x7e for byte in solution)
    return all(byte < 0x80 and chr(byte).isalnum() for byte in solution)


def escape_text(solution):
    return ''.join(chr(byte) if 0x20 <= byte <= 0x7e else '<%02x>' % byte for byte in solution)


def matched_target(found, resolved, addresses, texts):
    for entry in resolved:
        if entry['kind'] in ('symbol', 'address') and int(entry['address'], 16) == found.addr:
            return entry['target']
    for entry in resolved:
        if entry['kind'] == 'stdout':
            try:
                if entry['text'].encode() in found.posix.dumps(1):
                    return entry['target']
            except Exception:
                continue
    return None


def solve(request, output, started):
    import angr
    from angr import claripy
    binary = Path(request['binary'])
    limit = request['max_input_mib'] * 1024 * 1024
    digest = fingerprint(binary, limit)
    project = angr.Project(str(binary), auto_load_libs=False)
    mode, length = request['input_spec'].split(':')[0], int(request['input_spec'].split(':')[1])
    charset = request['charset']
    symbol = claripy.BVS('arg1' if mode == 'argv' else 'stdin', length * 8)
    find_resolved, find_addresses, find_texts = resolve_targets(project, request['find'])
    avoid_resolved, avoid_addresses, avoid_texts = resolve_targets(project, request['avoid'])
    find_target = build_matcher(find_addresses, find_texts)
    avoid_target = build_matcher(avoid_addresses, avoid_texts)
    deadline = started + max(request['timeout'] - SOFT_GRACE_SECONDS, 1.0)

    def build(content):
        if mode == 'argv':
            return project.factory.entry_state(args=['./sample', content])
        return project.factory.entry_state(stdin=angr.SimFile('stdin', content=content, has_end=True))

    def symbolic_state():
        state = build(symbol)
        if charset != 'any':
            for index in range(length):
                state.solver.add(charset_expression(symbol.get_byte(index), charset, claripy))
        return state

    simgr, steps, budget_reason = run_search(project, symbolic_state(), find_target, avoid_target,
                                             request['max_steps'], request['max_active'], deadline)
    found = next(iter(found_states(simgr)), None)
    status = 'found' if found is not None else (
        'not_found_budget' if budget_reason is not None else 'not_found_exhausted')
    report = {'status': status, 'executed_natively': False, 'angr_version': angr.__version__,
              'binary': {'path': str(binary), 'sha256': digest},
              'input': {'mode': mode, 'length': length, 'charset': charset, 'sha256': None},
              'resolved_targets': {'find': find_resolved, 'avoid': avoid_resolved},
              'limits': {'timeout': request['timeout'], 'memory_mib': request['memory_mib'],
                         'max_steps': request['max_steps'], 'max_active': request['max_active'],
                         'max_input_mib': request['max_input_mib']},
              'exploration': {'steps': steps, 'budget_hit': budget_reason is not None,
                              'budget_reason': budget_reason, 'states': stash_counts(simgr),
                              'errors': bound_errors(simgr)},
              'caveats': list(CAVEATS), 'elapsed_seconds': round(time.monotonic() - started, 3),
              'message': ''}
    if found is not None:
        solution = found.solver.eval(symbol, cast_to=bytes)
        require(len(solution) == length, 'the model did not return the requested number of bytes')
        replayed, replay_steps = replay(project, solution, build, find_target, avoid_target,
                                        request['max_steps'], request['max_active'], deadline)
        require(replayed is True, 'candidate replay did not reach a find target within the simulation bounds')
        report['solution'] = {'hex': solution.hex(), 'text': escape_text(solution),
                              'matched_target': matched_target(found, find_resolved,
                                                               find_addresses, find_texts)}
        report['input']['sha256'] = hashlib.sha256(solution).hexdigest()
        report['validation'] = {'constraints_satisfied': charset_ok(solution, charset),
                                'replay_in_simulation': replayed}
        report['exploration']['replay_steps'] = replay_steps
    require(fingerprint(binary, limit) == digest, 'the sample changed during the run')
    private_json(output / 'worker-report.json', report)
    return report


def replay(project, solution, build, find_target, avoid_target, max_steps, max_active, deadline):
    simgr, steps, _ = run_search(project, build(solution), find_target, avoid_target,
                                 max_steps, max_active, deadline)
    return bool(found_states(simgr)), steps


def main():
    parser = argparse.ArgumentParser(description='private angr worker')
    parser.add_argument('--request', required=True)
    parser.add_argument('--output', required=True)
    arguments = parser.parse_args()
    started = time.monotonic()
    request = json.loads(Path(arguments.request).read_text())
    output = Path(arguments.output)
    restrict(request['memory_mib'])
    try:
        solve(request, output, started)
    except BaseException as exc:
        traceback.print_exc()
        mode, _, length = request['input_spec'].partition(':')
        report = {'status': 'error', 'executed_natively': False, 'angr_version': 'unknown',
                  'binary': {'path': request['binary'], 'sha256': ''},
                  'input': {'mode': mode, 'length': int(length), 'charset': request['charset'],
                            'sha256': None},
                  'limits': {'timeout': request['timeout'], 'memory_mib': request['memory_mib'],
                             'max_steps': request['max_steps'], 'max_active': request['max_active'],
                             'max_input_mib': request['max_input_mib']},
                  'exploration': {'steps': 0, 'budget_hit': False, 'budget_reason': None,
                                  'states': {}, 'errors': [str(exc)[:512]]},
                  'caveats': list(CAVEATS),
                  'elapsed_seconds': round(time.monotonic() - started, 3),
                  'message': type(exc).__name__ + ': ' + str(exc)[:512]}
        try:
            private_json(output / 'worker-report.json', report)
        except OSError:
            pass
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
