#!/usr/bin/env python3
"""Private native worker: invoked by inspect_binary.py, not a public CLI."""
import json
from pathlib import Path
import sys
import traceback

from inspect_binary import NAME_LENGTH, REPORT_BYTES, fingerprint, private_json, require


def restrict(memory_mib):
    # Apply before loading any native SDK code. These are limits, not a sandbox.
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    for which, requested in ((resource.RLIMIT_AS, memory_mib*1024*1024),
                             (resource.RLIMIT_FSIZE, REPORT_BYTES)):
        _, hard = resource.getrlimit(which)
        cap = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
        require(cap > 0, 'inherited resource limit does not permit analysis')
        resource.setrlimit(which, (cap, cap))


def name_fields(value, field='name'):
    require(type(value) is str, 'SDK returned a non-string name')
    return {field: value[:NAME_LENGTH], field+'_truncated': len(value) > NAME_LENGTH}


def hex64(value):
    require(type(value) is int and 0 <= value < (1 << 64), 'SDK address outside unsigned 64-bit range')
    return hex(value)


def bounded(values, cap, convert):
    items = []
    total = 0
    for value in values:
        if total < cap:
            items.append(convert(value))
        total += 1
    return {'items': items, 'total': total, 'truncated': total > cap}


def symbol(value):
    return {**name_fields(value.name), 'value': hex64(value.value)}


def section(value, family):
    return {**name_fields(value.name), 'address': hex64(value.virtual_address),
            'address_coordinate': 'RVA' if family == 'PE' else 'VA',
            'offset': hex64(value.offset), 'size': hex64(value.size)}


def pe_imports(binary):
    for descriptor in binary.imports:
        for entry in descriptor.entries:
            result = name_fields(descriptor.name, 'library')
            if entry.is_ordinal:
                result.update(name=None, name_truncated=False, ordinal=entry.ordinal)
            else:
                result.update(name_fields(entry.name))
                result['ordinal'] = None
            yield result


def pe_export(entry):
    result = name_fields(entry.name)
    if not result['name']:
        result['name'] = None
    result.update(ordinal=entry.ordinal, address=hex64(entry.address), address_coordinate='RVA')
    if entry.is_forwarded:
        forward = entry.forward_information
        result.update(name_fields(forward.library+'.'+forward.function, 'forwarder'))
    else:
        result.update(forwarder=None, forwarder_truncated=False)
    return result


def slice_report(binary, family, cap):
    header = binary.header
    if family == 'ELF':
        architecture = str(header.machine_type)
        summary = {'file_type': str(header.file_type), 'class': str(header.identity_class),
                   'endianness': str(header.identity_data)}
        entrypoint = {'value': hex64(header.entrypoint), 'coordinate': 'VA'}
    elif family == 'PE':
        architecture = str(header.machine)
        optional = binary.optional_header
        summary = {'characteristics': hex64(header.characteristics),
                   'optional_magic': str(optional.magic), 'imagebase': hex64(optional.imagebase)}
        entrypoint = {'value': hex64(optional.addressof_entrypoint), 'coordinate': 'RVA'}
    else:
        architecture = str(header.cpu_type)
        summary = {'file_type': str(header.file_type), 'cpu_subtype': hex64(header.cpu_subtype)}
        entrypoint = ({'value': hex64(binary.entrypoint), 'coordinate': 'VA'}
                      if binary.has_entrypoint else None)
    require(bool(architecture) and 'UNKNOWN' not in architecture.upper(), 'unknown architecture')
    result = {'architecture': architecture, 'header': summary, 'entrypoint': entrypoint,
              'sections': bounded(binary.sections, cap, lambda s: section(s, family))}
    result['libraries'] = bounded(binary.libraries, cap,
                                  lambda lib: name_fields(lib.name if family == 'MachO' else lib))
    if family == 'PE':
        result['imports'] = bounded(pe_imports(binary), cap, lambda x: x)
        exports = binary.get_export()
        require(exports is not None or not binary.has_exports, 'missing PE export table')
        result['exports'] = bounded(exports.entries if exports is not None else (), cap, pe_export)
    else:
        result['imports'] = bounded(binary.imported_symbols, cap, symbol)
        result['exports'] = bounded(binary.exported_symbols, cap, symbol)
    return result


def main():
    require(len(sys.argv) == 2, 'worker requires one private request')
    request_path = Path(sys.argv[1])
    require(request_path.name == 'request.json' and request_path.stat().st_size <= 16384,
            'invalid request file')
    request = json.loads(request_path.read_text())
    limits = request['limits']
    require(type(limits['memory_mib']) is int and 1 <= limits['memory_mib'] <= 16384,
            'invalid worker memory cap')
    restrict(limits['memory_mib'])
    import lief

    source = Path(request['path'])
    output = Path(request['output'])
    require(output == request_path.parent and output.is_absolute(), 'invalid private output')
    require(fingerprint(source, limits['max_input_mib']*1024*1024) == request['input'],
            'input changed before native parsing')
    with source.open('rb') as stream:
        magic = stream.read(4)
    if magic == b'\x7fELF':
        family = 'ELF'
        binary = lief.ELF.parse(str(source))
        require(binary is not None, 'ELF parser returned None')
        binaries = [binary]
    elif magic[:2] == b'MZ':
        family = 'PE'
        binary = lief.PE.parse(str(source))
        require(binary is not None, 'PE parser returned None')
        binaries = [binary]
    elif magic in (b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xce',
                    b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
                    b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'):
        family = 'MachO'
        binaries = lief.MachO.parse(str(source))
        require(binaries is not None and len(binaries) > 0, 'MachO parser returned no slices')
    else:
        raise ValueError('unsupported/unknown format (only ELF, PE, MachO)')
    report = {'schema_version': 1, 'status': 'ok', 'input': request['input'], 'limits': limits,
              'sdk_version': lief.__version__, 'family': family,
              'slices': bounded(binaries, limits['max_slices'],
                                lambda b: slice_report(b, family, limits['max_items']))}
    require(fingerprint(source, limits['max_input_mib']*1024*1024) == request['input'],
            'input changed during native parsing')
    # The supervisor also checks native stdout/stderr after all SDK objects are destroyed.
    sys.stdout.flush()
    sys.stderr.flush()
    private_json(output / 'worker-report.json', report)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
