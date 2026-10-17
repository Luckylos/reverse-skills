"""Tiny C fixtures, compiled at test time. They are never executed, here or by the solver."""
import shutil
import subprocess
from pathlib import Path

# The fixtures accept exactly one six-byte input whose polynomial weight equals the weight of
# this known string. The weight is computed here so the C constant and the expectation cannot
# drift apart.
KNOWN_INPUT = b'ohoqrd'


def weight(payload):
    value = 0
    for byte in payload:
        value = (value * 131 + byte) & 0xffffffff
    return value


TARGET_WEIGHT = weight(KNOWN_INPUT)

ARGV_TEMPLATE = r'''
#include <stdio.h>
#include <string.h>

__attribute__((noinline)) int win(void) { puts("ACCESS GRANTED"); return 0; }
__attribute__((noinline)) int never_called(void) { puts("NEVER"); return 0; }

static int check(const char *s) {
    unsigned int h = 0;
    if (strlen(s) != 6) return 0;
    for (int i = 0; i < 6; i++) h = h * 131u + (unsigned char)s[i];
    return h == TARGET_WEIGHT_PLACEHOLDER;
}

int main(int argc, char **argv) {
    if (argc > 100) return never_called();
    if (argc > 1 && check(argv[1])) return win();
    puts("DENIED");
    return 1;
}
'''

STDIN_TEMPLATE = r'''
#include <stdio.h>

__attribute__((noinline)) int win(void) { puts("ACCESS GRANTED"); return 0; }

int main(void) {
    char buffer[8] = {0};
    if (fread(buffer, 1, 6, stdin) != 6) { puts("SHORT"); return 1; }
    unsigned int h = 0;
    for (int i = 0; i < 6; i++) h = h * 131u + (unsigned char)buffer[i];
    if (h == TARGET_WEIGHT_PLACEHOLDER) return win();
    puts("DENIED");
    return 1;
}
'''

SOURCES = {'argv': ARGV_TEMPLATE, 'stdin': STDIN_TEMPLATE}


def require_gcc():
    compiler = shutil.which('gcc')
    if compiler is None:
        raise RuntimeError('these tests need gcc to build the fixtures')
    return compiler


def build(directory, name):
    """Compile one fixture and return the binary path. Only gcc runs; the sample never does."""
    if name not in SOURCES:
        raise KeyError(name)
    source = Path(directory) / (name + '.c')
    binary = Path(directory) / (name + '.bin')
    source.write_text(SOURCES[name].replace('TARGET_WEIGHT_PLACEHOLDER', '0x%08xu' % TARGET_WEIGHT))
    completed = subprocess.run([require_gcc(), '-O0', '-no-pie', '-o', str(binary), str(source)],
                               capture_output=True, text=True)
    if completed.returncode != 0:
        raise RuntimeError('gcc failed: ' + completed.stderr[-500:])
    if not binary.is_file():
        raise RuntimeError('gcc produced no binary')
    return binary
