"""Owned, non-executed fixture bytes; no SDK builders or downloaded samples."""
import struct
import subprocess


def elf(directory):
    source = directory / 'owned.c'
    source.write_text('#include <stdio.h>\nint helper(void){return puts("owned");}\nint main(void){return helper();}\n')
    target = directory / 'owned ELF ; $sample'
    subprocess.run(['cc', '-Wl,--export-dynamic', '-o', str(target), str(source)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return target


def pe():
    data = bytearray(0x800)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', data, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    o = 0x98
    struct.pack_into('<H', data, o, 0x20b)
    struct.pack_into('<II', data, o+16, 0x1000, 0x1000)
    struct.pack_into('<Q', data, o+24, 0x180000000)
    struct.pack_into('<II', data, o+32, 0x1000, 0x200)
    struct.pack_into('<HH', data, o+40, 6, 0)
    struct.pack_into('<HH', data, o+48, 6, 0)
    struct.pack_into('<II', data, o+56, 0x2000, 0x200)
    struct.pack_into('<H', data, o+68, 3)
    struct.pack_into('<QQQQ', data, o+72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into('<I', data, o+108, 16)
    struct.pack_into('<II', data, o+112, 0x1200, 0x90)
    struct.pack_into('<II', data, o+120, 0x1100, 40)
    s = o+240
    struct.pack_into('<8sIIIIIIHHI', data, s, b'.rdata\0\0', 0x600, 0x1000, 0x600,
                     0x200, 0, 0, 0, 0, 0x40000040)
    def put(rva, blob):
        off = rva-0x1000+0x200
        data[off:off+len(blob)] = blob
    put(0x1100, struct.pack('<IIIII', 0x1140, 0, 0, 0x1180, 0x1160))
    put(0x1140, struct.pack('<QQQ', 0x1190, (1<<63)|7, 0))
    put(0x1160, struct.pack('<QQQ', 0x1190, (1<<63)|7, 0))
    put(0x1180, b'KERNEL32.dll\0')
    put(0x1190, b'\0\0NamedImport\0')
    put(0x1200, struct.pack('<IIHHIIIIIII', 0, 0, 0, 0, 0x1250, 1, 2, 1,
                            0x1260, 0x1270, 0x1278))
    put(0x1250, b'owned.dll\0')
    put(0x1260, struct.pack('<II', 0x1000, 0x1001))
    put(0x1270, struct.pack('<I', 0x1280))
    put(0x1278, struct.pack('<H', 0))
    put(0x1280, b'ExportedHelper\0')
    return bytes(data)


def macho(cpu=0x01000007):
    # MH_OBJECT, one LC_SEGMENT_64 with a regular __text section, no LC_MAIN.
    head = struct.pack('<IIIIIIII', 0xfeedfacf, cpu, 3 if cpu == 0x01000007 else 0,
                       1, 1, 152, 0, 0)
    seg = struct.pack('<II16sQQQQiiII', 0x19, 152, b'__TEXT', 0, 1, 184, 1, 7, 5, 1, 0)
    sec = struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT', 0, 1, 184, 0,
                      0, 0, 0x80000400, 0, 0, 0)
    return head + seg + sec + b'\xc3'


def fat_macho():
    a, b = macho(), macho(0x0100000c)
    header = struct.pack('>II', 0xcafebabe, 2)
    header += struct.pack('>IIIII', 0x01000007, 3, 0x1000, len(a), 12)
    header += struct.pack('>IIIII', 0x0100000c, 0, 0x2000, len(b), 12)
    return header.ljust(0x1000, b'\0') + a + bytes(0x1000-len(a)) + b
