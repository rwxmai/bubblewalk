import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path


def u16(data, offset):
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def pdb_streams(data):
    if data[:24] != b'Microsoft C/C++ MSF 7.00':
        raise ValueError('expected MSF 7.0 PDB')
    block, _, _, size, _, directory_map = struct.unpack_from('<6I', data, 32)
    if block not in (512, 1024, 2048, 4096):
        raise ValueError('unsupported PDB block size')
    count = (size + block - 1) // block
    blocks = struct.unpack_from('<' + 'I' * count, data, directory_map * block)
    directory = b''.join(data[n*block:(n+1)*block] for n in blocks)[:size]
    count = u32(directory, 0)
    sizes = struct.unpack_from('<' + 'I' * count, directory, 4)
    at = 4 + count * 4
    result = []
    for size in sizes:
        count = 0 if size == 0xffffffff else (size + block - 1) // block
        blocks = struct.unpack_from('<' + 'I' * count, directory, at)
        at += count * 4
        result.append(b''.join(data[n*block:(n+1)*block] for n in blocks)[:size])
    return result


def inspect(kernel_path, pdb_path):
    kernel = Path(kernel_path).read_bytes()
    digest = hashlib.sha256(kernel).hexdigest()
    if digest != '1cc3b103b25333ee2b79363bb898832a93576befd2e3a29817bd34cf7a3a102b':
        raise ValueError('kernel SHA-256 differs from the 26100.1 target')
    nt = u32(kernel, 0x3c)
    optional = nt + 24
    count, optional_size = u16(kernel, nt+6), u16(kernel, nt+20)
    sections = []
    for i in range(count):
        at = optional + optional_size + i * 40
        virtual_size, rva, raw_size, raw = struct.unpack_from('<4I', kernel, at+8)
        sections.append((rva, virtual_size, raw, raw_size))
    streams = pdb_streams(Path(pdb_path).read_bytes())
    info = streams[1]
    guid = uuid.UUID(bytes_le=info[12:28]).hex.upper()
    if guid != 'B6CDAA3A3EF13C3B2799115B0470342B' or u32(streams[3], 8) != 1:
        raise ValueError('PDB GUID/age differs from the target CodeView identity')
    symbols = streams[u16(streams[3], 20)]
    names = {}
    at = 0
    wanted = {'KiNmiInterrupt', 'KxNmiInterrupt', 'KiProcessNMI'}
    while at + 4 <= len(symbols):
        size, kind = struct.unpack_from('<HH', symbols, at)
        if size < 2 or at + size + 2 > len(symbols):
            raise ValueError('invalid symbol record')
        if kind == 0x110e:
            offset, segment = u32(symbols, at+8), u16(symbols, at+12)
            name = symbols[at+14:at+size+2].split(b'\0')[0].decode(errors='replace')
            if name in wanted and 0 < segment <= len(sections):
                names[name] = hex(sections[segment-1][0]+offset)
        at += size + 2
    expected = {'KiNmiInterrupt': '0x666fc0', 'KxNmiInterrupt': '0x667440', 'KiProcessNMI': '0x540b30'}
    if names != expected:
        raise ValueError('NMI symbols differ from the selected target')
    tpi = streams[2]
    header, first, last = struct.unpack_from('<3I', tpi, 4)
    records, at = {}, header
    for index in range(first, last):
        size = u16(tpi, at)
        records[index] = tpi[at+2:at+2+size]
        at += size + 2
    offsets = {}
    for record in records.values():
        if (record[:2] == b'\x05\x15' and len(record) > 20 and
                record[20:].split(b'\0')[0] == b'_KTHREAD' and not u16(record, 4) & 0x80):
            fields = records[u32(record, 6)]
            for name in ('StackBase', 'StackLimit'):
                at = fields.find(name.encode()+b'\0')
                if at < 10 or fields[at-10:at-8] != b'\x0d\x15':
                    raise ValueError('unsupported KTHREAD member record')
                offsets[name] = hex(u16(fields, at-2))
    if offsets != {'StackBase': '0x38', 'StackLimit': '0x30'}:
        raise ValueError('KTHREAD offsets differ from the selected target')
    return {'sha256': digest, 'pdb_guid': guid, 'pdb_age': u32(streams[3], 8), 'pdb_info_age': u32(info, 8), 'symbols': names, 'KTHREAD': offsets}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: Inspect-Target.py ntoskrnl.exe ntkrnlmp.pdb')
    print(json.dumps(inspect(*sys.argv[1:]), indent=2))
