"""Emit the C/MASM callback spill contract from one ordered register list."""
from pathlib import Path
import argparse

REGISTERS = ('Rax Rcx Rdx Rbx Rsp Rbp Rsi Rdi R8 R9 R10 R11 R12 R13 R14 R15 '
             'Rip Rflags Cs Ss').split()


def outputs():
    values = {'HOME': 0x20, 'REGS_SIZE': 0xa0, 'ALLOCATION': 0xc0,
              'ENTRY_RSP': 0xc8, 'SAVED_FLAGS': 0xc0}
    values.update({name.upper(): 0x20 + 8 * i for i, name in enumerate(REGISTERS)})
    header = ['/* abi: Generate the callback spill contract from Generate-CaptureAbi.py */',
              '#pragma once', '#include <stddef.h>', '#include "protocol.h"']
    assembly = ['; abi: Generate callback offsets from Generate-CaptureAbi.py']
    for name, value in values.items():
        header.append(f'#define NU_ABI_{name} 0x{value:x}u')
        assembly.append(f'NU_ABI_{name} EQU 0{value:X}h')
    header += ['#if defined(__cplusplus)', '#define NU_ABI_ASSERT(c) static_assert(c, "capture ABI")',
               '#else', '#define NU_ABI_ASSERT(c) _Static_assert(c, "capture ABI")', '#endif',
               'NU_ABI_ASSERT(sizeof(NU_REGS) == NU_ABI_REGS_SIZE);']
    for name in REGISTERS:
        header.append(f'NU_ABI_ASSERT(offsetof(NU_REGS, {name}) == NU_ABI_{name.upper()} - NU_ABI_HOME);')
    header += ['#undef NU_ABI_ASSERT']
    return {'include/capture_abi.h': '\n'.join(header) + '\n',
            'driver/capture_abi.inc': '\n'.join(assembly) + '\n'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    for relative, content in outputs().items():
        path = root / relative
        if args.check:
            if not path.exists() or path.read_text() != content:
                raise SystemExit(f'stale capture ABI: {relative}')
        else:
            path.write_text(content)


if __name__ == '__main__':
    main()
