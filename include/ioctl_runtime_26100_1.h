#pragma once
#include "ioctl_26100_1.h"

/* target: The pinned image's FUNCTION_OVERRIDE DVRT entry for 0x664660
 * permits 0xb57780 and 0xb577e0. Its X64_REL32 fixups cover the CALLs
 * at 0x32bf18 and 0x86ffff. Only their four displacement bytes may vary;
 * the E8 opcode, surrounding instructions and return RVAs stay pinned.
 * Archived PE validation must continue using NuIoctlCode directly.
 */
static int NuIoctlRuntimeCodeMatches(const NU_CODE_CHECK* Check,
                                   const unsigned char* Bytes)
{
    unsigned int i, displacementAt = 0, displacement, target;
    if (!Check || !Bytes || !Check->Size || Check->Size > sizeof(Check->Bytes))
        return 0;
    if ((Check->Rva == 0x32bf0cu && Check->Size == 17u) ||
        (Check->Rva == 0x86ffc2u && Check->Size == 66u)) {
        displacementAt = Check->Size - 4u;
        if (Check->Bytes[displacementAt - 1u] != 0xe8 ||
            Bytes[displacementAt - 1u] != 0xe8) return 0;
        displacement = (unsigned int)Bytes[displacementAt] |
            ((unsigned int)Bytes[displacementAt + 1u] << 8) |
            ((unsigned int)Bytes[displacementAt + 2u] << 16) |
            ((unsigned int)Bytes[displacementAt + 3u] << 24);
        /* Unsigned RVA arithmetic also handles the original negative
         * displacement at the fast-I/O site without signed overflow.
         */
        target = Check->Rva + Check->Size + displacement;
        if (target != 0x664660u && target != 0xb57780u && target != 0xb577e0u)
            return 0;
    }
    for (i = 0; i < Check->Size; ++i) {
        if (displacementAt && i >= displacementAt) continue;
        if (Bytes[i] != Check->Bytes[i]) return 0;
    }
    return 1;
}
