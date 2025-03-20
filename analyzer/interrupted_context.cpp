#include "interrupted_context.h"
#include "../include/target_26100_1.h"
#include <cstring>
#include <limits>

namespace nu {
bool targetImage(const PeImage& image) {
    if (image.size() != NU_TARGET_SIZE || image.timestamp() != NU_TARGET_TIMESTAMP ||
        image.checksum() != NU_TARGET_CHECKSUM) return false;
    for (const auto& code : NuTargetCode) {
        uint8_t bytes[96]{};
        if (!image.read(code.Rva, bytes, code.Size) ||
            std::memcmp(bytes, code.Bytes, code.Size)) return false;
    }
    return true;
}

/* context: Recover GPRs from the pinned Ki/Kx NMI save slots
 * Let F address the hardware RIP. Ki reserves 0x168 bytes below F;
 * Kx then CALLs and reserves 0x138. RSI is overwritten before Kx, so
 * recover its original value from Ki's PUSH, not Kx's SAVE_NONVOL.
 */
bool interruptedContext(const NU_SAMPLE& s, const NU_MODULE& kernel,
                        NU_REGS& output, std::string& error) {
    auto reject = [&](const char* message) { error=message; return false; };
    if (s.Version != NU_VERSION || s.KernelBase != kernel.Base ||
        !(kernel.Flags & NU_M_IDENTITY_VALID) || kernel.Size != NU_TARGET_SIZE ||
        kernel.Timestamp != NU_TARGET_TIMESTAMP || kernel.Checksum != NU_TARGET_CHECKSUM ||
        kernel.Base < 0xffff800000000000ull ||
        kernel.Base > std::numeric_limits<uint64_t>::max() - NU_TARGET_SIZE)
        return reject("TARGET_IDENTITY");
    if (s.Flags & (NU_F_ARCH_INVALID | NU_F_USER_INTERRUPTED | NU_F_STACK_UNSUPPORTED |
                   NU_F_NMI_TRUNCATED)) return reject("CAPTURE_FLAGS");
    if (s.Nmi.Base < 0xffff800000000000ull ||
        s.Nmi.Size < 0x2d8 || s.Nmi.Size > NU_NMI_BYTES ||
        s.Stack.Size > NU_THREAD_BYTES || s.Entry.Rsp != s.Nmi.Base ||
        s.Nmi.Base > std::numeric_limits<uint64_t>::max() - s.Nmi.Size)
        return reject("NMI_REGION");
    const uint64_t f = s.Nmi.Base + s.Nmi.Size - 40;
    if ((f & 15) != 8) return reject("MACHINE_FRAME_ALIGNMENT");
    auto get = [&](uint64_t address, uint64_t& value) {
        return readRegion(s.Nmi.Base, s.NmiBytes, s.Nmi.Size, address, &value, 8);
    };
    uint64_t kiReturn=0, kxReturn=0;
    if (!get(f-0x170, kiReturn) || !get(f-0x2b0, kxReturn) ||
        kiReturn != kernel.Base + NU_TARGET_KI_RETURN ||
        kxReturn != kernel.Base + NU_TARGET_KX_RETURN)
        return reject("HANDLER_RETURN_SLOTS");
    NU_REGS r{};
    if (!get(f, r.Rip) || !get(f+8, r.Cs) || !get(f+16, r.Rflags) ||
        !get(f+24, r.Rsp) || !get(f+32, r.Ss)) return reject("MACHINE_FRAME_READ");
    if (r.Rip != s.InterruptedRip || r.Rsp != s.InterruptedRsp ||
        r.Cs != s.InterruptedCs || r.Rflags != s.InterruptedFlags ||
        r.Cs != 0x10 || r.Ss != 0x18 || !(r.Rflags & 2) ||
        r.Rip < 0xffff800000000000ull || r.Rsp < 0xffff800000000000ull ||
        (r.Rsp & 7) || s.Stack.Base != r.Rsp || !s.Stack.Size)
        return reject("MACHINE_FRAME_FIELDS");
    if (!get(f-0x138, r.Rax) || !get(f-0x130, r.Rcx) || !get(f-0x128, r.Rdx) ||
        !get(f-0x120, r.R8) || !get(f-0x118, r.R9) || !get(f-0x110, r.R10) ||
        !get(f-0x108, r.R11) || !get(f-0x10, r.Rbp) || !get(f-0x18, r.Rsi) ||
        !get(f-0x1a8, r.Rbx) || !get(f-0x1a0, r.Rdi) || !get(f-0x190, r.R12) ||
        !get(f-0x188, r.R13) || !get(f-0x180, r.R14) || !get(f-0x178, r.R15))
        return reject("REGISTER_SAVE_SLOTS");
    output=r;
    error.clear();
    return true;
}
}
