/* abi: Generate the callback spill contract from Generate-CaptureAbi.py */
#pragma once
#include <stddef.h>
#include "protocol.h"
#define NU_ABI_HOME 0x20u
#define NU_ABI_REGS_SIZE 0xa0u
#define NU_ABI_ALLOCATION 0xc0u
#define NU_ABI_ENTRY_RSP 0xc8u
#define NU_ABI_SAVED_FLAGS 0xc0u
#define NU_ABI_RAX 0x20u
#define NU_ABI_RCX 0x28u
#define NU_ABI_RDX 0x30u
#define NU_ABI_RBX 0x38u
#define NU_ABI_RSP 0x40u
#define NU_ABI_RBP 0x48u
#define NU_ABI_RSI 0x50u
#define NU_ABI_RDI 0x58u
#define NU_ABI_R8 0x60u
#define NU_ABI_R9 0x68u
#define NU_ABI_R10 0x70u
#define NU_ABI_R11 0x78u
#define NU_ABI_R12 0x80u
#define NU_ABI_R13 0x88u
#define NU_ABI_R14 0x90u
#define NU_ABI_R15 0x98u
#define NU_ABI_RIP 0xa0u
#define NU_ABI_RFLAGS 0xa8u
#define NU_ABI_CS 0xb0u
#define NU_ABI_SS 0xb8u
#if defined(__cplusplus)
#define NU_ABI_ASSERT(c) static_assert(c, "capture ABI")
#else
#define NU_ABI_ASSERT(c) _Static_assert(c, "capture ABI")
#endif
NU_ABI_ASSERT(sizeof(NU_REGS) == NU_ABI_REGS_SIZE);
NU_ABI_ASSERT(offsetof(NU_REGS, Rax) == NU_ABI_RAX - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rcx) == NU_ABI_RCX - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rdx) == NU_ABI_RDX - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rbx) == NU_ABI_RBX - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rsp) == NU_ABI_RSP - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rbp) == NU_ABI_RBP - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rsi) == NU_ABI_RSI - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rdi) == NU_ABI_RDI - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R8) == NU_ABI_R8 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R9) == NU_ABI_R9 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R10) == NU_ABI_R10 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R11) == NU_ABI_R11 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R12) == NU_ABI_R12 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R13) == NU_ABI_R13 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R14) == NU_ABI_R14 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, R15) == NU_ABI_R15 - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rip) == NU_ABI_RIP - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Rflags) == NU_ABI_RFLAGS - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Cs) == NU_ABI_CS - NU_ABI_HOME);
NU_ABI_ASSERT(offsetof(NU_REGS, Ss) == NU_ABI_SS - NU_ABI_HOME);
#undef NU_ABI_ASSERT
