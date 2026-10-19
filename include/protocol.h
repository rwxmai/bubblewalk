#pragma once
#include <stdint.h>

/* wire: Fix field widths across driver, collector, and archive */
#define NU_VERSION 3u
/* wire: Encode the NWU3 signature as little-endian 0x3355574E */
#define NU_MAGIC 0x3355574eu
#define NU_NMI_BYTES 8192u
#define NU_THREAD_BYTES 65536u
#define NU_MAX_FRAMES 128u
#define NU_DEVICE_PATH L"\\\\.\\Bubble"
#define NU_CTL(n) ((0x8337u << 16) | (3u << 14) | ((n) << 2))
#define NU_INFO NU_CTL(0x800u)
#define NU_ARM NU_CTL(0x801u)
#define NU_READ NU_CTL(0x802u)
#define NU_MODULES NU_CTL(0x803u)
#define NU_DISARM NU_CTL(0x804u)
#define NU_PULSE NU_CTL(0x807u)
#define NU_CAP_PULSE 1u
#define NU_PULSE_MIN_MS 50u
#define NU_F_ARCH_INVALID      0x0001u
#define NU_F_USER_INTERRUPTED  0x0002u
#define NU_F_STACK_UNSUPPORTED 0x0004u
#define NU_F_NMI_TRUNCATED     0x0008u
#define NU_F_THREAD_TRUNCATED  0x0010u
#define NU_M_IDENTITY_VALID    0x0001u

#pragma pack(push, 8)
/* abi: Match NU_REGS to the 0x20..0xBF assembly spill range */
typedef struct NU_REGS {
    uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t Rip, Rflags, Cs, Ss;
} NU_REGS;

/* monitor: Describe the round without claiming complete delivery */
typedef struct NU_PULSE_DATA {
    uint32_t Generation, SenderCpu, TargetCount, Reserved;
} NU_PULSE_DATA;

typedef struct NU_REGION {
    uint64_t Base;
    uint32_t Size;
    uint32_t Reserved;
} NU_REGION;

typedef struct NU_SAMPLE {
    uint32_t Version, Cpu, Generation, Flags;
    uint64_t Tsc, Thread, KernelBase;
    uint64_t InterruptedRip, InterruptedRsp, InterruptedCs, InterruptedFlags;
    NU_REGS Entry;
    NU_REGION Nmi, Stack;
    uint8_t NmiBytes[NU_NMI_BYTES];
    uint8_t StackBytes[NU_THREAD_BYTES];
} NU_SAMPLE;

typedef struct NU_INFO_DATA {
    uint32_t Version, Build, CpuCount, SampleSize;
    uint32_t StackBaseOffset, StackLimitOffset, CaptureBytes, Features;
} NU_INFO_DATA;

typedef struct NU_MODULE {
    uint64_t Base;
    uint32_t Size, Timestamp, Checksum, Flags;
    char Path[256];
} NU_MODULE;

/* wire: Prefix the IOCTL module array with an 8-byte header */
typedef struct NU_MODULE_HEADER { uint32_t Count, Reserved; } NU_MODULE_HEADER;
/* wire: Serialize the 32-byte header, module array, then samples */
typedef struct NU_FILE_HEADER {
    uint32_t Magic, Version, Build, ModuleCount;
    uint32_t SampleCount, SampleSize, InventoryStable, Reserved;
} NU_FILE_HEADER;
#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(NU_REGS) == 160, "assembly register layout");
static_assert(sizeof(NU_SAMPLE) == 73992, "wire layout");
static_assert(sizeof(NU_MODULE) == 280, "module wire layout");
#endif
