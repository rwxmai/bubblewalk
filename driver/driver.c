#include <ntddk.h>
#include <wdmsec.h>
#include <aux_klib.h>
#include <ntimage.h>
#include <intrin.h>
#include "../include/protocol.h"
#include "../include/capture_abi.h"
#include "../include/target_26100_1.h"
#include "../include/ioctl_26100_1.h"

#define NU_TAG 'wUmN'
#define NU_EMPTY 0
#define NU_WAITING 1
#define NU_WRITING 2
#define NU_READY 3
#define NU_READING 4

C_ASSERT(sizeof(NU_REGS) == 160);
C_ASSERT(sizeof(NU_SAMPLE) == 73992);

/* hal: Reserve the 26100.1 affinity object without importing private types */
typedef struct NU_AFFINITY {
    USHORT Count, Size;
    ULONG Reserved;
    UINT64 Bitmap[32];
} NU_AFFINITY;
C_ASSERT(sizeof(NU_AFFINITY) == 0x108);
typedef VOID (*NU_INIT_AFFINITY)(PVOID);
typedef VOID (*NU_ADD_AFFINITY)(PVOID, ULONG);
typedef VOID (*NU_SEND_NMI)(PVOID);

typedef struct NU_SLOT { volatile LONG State; NU_SAMPLE Sample; } NU_SLOT;
typedef struct NU_DEVICE {
    PDEVICE_OBJECT Device;
    NU_SLOT* Slots;
    ULONG CpuCount, Build, BaseOffset, LimitOffset, CaptureBytes;
    volatile LONG Armed, Active, Generation;
    UINT64 KernelBase;
    PVOID NmiHandle;
    KMUTEX ControlLock;
    NU_INIT_AFFINITY InitAffinity;
    NU_ADD_AFFINITY AddAffinity;
    NU_SEND_NMI SendNmi;
    ULONG NextSender, PulseGeneration;
    UINT64 LastPulse;
    KTIMER Timer;
    KDPC TimeoutDpc;
} NU_DEVICE;

#pragma pack(push, 1)
typedef struct NU_DTR { USHORT Limit; UINT64 Base; UCHAR Padding[6]; } NU_DTR;
typedef struct NU_TABLES { NU_DTR Idt, Gdt; USHORT Tr; } NU_TABLES;
#pragma pack(pop)

extern VOID NuCopyBytes(PVOID To, const VOID* From, SIZE_T Count);
extern BOOLEAN NuNmiEntry(PVOID Context, BOOLEAN Handled);
extern VOID NuReadTables(NU_TABLES* Tables);
C_ASSERT(FIELD_OFFSET(NU_TABLES, Gdt) == 16);
C_ASSERT(FIELD_OFFSET(NU_TABLES, Tr) == 32);
static NU_DEVICE gNu;
static const GUID NuDeviceGuid =
    {0x8b973c74,0x23d1,0x4c10,{0xac,0x35,0x02,0xc1,0xa9,0x27,0x13,0x43}};

static BOOLEAN NuKernel(UINT64 Address)
{
    /* va: Restrict pointers to canonical LA48 kernel addresses */
    return Address >= 0xffff800000000000ull;
}

/* x64: Locate the five-qword machine frame below the IST top
 * Resolve IDT[2].IST through TR and the 64-bit TSS descriptor. Assume
 * the aligned IST top precedes RIP, CS, RFLAGS, RSP, SS by 40 bytes.
 */
static BOOLEAN NuMachineFrame(UINT64 EntryRsp, UINT64* Top, UINT64** Frame)
{
    NU_TABLES tables;
    const volatile UCHAR *gate, *desc;
    UINT64 tss, top;
    ULONG selector, ist, limit;
    NuReadTables(&tables);
    if (!NuKernel(tables.Idt.Base) || !NuKernel(tables.Gdt.Base) ||
        tables.Idt.Limit < 47 || (tables.Tr & 4)) return FALSE;
    gate = (const volatile UCHAR*)(ULONG_PTR)(tables.Idt.Base + 2 * 16);
    if ((gate[5] & 0x9f) != 0x8e) return FALSE;
    ist = gate[4] & 7;
    if (!ist) return FALSE;
    selector = tables.Tr & ~7u;
    if (selector + 15 > tables.Gdt.Limit) return FALSE;
    desc = (const volatile UCHAR*)(ULONG_PTR)(tables.Gdt.Base + selector);
    if (!(desc[5] & 0x80) || (desc[5] & 0x10) ||
        ((desc[5] & 15) != 9 && (desc[5] & 15) != 11)) return FALSE;
    limit = desc[0] | ((ULONG)desc[1] << 8) | ((ULONG)(desc[6] & 15) << 16);
    if (limit < 103 || (desc[6] & 0x80)) return FALSE;
    tss = desc[2] | ((UINT64)desc[3] << 8) | ((UINT64)desc[4] << 16) |
        ((UINT64)desc[7] << 24) | ((UINT64)desc[8] << 32) |
        ((UINT64)desc[9] << 40) | ((UINT64)desc[10] << 48) |
        ((UINT64)desc[11] << 56);
    if (!NuKernel(tss)) return FALSE;
    top = *(volatile UINT64*)(ULONG_PTR)(tss + 36 + (ist - 1) * 8);
    top &= ~15ull;
    if (!NuKernel(top) || EntryRsp > top - 40 || top - EntryRsp > 0x10000)
        return FALSE;
    *Top = top;
    *Frame = (UINT64*)(ULONG_PTR)(top - 40);
    return TRUE;
}

/* nmi: Confine capture to resident state and nonblocking operations
 * HIGH_LEVEL cannot service a page fault or wait for a preempted owner.
 */
BOOLEAN NuCapture(PVOID Context, BOOLEAN Handled, const NU_REGS* Entry)
{
    NU_DEVICE* d = (NU_DEVICE*)Context;
    NU_SLOT* slot;
    NU_SAMPLE* s;
    PROCESSOR_NUMBER number;
    ULONG cpu, size;
    UINT64 top, *frame, low, high;
    LONG previous;
    InterlockedIncrement(&d->Active);
    if (!InterlockedCompareExchange(&d->Armed, 0, 0)) {
        InterlockedDecrement(&d->Active);
        return Handled;
    }
    KeGetCurrentProcessorNumberEx(&number);
    cpu = KeGetProcessorIndexFromNumber(&number);
    if (cpu >= d->CpuCount) goto done;
    slot = &d->Slots[cpu];
    previous = InterlockedCompareExchange(&slot->State, NU_WRITING, NU_WAITING);
    if (previous != NU_WAITING) goto done;
    /* nmi: Populate the zeroed slot acquired by WAITING-to-WRITING CAS */
    s = &slot->Sample;
    s->Version = NU_VERSION;
    s->Cpu = cpu;
    s->Generation = (ULONG)InterlockedCompareExchange(&d->Generation, 0, 0);
    s->Tsc = __rdtsc();
    s->KernelBase = d->KernelBase;
    s->Thread = (UINT64)(ULONG_PTR)KeGetCurrentThread();
    NuCopyBytes(&s->Entry, Entry, sizeof(*Entry));
    if (!NuMachineFrame(Entry->Rsp, &top, &frame)) {
        s->Flags |= NU_F_ARCH_INVALID;
        goto publish;
    }
    s->InterruptedRip = frame[0];
    s->InterruptedCs = frame[1];
    s->InterruptedFlags = frame[2];
    s->InterruptedRsp = frame[3];
    s->Nmi.Base = Entry->Rsp;
    size = (ULONG)(top - Entry->Rsp);
    if (size > NU_NMI_BYTES) {
        size = NU_NMI_BYTES;
        s->Flags |= NU_F_NMI_TRUNCATED;
    }
    s->Nmi.Size = size;
    NuCopyBytes(s->NmiBytes, (PVOID)(ULONG_PTR)Entry->Rsp, size);
    if (s->InterruptedCs & 3) {
        s->Flags |= NU_F_USER_INTERRUPTED;
        goto publish;
    }
    /* nmi: Bound interrupted RSP against KTHREAD StackLimit/StackBase
     * Alternate stacks outside this interval produce STACK_UNSUPPORTED.
     */
    low = *(volatile UINT64*)(ULONG_PTR)(s->Thread + d->LimitOffset);
    high = *(volatile UINT64*)(ULONG_PTR)(s->Thread + d->BaseOffset);
    if (!NuKernel(low) || !NuKernel(high) || high <= low || high - low > 0x100000 ||
        s->InterruptedRsp < low || s->InterruptedRsp >= high ||
        !NuKernel(s->InterruptedRip) || (s->InterruptedRsp & 7)) {
        s->Flags |= NU_F_STACK_UNSUPPORTED;
        goto publish;
    }
    s->Stack.Base = s->InterruptedRsp;
    size = (ULONG)(high - s->InterruptedRsp);
    if (size > d->CaptureBytes) {
        size = d->CaptureBytes;
        s->Flags |= NU_F_THREAD_TRUNCATED;
    }
    s->Stack.Size = size;
    NuCopyBytes(s->StackBytes, (PVOID)(ULONG_PTR)s->Stack.Base, size);
publish:
    /* nmi: Publish READY with a full interlocked memory barrier
     * The reader acquires READY before copying NU_SAMPLE.
     */
    InterlockedExchange(&slot->State, NU_READY);
done:
    InterlockedDecrement(&d->Active);
    /* nmi: Return TRUE for callbacks admitted by the armed gate
     * Source attribution is absent; hardware-fault NMIs are consumed too.
     */
    return TRUE;
}

static VOID NuTimeout(KDPC* Dpc, PVOID Context, PVOID A, PVOID B)
{
    UNREFERENCED_PARAMETER(Dpc); UNREFERENCED_PARAMETER(A); UNREFERENCED_PARAMETER(B);
    InterlockedExchange(&((NU_DEVICE*)Context)->Armed, 0);
}

/* capture: Close admission before waiting for active callbacks
 * NuCapture increments Active before reading Armed. Interlocked ordering
 * keeps every callback admitted by the old gate inside this rundown.
 */
static VOID NuStop(VOID)
{
    LARGE_INTEGER pause;
    InterlockedExchange(&gNu.Armed, 0);
    pause.QuadPart = -10000;
    while (InterlockedCompareExchange(&gNu.Active, 0, 0))
        KeDelayExecutionThread(KernelMode, FALSE, &pause);
}

static NTSTATUS NuDword(HANDLE Key, PCWSTR Name, ULONG* Value)
{
    UCHAR bytes[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION p = (PKEY_VALUE_PARTIAL_INFORMATION)bytes;
    UNICODE_STRING name;
    ULONG length;
    NTSTATUS status;
    RtlInitUnicodeString(&name, Name);
    status = ZwQueryValueKey(Key, &name, KeyValuePartialInformation,
                            bytes, sizeof(bytes), &length);
    if (!NT_SUCCESS(status)) return status;
    if (p->Type != REG_DWORD || p->DataLength != sizeof(ULONG))
        return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(Value, p->Data, sizeof(ULONG));
    return STATUS_SUCCESS;
}

static NTSTATUS NuProfile(PUNICODE_STRING RegistryPath)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING parameters;
    HANDLE service = NULL, key = NULL;
    RTL_OSVERSIONINFOW version = {0};
    NTSTATUS status;
    ULONG expected = 0, enabled = 0;
    ULONG_PTR low, high;
    UINT64 actualLow, actualHigh;
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status)) return status;
    gNu.Build = version.dwBuildNumber;
    InitializeObjectAttributes(&oa, RegistryPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenKey(&service, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) return status;
    RtlInitUnicodeString(&parameters, L"Parameters");
    InitializeObjectAttributes(&oa, &parameters, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               service, NULL);
    status = ZwOpenKey(&key, KEY_READ, &oa);
    ZwClose(service);
    if (!NT_SUCCESS(status)) return status;
    status = NuDword(key, L"ExpectedBuild", &expected);
    if (NT_SUCCESS(status)) status = NuDword(key, L"EnableLabCapture", &enabled);
    if (NT_SUCCESS(status)) status = NuDword(key, L"KthreadStackBaseOffset", &gNu.BaseOffset);
    if (NT_SUCCESS(status)) status = NuDword(key, L"KthreadStackLimitOffset", &gNu.LimitOffset);
    gNu.CaptureBytes = NU_THREAD_BYTES;
    (void)NuDword(key, L"CaptureBytes", &gNu.CaptureBytes);
    ZwClose(key);
    if (!NT_SUCCESS(status)) return status;
    if (version.dwMajorVersion != 10 || version.dwBuildNumber != NU_TARGET_BUILD ||
        expected != gNu.Build || enabled != 1 ||
        gNu.BaseOffset != NU_TARGET_STACK_BASE || gNu.LimitOffset != NU_TARGET_STACK_LIMIT ||
        !gNu.BaseOffset || !gNu.LimitOffset || gNu.BaseOffset > 0x1000 ||
        gNu.LimitOffset > 0x1000 || (gNu.BaseOffset & 7) || (gNu.LimitOffset & 7) ||
        gNu.CaptureBytes < 512 || gNu.CaptureBytes > NU_THREAD_BYTES)
        return STATUS_NOT_SUPPORTED;
    /* profile: Compare symbol-derived bounds with IoGetStackLimits
     * This checks the initialization thread, not every stack transition.
     */
    IoGetStackLimits(&low, &high);
    __try {
        actualLow = *(UINT64*)((UCHAR*)KeGetCurrentThread() + gNu.LimitOffset);
        actualHigh = *(UINT64*)((UCHAR*)KeGetCurrentThread() + gNu.BaseOffset);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    if (actualLow != low || actualHigh != high) return STATUS_REVISION_MISMATCH;
    return STATUS_SUCCESS;
}

static BOOLEAN NuCopyKernel(PVOID To, UINT64 From, SIZE_T Length)
{
    MM_COPY_ADDRESS source;
    SIZE_T copied = 0;
    source.VirtualAddress = (PVOID)(ULONG_PTR)From;
    return NT_SUCCESS(MmCopyMemory(To, source, Length, MM_COPY_MEMORY_VIRTUAL, &copied)) &&
           copied == Length;
}

static NTSTATUS NuModules(PVOID Buffer, ULONG Length, ULONG_PTR* Written)
{
    PAUX_MODULE_EXTENDED_INFO modules = NULL;
    NU_MODULE_HEADER* header = (NU_MODULE_HEADER*)Buffer;
    NU_MODULE* out = (NU_MODULE*)(header + 1);
    ULONG size = 0, count, i, attempt;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    for (attempt = 0; attempt < 4; ++attempt) {
        status = AuxKlibQueryModuleInformation(&size, sizeof(*modules), NULL);
        if (!NT_SUCCESS(status)) return status;
        if (!size || size > 4 * 1024 * 1024) return STATUS_INVALID_BUFFER_SIZE;
        modules = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, NU_TAG);
        if (!modules) return STATUS_INSUFFICIENT_RESOURCES;
        status = AuxKlibQueryModuleInformation(&size, sizeof(*modules), modules);
        if (status != STATUS_BUFFER_TOO_SMALL) break;
        ExFreePoolWithTag(modules, NU_TAG);
        modules = NULL;
    }
    if (!NT_SUCCESS(status)) goto done;
    count = size / sizeof(*modules);
    if (count > 8192 || Length < sizeof(*header) + count * sizeof(*out)) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto done;
    }
    RtlZeroMemory(Buffer, sizeof(*header) + count * sizeof(*out));
    header->Count = count;
    for (i = 0; i < count; ++i) {
        IMAGE_DOS_HEADER dos;
        IMAGE_NT_HEADERS64 nt;
        out[i].Base = (UINT64)(ULONG_PTR)modules[i].BasicInfo.ImageBase;
        out[i].Size = modules[i].ImageSize;
        RtlCopyMemory(out[i].Path, modules[i].FullPathName, sizeof(out[i].Path) - 1);
        if (NuCopyKernel(&dos, out[i].Base, sizeof(dos)) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
            dos.e_lfanew > 0 && (ULONG)dos.e_lfanew < out[i].Size &&
            out[i].Size - (ULONG)dos.e_lfanew >= sizeof(nt) &&
            NuCopyKernel(&nt, out[i].Base + dos.e_lfanew, sizeof(nt)) &&
            nt.Signature == IMAGE_NT_SIGNATURE &&
            nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            out[i].Timestamp = nt.FileHeader.TimeDateStamp;
            out[i].Checksum = nt.OptionalHeader.CheckSum;
            out[i].Flags = NU_M_IDENTITY_VALID;
        }
    }
    *Written = sizeof(*header) + count * sizeof(*out);
done:
    if (modules) ExFreePoolWithTag(modules, NU_TAG);
    return status;
}

/* target: Match runtime headers and the pinned NMI save instructions */
static NTSTATUS NuTargetKernel(VOID)
{
    const ULONG capacity = 4 * 1024 * 1024;
    NU_MODULE_HEADER* header = ExAllocatePool2(POOL_FLAG_NON_PAGED, capacity, NU_TAG);
    NU_MODULE* modules;
    ULONG_PTR written = 0;
    ULONG i, j;
    NTSTATUS status;
    UCHAR bytes[96];
    if (!header) return STATUS_INSUFFICIENT_RESOURCES;
    status = NuModules(header, capacity, &written);
    if (!NT_SUCCESS(status)) goto done;
    modules = (NU_MODULE*)(header + 1);
    status = STATUS_REVISION_MISMATCH;
    for (i = 0; i < header->Count; ++i) {
        if (!(modules[i].Flags & NU_M_IDENTITY_VALID) ||
            modules[i].Size != NU_TARGET_SIZE || modules[i].Timestamp != NU_TARGET_TIMESTAMP ||
            modules[i].Checksum != NU_TARGET_CHECKSUM) continue;
        for (j = 0; j < RTL_NUMBER_OF(NuTargetCode); ++j) {
            const NU_CODE_CHECK* code = &NuTargetCode[j];
            if (!NuCopyKernel(bytes, modules[i].Base + code->Rva, code->Size) ||
                RtlCompareMemory(bytes, code->Bytes, code->Size) != code->Size) break;
        }
        if (j != RTL_NUMBER_OF(NuTargetCode)) break;
        for (j = 0; j < RTL_NUMBER_OF(NuIoctlCode); ++j) {
            const NU_CODE_CHECK* code = &NuIoctlCode[j];
            if (!NuCopyKernel(bytes, modules[i].Base + code->Rva, code->Size) ||
                RtlCompareMemory(bytes, code->Bytes, code->Size) != code->Size) break;
        }
        if (j != RTL_NUMBER_OF(NuIoctlCode)) break;
        gNu.KernelBase = modules[i].Base;
        status = STATUS_SUCCESS;
        break;
    }
done:
    ExFreePoolWithTag(header, NU_TAG);
    return status;
}

/* hal: Resolve the private sender only on the pinned kernel */
static PVOID NuRoutine(PCWSTR Name, ULONG Rva)
{
    UNICODE_STRING name;
    PVOID address;
    RtlInitUnicodeString(&name, Name);
    address = MmGetSystemRoutineAddress(&name);
    return (UINT64)(ULONG_PTR)address == gNu.KernelBase + Rva ? address : NULL;
}

/* monitor: Rotate the sender and interrupt every other active processor
 * KeInitializeAffinityEx sets Size=20 on 26100.1. Reject larger groups.
 * Exclude the issuing CPU so NU_PULSE does not dominate its own sample.
 */
static NTSTATUS NuPulse(NU_PULSE_DATA* Result)
{
    NU_AFFINITY targets;
    GROUP_AFFINITY bind = {0}, previous;
    PROCESSOR_NUMBER number;
    ULONG index, sender = MAXULONG, count = 0, attempt;
    UINT64 now = KeQueryInterruptTime();
    if (!gNu.SendNmi || !gNu.InitAffinity || !gNu.AddAffinity) return STATUS_NOT_SUPPORTED;
    if (!InterlockedCompareExchange(&gNu.Armed, 0, 0)) return STATUS_DEVICE_NOT_READY;
    if (gNu.PulseGeneration == (ULONG)gNu.Generation ||
        (gNu.LastPulse && now - gNu.LastPulse < NU_PULSE_MIN_MS * 10000ull))
        return STATUS_DEVICE_BUSY;
    for (attempt = 0; attempt < gNu.CpuCount; ++attempt) {
        index = (gNu.NextSender + attempt) % gNu.CpuCount;
        if (NT_SUCCESS(KeGetProcessorNumberFromIndex(index, &number)) && number.Group < 20 &&
            number.Number < 64 &&
            (KeQueryGroupAffinity(number.Group) & (1ull << number.Number))) {
            sender = index; break;
        }
    }
    if (sender == MAXULONG) return STATUS_NOT_SUPPORTED;
    bind.Group = number.Group;
    bind.Mask = 1ull << number.Number;
    RtlZeroMemory(&targets, sizeof(targets));
    gNu.InitAffinity(&targets);
    if (targets.Size != 20) return STATUS_REVISION_MISMATCH;
    for (index = 0; index < gNu.CpuCount; ++index) {
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(index, &number))) continue;
        if (number.Group >= targets.Size) return STATUS_NOT_SUPPORTED;
        if (index != sender && number.Number < 64 &&
            (KeQueryGroupAffinity(number.Group) & (1ull << number.Number))) {
            gNu.AddAffinity(&targets, index); ++count;
        }
    }
    if (!count) return STATUS_NOT_SUPPORTED;
    gNu.NextSender = (sender + 1) % gNu.CpuCount;
    gNu.PulseGeneration = (ULONG)gNu.Generation;
    gNu.LastPulse = now;
    Result->Generation = (ULONG)gNu.Generation;
    Result->SenderCpu = sender;
    Result->TargetCount = count;
    KeSetSystemGroupAffinityThread(&bind, &previous);
    if (!InterlockedCompareExchange(&gNu.Armed, 0, 0)) {
        KeRevertToUserGroupAffinityThread(&previous);
        return STATUS_DEVICE_NOT_READY;
    }
    gNu.SendNmi(&targets);
    KeRevertToUserGroupAffinityThread(&previous);
    return STATUS_SUCCESS;
}

static NTSTATUS NuComplete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS NuCreateClose(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);
    return NuComplete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS NuCleanup(PDEVICE_OBJECT Device, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Device);
    (void)KeWaitForSingleObject(&gNu.ControlLock, Executive, KernelMode, FALSE, NULL);
    NuStop();
    KeCancelTimer(&gNu.Timer);
    KeFlushQueuedDpcs();
    for (ULONG i = 0; i < gNu.CpuCount; ++i) InterlockedExchange(&gNu.Slots[i].State, NU_EMPTY);
    KeReleaseMutex(&gNu.ControlLock, FALSE);
    return NuComplete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS NuControl(PDEVICE_OBJECT Device, PIRP Irp)
{
    PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG in = io->Parameters.DeviceIoControl.InputBufferLength;
    ULONG out = io->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG cpu, i;
    LARGE_INTEGER due;
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR written = 0;
    UNREFERENCED_PARAMETER(Device);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return NuComplete(Irp, STATUS_INVALID_DEVICE_STATE, 0);
    (void)KeWaitForSingleObject(&gNu.ControlLock, Executive, KernelMode, FALSE, NULL);
    switch (io->Parameters.DeviceIoControl.IoControlCode) {
    case NU_PULSE:
        if (in || out != sizeof(NU_PULSE_DATA)) { status = STATUS_INVALID_PARAMETER; break; }
        {
            NU_PULSE_DATA result = {0};
            status = NuPulse(&result);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(buffer, &result, sizeof(result)); written = sizeof(result);
            }
        }
        break;
    case NU_INFO:
        if (out < sizeof(NU_INFO_DATA)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            NU_INFO_DATA info = {0};
            info.Version = NU_VERSION; info.Build = gNu.Build;
            info.CpuCount = gNu.CpuCount; info.SampleSize = sizeof(NU_SAMPLE);
            info.StackBaseOffset = gNu.BaseOffset; info.StackLimitOffset = gNu.LimitOffset;
            info.CaptureBytes = gNu.CaptureBytes;
            if (gNu.SendNmi && gNu.InitAffinity && gNu.AddAffinity) info.Features |= NU_CAP_PULSE;
            RtlCopyMemory(buffer, &info, sizeof(info));
            written = sizeof(info); status = STATUS_SUCCESS;
        }
        break;
    case NU_ARM:
        if (InterlockedCompareExchange(&gNu.Armed, 0, 0) ||
            InterlockedCompareExchange(&gNu.Active, 0, 0)) {
            status = STATUS_DEVICE_BUSY; break;
        }
        for (i = 0; i < gNu.CpuCount; ++i) {
            LONG state = InterlockedCompareExchange(&gNu.Slots[i].State, 0, 0);
            if (state == NU_READY || state == NU_WRITING || state == NU_READING) break;
        }
        if (i != gNu.CpuCount) { status = STATUS_DEVICE_BUSY; break; }
        KeCancelTimer(&gNu.Timer);
        KeFlushQueuedDpcs();
        for (i = 0; i < gNu.CpuCount; ++i) {
            RtlZeroMemory(&gNu.Slots[i].Sample, sizeof(NU_SAMPLE));
            InterlockedExchange(&gNu.Slots[i].State, NU_WAITING);
        }
        InterlockedIncrement(&gNu.Generation);
        InterlockedExchange(&gNu.Armed, 1);
        due.QuadPart = -10 * 1000 * 1000 * 10ll;
        KeSetTimer(&gNu.Timer, due, &gNu.TimeoutDpc);
        status = STATUS_SUCCESS;
        break;
    case NU_DISARM:
        NuStop();
        status = STATUS_SUCCESS;
        break;
    case NU_READ:
        if (in < sizeof(cpu) || out < sizeof(NU_SAMPLE)) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        RtlCopyMemory(&cpu, buffer, sizeof(cpu));
        if (cpu >= gNu.CpuCount) { status = STATUS_INVALID_PARAMETER; break; }
        if (InterlockedCompareExchange(&gNu.Slots[cpu].State, NU_READING, NU_READY) != NU_READY) {
            status = STATUS_NO_MORE_ENTRIES; break;
        }
        RtlCopyMemory(buffer, &gNu.Slots[cpu].Sample, sizeof(NU_SAMPLE));
        InterlockedExchange(&gNu.Slots[cpu].State, NU_EMPTY);
        written = sizeof(NU_SAMPLE); status = STATUS_SUCCESS;
        break;
    case NU_MODULES:
        status = NuModules(buffer, out, &written);
        break;
    }
    KeReleaseMutex(&gNu.ControlLock, FALSE);
    return NuComplete(Irp, status, written);
}

static VOID NuUnload(PDRIVER_OBJECT Driver)
{
    UNICODE_STRING link;
    LARGE_INTEGER pause;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(Driver);
    InterlockedExchange(&gNu.Armed, 0);
    KeCancelTimer(&gNu.Timer);
    KeFlushQueuedDpcs();
    status = KeDeregisterNmiCallback(gNu.NmiHandle);
    NT_ASSERT(NT_SUCCESS(status));
    pause.QuadPart = -10000;
    while (InterlockedCompareExchange(&gNu.Active, 0, 0))
        KeDelayExecutionThread(KernelMode, FALSE, &pause);
    RtlInitUnicodeString(&link, L"\\DosDevices\\Bubble");
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(gNu.Device);
    ExFreePoolWithTag(gNu.Slots, NU_TAG);
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name, link, sddl;
    NTSTATUS status;
    SIZE_T bytes;
    status = NuProfile(RegistryPath);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "Bubble: build/profile validation failed: %08x\n", status);
        return status;
    }
    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) return status;
    status = NuTargetKernel();
    if (!NT_SUCCESS(status)) return status;
    gNu.InitAffinity = (NU_INIT_AFFINITY)NuRoutine(L"KeInitializeAffinityEx", 0x422280);
    gNu.AddAffinity = (NU_ADD_AFFINITY)NuRoutine(L"KeAddProcessorAffinityEx", 0x2779a0);
    gNu.SendNmi = (NU_SEND_NMI)NuRoutine(L"HalSendNMI", 0x4d0b10);
    gNu.CpuCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    bytes = (SIZE_T)gNu.CpuCount * sizeof(NU_SLOT);
    if (!bytes || bytes > 128 * 1024 * 1024) return STATUS_INSUFFICIENT_RESOURCES;
    gNu.Slots = ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, NU_TAG);
    if (!gNu.Slots) return STATUS_INSUFFICIENT_RESOURCES;
    KeInitializeMutex(&gNu.ControlLock, 0);
    KeInitializeTimer(&gNu.Timer);
    KeInitializeDpc(&gNu.TimeoutDpc, NuTimeout, &gNu);
    RtlInitUnicodeString(&name, L"\\Device\\Bubble");
    RtlInitUnicodeString(&link, L"\\DosDevices\\Bubble");
    RtlInitUnicodeString(&sddl, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    status = IoCreateDeviceSecure(Driver, 0, &name, 0x8337, FILE_DEVICE_SECURE_OPEN,
                                  TRUE, &sddl, &NuDeviceGuid, &gNu.Device);
    if (!NT_SUCCESS(status)) goto fail;
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) goto fail_device;
    Driver->MajorFunction[IRP_MJ_CREATE] = NuCreateClose;
    Driver->MajorFunction[IRP_MJ_CLOSE] = NuCreateClose;
    Driver->MajorFunction[IRP_MJ_CLEANUP] = NuCleanup;
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NuControl;
    gNu.NmiHandle = KeRegisterNmiCallback(NuNmiEntry, &gNu);
    if (!gNu.NmiHandle) { status = STATUS_INSUFFICIENT_RESOURCES; goto fail_link; }
    Driver->DriverUnload = NuUnload;
    gNu.Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
fail_link:
    IoDeleteSymbolicLink(&link);
fail_device:
    IoDeleteDevice(gNu.Device);
fail:
    ExFreePoolWithTag(gNu.Slots, NU_TAG);
    return status;
}
