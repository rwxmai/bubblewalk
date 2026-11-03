#include <ntddk.h>

/* Research fixture: bounded execution in a manually mapped image. */
#define WORK_DURATION_100NS (30ull * 10000000ull)
#define BURST_DURATION_100NS (20ull * 10000ull)
#define REST_DURATION_100NS (-5ll * 10000ll)

static volatile LONG gWorkChecksum;
NTSTATUS CustomDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);

__declspec(noinline)
static ULONG WorkChunk(ULONG seed)
{
    volatile ULONG value = seed;
    for (ULONG i = 0; i < 4096; ++i) {
        value = (value * 1664525u) + 1013904223u + i;
    }
    return value;
}

static VOID NTAPI WorkerThread(PVOID Context)
{
    ULONGLONG start, deadline, now;
    ULONG state = 0x4e4d4931u;
    LARGE_INTEGER rest;
    UNREFERENCED_PARAMETER(Context);

    start = KeQueryInterruptTimePrecise(NULL);
    deadline = start + WORK_DURATION_100NS;
    rest.QuadPart = REST_DURATION_100NS;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "NMI_FIXTURE_START entry=%p worker=%p chunk=%p start_100ns=%llu duration_ms=30000\n",
        CustomDriverEntry, WorkerThread, WorkChunk, start);

    while ((now = KeQueryInterruptTimePrecise(NULL)) < deadline) {
        ULONGLONG burstEnd = now + BURST_DURATION_100NS;
        if (burstEnd > deadline) burstEnd = deadline;
        do {
            state = WorkChunk(state);
        } while (KeQueryInterruptTimePrecise(NULL) < burstEnd);
        if (KeQueryInterruptTimePrecise(NULL) < deadline)
            KeDelayExecutionThread(KernelMode, FALSE, &rest);
    }

    InterlockedExchange(&gWorkChecksum, (LONG)state);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
        "NMI_FIXTURE_END worker=%p end_100ns=%llu checksum=%08lx\n",
        WorkerThread, KeQueryInterruptTimePrecise(NULL), state);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS CustomDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    OBJECT_ATTRIBUTES attributes;
    HANDLE thread = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, &attributes,
        NULL, NULL, WorkerThread, NULL);
    if (NT_SUCCESS(status)) ZwClose(thread);
    return status;
}
