#include <ntddk.h>
#include <wdmsec.h>
#include <aux_klib.h>
#include <ntimage.h>
#include <intrin.h>
#include "../include/protocol.h"
#include "../include/target_26100_1.h"

#define NU_TAG 'wUmN'
#define NU_EMPTY 0
#define NU_WAITING 1
#define NU_WRITING 2
#define NU_READY 3
#define NU_READING 4

C_ASSERT(sizeof(NU_REGS) == 160);
C_ASSERT(sizeof(NU_SAMPLE) == 73992);

typedef struct NU_SLOT { volatile LONG State; NU_SAMPLE Sample; } NU_SLOT;
typedef struct NU_DEVICE {
    PDEVICE_OBJECT Device;
    NU_SLOT* Slots;
    ULONG CpuCount, Build, BaseOffset, LimitOffset, CaptureBytes;
    volatile LONG Armed, Active, Generation;
    UINT64 KernelBase;
    PVOID NmiHandle;
    KMUTEX ControlLock;
    KTIMER Timer;
    KDPC TimeoutDpc;
} NU_DEVICE;

#pragma pack(push, 1)
typedef struct NU_DTR { USHORT Limit; UINT64 Base; UCHAR Padding[6]; } NU_DTR;
typedef struct NU_TABLES { NU_DTR Idt, Gdt; USHORT Tr; } NU_TABLES;
#pragma pack(pop)

extern BOOLEAN NuNmiEntry(PVOID Context, BOOLEAN Handled);
extern VOID NuReadTables(NU_TABLES* Tables);
static NU_DEVICE gNu;
static const GUID NuDeviceGuid =
    {0x8b973c74,0x23d1,0x4c10,{0xac,0x35,0x02,0xc1,0xa9,0x27,0x13,0x43}};

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
    case NU_INFO:
        if (out < sizeof(NU_INFO_DATA)) { status = STATUS_BUFFER_TOO_SMALL; break; }
        {
            NU_INFO_DATA info = {0};
            info.Version = NU_VERSION; info.Build = gNu.Build;
            info.CpuCount = gNu.CpuCount; info.SampleSize = sizeof(NU_SAMPLE);
            info.StackBaseOffset = gNu.BaseOffset; info.StackLimitOffset = gNu.LimitOffset;
            info.CaptureBytes = gNu.CaptureBytes;
            RtlCopyMemory(buffer, &info, sizeof(info));
            written = sizeof(info); status = STATUS_SUCCESS;
        }
        break;
    }
    KeReleaseMutex(&gNu.ControlLock, FALSE);
    return NuComplete(Irp, status, written);
}

static VOID NuUnload(PDRIVER_OBJECT Driver)
{
    UNICODE_STRING link;
    UNREFERENCED_PARAMETER(Driver);
    RtlInitUnicodeString(&link, L"\\DosDevices\\Bubble");
    IoDeleteSymbolicLink(&link);
    IoDeleteDevice(gNu.Device);
}

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name, link, sddl;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);
    gNu.CpuCount = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    KeInitializeMutex(&gNu.ControlLock, 0);
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
    Driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NuControl;
    Driver->DriverUnload = NuUnload;
    gNu.Device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
fail_device:
    IoDeleteDevice(gNu.Device);
fail:
    return status;
}
