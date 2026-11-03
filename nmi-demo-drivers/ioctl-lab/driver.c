#include <ntddk.h>
#include <wdmsec.h>
#include "protocol.h"

static const GUID LabClassGuid =
    {0xebec3ae7, 0xf2cf, 0x4528, {0xb8, 0xf8, 0xda, 0x0f, 0x61, 0x41, 0xd3, 0x90}};
static volatile LONG gDiagnosticChecksum;

static NTSTATUS Finish(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS LabCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return Finish(Irp, STATUS_SUCCESS, 0);
}

/* Artificial hold used only to measure sampled-dispatch sensitivity. */
static ULONG DiagnosticWork(ULONG Milliseconds, ULONG Seed)
{
    ULONGLONG start = KeQueryInterruptTimePrecise(NULL);
    ULONGLONG deadline = start + ((ULONGLONG)Milliseconds * 10000ull);
    volatile ULONG value = Seed;
    while (Milliseconds && KeQueryInterruptTimePrecise(NULL) < deadline) {
        for (ULONG i = 0; i < 512; ++i)
            value = value * 1664525u + 1013904223u + i;
    }
    InterlockedExchange(&gDiagnosticChecksum, (LONG)value);
    return (ULONG)((KeQueryInterruptTimePrecise(NULL) - start) / 10ull);
}

static NTSTATUS LabDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG input = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG output = stack->Parameters.DeviceIoControl.OutputBufferLength;
    LAB_REPLY reply = { LAB_VERSION, 0, LAB_DECISION_DENIED, 0 };
    LAB_REQUEST request;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(DeviceObject);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return Finish(Irp, STATUS_INVALID_DEVICE_STATE, 0);
    if (!Irp->AssociatedIrp.SystemBuffer || output < sizeof(reply))
        return Finish(Irp, STATUS_BUFFER_TOO_SMALL, 0);

    switch (code) {
    case LAB_IOCTL_STATUS:
        if (input != 0) return Finish(Irp, STATUS_INVALID_BUFFER_SIZE, 0);
        reply.Decision = 0;
        break;
    case LAB_IOCTL_EVALUATE:
        status = IoValidateDeviceIoControlAccess(Irp, FILE_WRITE_DATA);
        if (!NT_SUCCESS(status)) return Finish(Irp, status, 0);
        if (input != sizeof(request))
            return Finish(Irp, STATUS_INVALID_BUFFER_SIZE, 0);
        RtlCopyMemory(&request, Irp->AssociatedIrp.SystemBuffer, sizeof(request));
        if (request.Version != LAB_VERSION || request.TargetPid == 0 ||
            request.HoldMs > LAB_MAX_HOLD_MS)
            return Finish(Irp, STATUS_INVALID_PARAMETER, 0);
        reply.RequestId = request.RequestId;
        reply.ElapsedUs = DiagnosticWork(request.HoldMs, request.RequestId);
        break;
    default:
        return Finish(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }

    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &reply, sizeof(reply));
    return Finish(Irp, STATUS_SUCCESS, sizeof(reply));
}

static VOID LabUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\NmiIoctlLab");
    IoDeleteSymbolicLink(&link);
    if (DriverObject->DeviceObject) IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Device\\NmiIoctlLab");
    UNICODE_STRING link = RTL_CONSTANT_STRING(L"\\DosDevices\\NmiIoctlLab");
    UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT device = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    status = IoCreateDeviceSecure(DriverObject, 0, &name, LAB_DEVICE_TYPE,
        FILE_DEVICE_SECURE_OPEN, FALSE, &sddl, &LabClassGuid, &device);
    if (!NT_SUCCESS(status)) return status;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = LabCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = LabCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LabDeviceControl;
    DriverObject->DriverUnload = LabUnload;
    status = IoCreateSymbolicLink(&link, &name);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(device);
        return status;
    }
    device->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}
