#pragma once

/* Include ntddk.h or windows.h/winioctl.h before this header. */
#define LAB_DEVICE_TYPE 0x8338u
#define LAB_VERSION 1u
#define LAB_IOCTL_STATUS CTL_CODE(LAB_DEVICE_TYPE, 0x800u, METHOD_BUFFERED, FILE_READ_DATA)
#define LAB_IOCTL_EVALUATE CTL_CODE(LAB_DEVICE_TYPE, 0x801u, METHOD_BUFFERED, FILE_WRITE_DATA)
#define LAB_DECISION_DENIED 1u
#define LAB_MAX_HOLD_MS 20u

typedef struct _LAB_REQUEST {
    ULONG Version;
    ULONG RequestId;
    ULONG TargetPid;
    ULONG HoldMs;
} LAB_REQUEST;

typedef struct _LAB_REPLY {
    ULONG Version;
    ULONG RequestId;
    ULONG Decision;
    ULONG ElapsedUs;
} LAB_REPLY;
