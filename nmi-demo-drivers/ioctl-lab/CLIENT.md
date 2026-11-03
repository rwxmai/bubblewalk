# IOCTL lab client

Run in the isolated guest after the test-signed `nmi-ioctl-lab.sys` service is
started. The client opens `\\.\NmiIoctlLab`; the lab driver grants access to
System and Administrators.

```powershell
.\nmi-ioctl-client.exe --mode status --count 5
.\nmi-ioctl-client.exe --mode evaluate --count 100 --spacing-ms 20 > natural.jsonl
.\nmi-ioctl-client.exe --mode evaluate --count 100 --spacing-ms 20 --hold-ms 20 > diagnostic.jsonl
.\nmi-ioctl-client.exe --mode evaluate --count 5 --read-only > access-denied.jsonl
.\nmi-ioctl-client.exe --mode evaluate --count 5 --bad-length > invalid-length.jsonl
```

`--pid N` sets a request field only. The driver does not inspect or act on that
process. Default is the client PID. Each JSON line records the submitted code,
buffer lengths, start/end Windows FILETIME, elapsed time, Win32 result, and
validated reply. The summary gives sent/completed counts. The status code uses
read access; evaluate uses write access. `--read-only` is expected to fail
before dispatch, while `--bad-length` reaches dispatch and is rejected there.
The 20 ms hold is an artificial active calculation for sampling experiments.

The client cannot establish a Bubblewalk finding alone. Correlate its code,
lengths, and time window with Bubblewalk `nmi_ioctl` events, then report NMI
round capture and usable-context counts alongside the client summary.
