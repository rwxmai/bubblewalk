# bubblewalk

Continuous NMI sampling of Windows driver IOCTL dispatch. **bubble.sys** captures
interrupted CPU state and stack bytes; **bubble.exe** unwinds them and streams
observations. No driver list, file reputation or IOCTL semantics participate.

tested in Win 11 24H2 (ntoskrnl 10.0.26100.1)

## Run

Build with Visual Studio x64, Windows 11 SDK/WDK and CMake 3.20+:

```powershell
cmake -S . -B build -A x64
cmake --build build --config Release
msbuild driver\Bubble.vcxproj /p:Configuration=Release /p:Platform=x64
```

Configure the isolated guest with [Configure-Lab.ps1](scripts/Configure-Lab.ps1),
install the signed `bubble.sys`, and start the Bubble service. From an elevated
terminal:

```powershell
.\build\Release\bubble.exe monitor --interval-ms 250
```

Run the driver workload separately. `bubble demo` starts the same monitor.
Ctrl+C drains the current round and closes the device. `--rounds N` bounds a run;
`--verbose` includes stack frames and incomplete observations.

## Evidence

`nmi_ioctl` reports the **submitted IOCTL**, input/output lengths, dispatch image,
PC, thread address, CPU and capture generation. The code remains opaque.

For the IRP path, adjacent unwind frames must recover these kernel return sites:
`IofCallDriver` → `IopSynchronousServiceTail` → `IopXxxControlFile` →
`NtDeviceIoControlFile`. A separate predicate handles fast I/O. Exact call sites,
frame extents and duplicate argument slots must agree. Generic driver execution
or `IofCallDriver` alone produces no IOCTL observation.

The wrapper's suspended RSP preserves the submitted code at `+28h`, with its
incoming copy at `+98h`. Both come from the NMI stack snapshot. No live IRP is
chased, and no volatile argument register is guessed.
[Dispatch profile and coverage](docs/ioctl-monitor.md).

## Capture

`SIDT`, `SGDT`, `STR` resolve vector 2's IST. Ki/Kx saves recover the interrupted
GPRs. A generated C/MASM ABI fixes the callback spill layout; `REP MOVSB` copies
resident bytes into preallocated slots. `StackWalk64` consumes snapshots and PE
unwind metadata afterward. [Save layout](docs/26100.1.md).

The sender rotates across CPUs, calls the pinned `HalSendNMI` export and excludes
itself. Each round closes admission, drains captures and compares module
inventories. JSON round counters expose delivery gaps and incomplete walks.

Sampling can miss short requests. The decoder covers the pinned user-request
paths; kernel-originated requests, deferred workers and verifier-altered dispatch
chains can lack the required frames. The reported code is the original submitted
value, which a downstream driver may change. An observation establishes activity,
not exploitation. A quiet monitor establishes neither absence nor safety.

Existing PC-provenance checks still report unowned or non-executable frames.
[Evidence limits](docs/nmi-detection.md).
