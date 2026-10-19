# IOCTL monitor

`bubble monitor` and `bubble demo` continuously sample actual driver traffic.
Neither command generates requests for the driver under observation. The monitor
uses its own control device to arm, send NMIs and drain snapshots.

## Dispatch evidence

The 26100.1 profile accepts adjacent frames, youngest first:

| Path | Return PCs, relative to ntoskrnl |
|---|---|
| IRP | dispatch frame, `32BF1D`, `871277`, `870284`, `86F97E` |
| Fast I/O | dispatch frame, `870004`, `86F97E` |

`32BF1D` follows the CFG dispatch call in `IofCallDriver`. `871277` follows
`IopSynchronousServiceTail`'s call to `IofCallDriver`. `870284` follows the call
to that service tail. `86F97E` is the wrapper's return from `IopXxxControlFile`.
`870004` follows the fast-device-control callback through CFG.

The IRP chain's stack deltas must be `40h`, `B0h`, `270h`; the fast-I/O path
requires `270h` between Iop and Nt. Every frame through the wrapper must have
valid executable image coverage. Missing suffixes do not erase a verified prefix.
These checks establish consistency under the selected kernel profile. They do
not authenticate a stack against a kernel attacker that can rewrite it.

The unwound Nt frame's RSP addresses two copies of its arguments:

| Value | Outgoing slot | Incoming slot |
|---|---|---|
| Submitted IOCTL | `+28h` | `+98h` |
| Input length | `+38h` | `+A8h` |
| Output length | `+48h` | `+B8h` |

Both copies must agree. The device-control selector at `+50h` must be one.
The distinct Nt return site excludes `NtFsControlFile`, which shares Iop's
implementation. All reads stay inside the captured stack interval. No IRP,
DEVICE_OBJECT, request buffer or user address is dereferenced during analysis.

The dispatch image owns the frame immediately below the validated dispatch
boundary. A framework dispatcher can therefore name the framework's image;
this field does not claim to identify its client driver or every lower filter.
The code describes the original submission, not a modified downstream request.

## Round lifecycle

1. Query the module inventory and cache matching PE metadata.
2. Arm zeroed per-CPU slots under the control mutex.
3. Rotate the sender, bind its group affinity and send one NMI to each other
   active processor. The private HAL/affinity exports must match the profile.
4. Poll and drain captures for at most 100 ms. Disarm waits for admitted callbacks.
5. Compare the inventory, unwind and emit observations plus a round summary.
6. Wait for the configured period plus 0–25% jitter; repeat until Ctrl+C.

The default period is 250 ms; the driver enforces at least 50 ms between sends
and one send per generation. The current sender is excluded from that round and
rotates on the next. A delivery gap stops monitoring before another generation.
The ten-second arm lease and file cleanup close admission after collector loss.

This remains a lab capture mechanism: `HalSendNMI` is private, source attribution
is absent, and hardware-fault NMIs received while armed are consumed too. A stalled
or hostile hypervisor can delay delivery beyond the capture window. Counters do
not establish trusted delivery timing or resistance to an in-kernel adversary.

## Coverage

Observed request type and numeric code require no reputation rule. Short calls
can run entirely between samples. Kernel-created/internal requests, detached
workers, alternate stacks, altered verifier paths, unavailable PE files and
failed unwinds may produce no IOCTL event. Module unload/reload between inventory
endpoints is not excluded by matching endpoint inventories.

Repeated samples can describe one request; event count is not request count.
`nmi_round` reports targeted/captured CPUs and incomplete samples. Zero IOCTL
observations means no supported dispatch was observed in those samples.

Native verification uses the actual pinned kernel's `.pdata/.xdata` and instruction
bytes with constructed stack snapshots. It checks both dispatch paths through
Windows DbgHelp; it does not substitute for a live NMI capture.
