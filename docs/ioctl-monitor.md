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

At the dispatch calls returning to `32BF1D` and `870004`, the runtime validator
accepts the original thunk at RVA `664660` and the pinned kernel's loader
overrides at `B57780` and `B577E0`. All retain a five-byte CALL and the same
return PC. Other checked bytes remain exact, and the archived PE must retain
the original disk bytes. See [loader overrides and load diagnostics](26100.1.md#loader-function-overrides).

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

1. Query the module inventory and cache matching PE metadata and kernel-profile validation.
2. Arm zeroed per-CPU slots under the control mutex.
3. Rotate the sender, bind its group affinity and send one NMI to each other
   active processor. The private HAL/affinity exports must match the profile.
4. Poll and drain captures for at most 100 ms. Disarm waits for admitted callbacks.
5. Compare the inventory, unwind and emit observations plus a round summary.
6. Rest for the round's duty budget and any remaining requested pulse interval
   plus jitter; repeat until Ctrl+C.

The default requested interval is 1 ms; `--interval-ms` accepts 1–60,000 ms.
Additive jitter is an integer from zero through `floor(interval_ms / 4)`, so a
1 ms request has zero jitter. Client timing uses `QueryInterruptTimePrecise` and
a high-resolution waitable timer without spinning. The driver uses a precise
clock to enforce at least 1 ms after the previous send call completes and still
allows only one send per armed generation. Both client and driver must be
rebuilt, and the rebuilt driver re-signed and installed, to use the 1 ms floor.

`--duty-percent` accepts 1–100 and defaults to 1. After measuring a round's wall
time, including inventory checks, acquisition, decoding and flushed output, the
client requires additional rest of `ceil(work * (100 - duty) / duty)`. At 1%,
10 ms of round work requires 990 ms of rest. The wait satisfies both this budget
and the interval measured from the completed NMI-send IOCTL. Serialized work and
the budget can therefore make actual pulse spacing much longer than requested;
the settings do not guarantee CPU utilization or a 1 kHz sampling rate.

If the driver returns `ERROR_BUSY`, the client waits and retries within the same
armed generation for up to 250 ms. `nmi_round` reports `rate_limit_retries`,
`pulse_interval_ms` from client timestamps after send completion (`null` for the
first round), and `context_recovered_samples`. This approximates pulse spacing
rather than hardware send time. Its `elapsed_ms` measures round work and excludes
the final rest; it is not the sampling period.

Matching image metadata and read-only kernel-profile validation remain cached
until the recorded module identity changes. A 4 MB inventory buffer, snapshot
buffers and the IOCTL completion event are reused across rounds. Every round
still compares inventories and applies the same capture and dispatch criteria.

On normal shutdown, `monitor_stopped` includes `collector_cpu_ms` and
`collector_cpu_percent_of_one_core`, measured from the collector process's kernel
plus user CPU time over the monitor loop. These measurements exclude NMI work
on other CPUs and do not establish the monitor's effect on the workload.

The current sender is excluded from that round and rotates on the next. A
delivery gap stops monitoring before another generation. The ten-second arm
lease and file cleanup close admission after collector loss.

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

## Diagnose rejected captures

Use `bubble monitor --interval-ms 1 --duty-percent 1 --rounds 20 --verbose` to include
`nmi_stack` reports. They include the raw decimal `capture_flags` bitmask and
specific context rejection reasons:

| Stop | Meaning |
| --- | --- |
| `context_ARCH_INVALID` | The active descriptor/IST interpretation or frame geometry was rejected |
| `context_STACK_UNSUPPORTED` | Interrupted state was outside the supported KTHREAD stack bounds |
| `context_NMI_TRUNCATED` | The handler snapshot exceeded the capture buffer |
| `user_context` | The NMI interrupted user-mode execution |

These cases stop before stack walking. A captured NMI with zero recovered frames
does not establish that an IOCTL was absent. The client reports existing capture
flags; this diagnostic change does not require a new driver protocol.

## Sampling brief requests

Shorter actual pulse spacing improves the chance of sampling repeated brief
calls, but does not record every request. For randomly timed samples, the relevant
duration is time executing a supported dispatch chain on a sampled CPU, not
request-buffer size or time queued waiting for completion. The excluded sender
CPU and unusable captures further limit coverage.

Recover valid contexts before increasing the sample rate. Use `pulse_interval_ms`
to assess actual spacing under the duty budget. Acquisition, inventory checks,
unwinding and output remain serialized. A future producer/consumer design would need
bounded buffering, generation-specific inventories, serialized DbgHelp access and
explicit drop counts. Complete request accounting requires request-boundary
instrumentation in a controlled caller/driver or tracing that the target exposes.

Native verification uses the actual pinned kernel's `.pdata/.xdata` and instruction
bytes with constructed stack snapshots. It checks both dispatch paths through
Windows DbgHelp; it does not substitute for a live NMI capture.
