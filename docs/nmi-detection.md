# NMI evidence

The monitor reports IOCTL activity independently of PC-provenance anomalies.
An ordinary signed driver's fully image-backed dispatch can produce `nmi_ioctl`.
See [the dispatch profile](ioctl-monitor.md) for the required chain and fields.

The provenance evaluator retains four independent findings:

| Finding | Evidence |
|---|---|
| `NMI_UNOWNED_RIP` | Interrupted RIP lies outside inventoried modules |
| `NMI_UNOWNED_CALLER` | A recovered caller lies outside those modules |
| `NMI_RIP_OUTSIDE_EXECUTABLE_SECTIONS` | RIP lacks executable PE section coverage |
| `NMI_CALLER_OUTSIDE_EXECUTABLE_SECTIONS` | A caller lacks that coverage |

No filename, vulnerable-driver hash or external catalog enters either predicate.
Module boundaries supply ownership; archived PE sections supply permissions and
unwind records. They do not attest runtime bytes, PTE permissions or signatures.

## Unwind contract

The callback snapshots resident state into preallocated slots. Reconstruction
recovers interrupted GPRs from the pinned Ki/Kx saves. DbgHelp walks offline;
ordinary kernel unwind routines are not called from the NMI callback.

x64 unwind metadata supports interrupted prologs and epilogs. Context switches,
unsupported stack transitions, missing metadata and overwritten return addresses
can still stop reconstruction. A raw pointer scan is not a call chain. Unknown
code terminates the walk instead of receiving an invented leaf unwind rule.

The first PC is exact RIP. Later PCs are return addresses. Classification can
use PC-1 at an executable boundary while retaining the raw PC. IOCTL matching
uses exact return sites and independent frame-extent checks.

Missing context, changed inventories, missing image metadata and failed walks
remain incomplete. A verified IOCTL prefix can survive an unavailable outer
suffix. No observation proves exploitation or identifies a BYOVD entry mechanism.

## Lab

Start `bubble monitor`, exercise the driver separately and retain stdout as JSONL.
Inspect `nmi_ioctl` alongside `nmi_round`; missing or unsupported observations are
part of the coverage result. Ctrl+C stops the session. Use `--rounds N` for a
bounded recording, and `--verbose` when diagnosing context or unwind failures.

`bubble capture bubble.nwu` retains the single external-NMI capture path;
`bubble analyze bubble.nwu` applies both observers offline. Preserve the adjacent
`bubble.nwu.images` directory. NWU3 contains stacks and module identities, not
copied driver request buffers.

NMI delivery controlled by a hostile hypervisor can bias observations. Kernel
code can tamper with the observer or its inputs. The monitor is not an independent
trust boundary against those components.
