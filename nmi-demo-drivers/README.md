# Bubblewalk lab fixtures

Two separate, harmless workloads exercise Bubblewalk's two observations on its
pinned Windows 11 `26100.1` guest. These are research controls, not malware or a
reproduction of `mhyprot2`.

| Workload | Load route | Intended Bubblewalk evidence |
| --- | --- | --- |
| `nmi-fixture.sys` | Manually map with the local kdmapper in the approved guest | `NMI_UNOWNED_RIP` while its own code runs |
| `nmi-ioctl-lab.sys` + `nmi-ioctl-client.exe` | Normal test-signed service + user-mode `DeviceIoControl` caller | `nmi_ioctl` if the pinned dispatch chain is sampled |

The worker starts one system thread, runs 20 ms compute bursts separated by
5 ms rests for 30 seconds, logs `NMI_FIXTURE_START/END` with function addresses,
then terminates itself. It has no device interface or privileged action.
**Do not use kdmapper's `--free` option:** it could release the mapped image
while the worker still executes. Wait for `NMI_FIXTURE_END` before reverting the
guest snapshot. The entry point deliberately does not use its `DriverObject`.

The normally loaded lab driver creates `\\.\NmiIoctlLab` with System and
Administrators access only. It accepts a status request and a PID-shaped
evaluation request. Evaluation always returns `LAB_DECISION_DENIED`; it never
looks up, opens, terminates or modifies the target process. Its `--hold-ms`
diagnostic mode performs at most 20 ms of active arithmetic *within dispatch*
to measure sampling sensitivity. This is artificial duration, not typical
driver latency. The client prints request-level JSON lines with timestamps,
code, lengths, result and decision. Bubblewalk cannot see the PID or intent in
its `nmi_ioctl` event, and sampled event counts are not request counts.

## Build

Use Visual Studio x64 with the WDK and SDK. The projects target installed WDK
`10.0.28000.0`; retarget both projects if your WDK version differs. From this
directory:

```powershell
msbuild .\mapped-worker\MappedWorker.vcxproj /p:Configuration=Release /p:Platform=x64
msbuild .\ioctl-lab\IoctlLab.vcxproj /p:Configuration=Release /p:Platform=x64
cmake -S .\ioctl-lab -B .\out\client-build -A x64
cmake --build .\out\client-build --config Release
```

Output driver names are `out\Release\nmi-fixture.sys` and
`out\Release\nmi-ioctl-lab.sys`. The mapped worker does not use a normal service
load. Both projects disable WDK's automatic `TestSign` target; the
`nmi-ioctl-lab.sys` output is signed explicitly with `/fd SHA256` below. If an
earlier build stopped at `SIGNTASK: No file digest algorithm specified`, rerun
the two `msbuild` commands after updating these project files. The sandboxed
authoring environment could compile/link the drivers
directly with MSVC/WDK, but its MSBuild file tracker
failed with `E_ACCESSDENIED`; see validation status below.

## Add the IOCTL lab to an existing Bubblewalk guest

Follow [Bubblewalk's own setup](../README.md#run) for `bubble.sys` and
`bubble.exe`. This section assumes your isolated `26100.1` guest already has
test-signing enabled, trusts the certificate used for `bubble.sys`, and has a
configured `Bubble` service. There is no new `bcdedit`, reboot, certificate
creation, `Bubble` registration, or `Configure-Lab.ps1` step for this fixture.

**Sign only the new `nmi-ioctl-lab.sys`.** Run this on the machine where you
signed Bubblewalk, from `nmi-demo-drivers`. Bubblewalk's existing signed
`bubble.sys` and public `bubble.cer` are at `..\out\driver\Release\`.
Read the signer thumbprint from that signed `bubble.sys`; the matching private
key must be accessible to your signing account in `Cert:\CurrentUser\My`.
`bubble.cer` alone cannot sign. Use the same `signtool.exe` installation and
`/fd SHA256` pattern that worked for Bubblewalk:

```powershell
$bubbleSignature = Get-AuthenticodeSignature ..\out\driver\Release\bubble.sys
if (-not $bubbleSignature.SignerCertificate) { throw 'Existing bubble.sys has no embedded signer.' }
$signer = Get-Item "Cert:\CurrentUser\My\$($bubbleSignature.SignerCertificate.Thumbprint)" -ErrorAction Stop
if (-not $signer.HasPrivateKey) { throw 'Matching Bubblewalk signing key unavailable.' }
signtool.exe sign /v /fd SHA256 /s My /sha1 $signer.Thumbprint .\out\Release\nmi-ioctl-lab.sys
```

If you previously signed using `Cert:\LocalMachine\My`, select that store and
add `/sm` to SignTool. If the key is in a PFX, use the same PFX signing method
you used for Bubblewalk. A different certificate would need guest trust setup;
reusing the Bubblewalk signer avoids that step. The mapped `nmi-fixture.sys`
does not use a service load, so signing it is optional. An unchanged, already
signed `bubble.sys` needs no action here; if you rebuild Bubblewalk, follow its
re-sign and driver replacement instruction separately.

Copy the **signed** `out\Release\nmi-ioctl-lab.sys` and
`out\client-build\Release\nmi-ioctl-client.exe` into the guest alongside your
existing Bubblewalk files. The example below uses `C:\NullconDemo` as the guest
directory; set `$labDir` to your actual Bubblewalk directory. From an elevated
guest PowerShell terminal, with the signed file in that directory:

```powershell
$labDir = 'C:\NullconDemo'
Get-AuthenticodeSignature "$labDir\nmi-ioctl-lab.sys" | Format-List Status,SignerCertificate
sc.exe create NmiIoctlLab type= kernel start= demand binPath= "$labDir\nmi-ioctl-lab.sys"
sc.exe start NmiIoctlLab
sc.exe query NmiIoctlLab
& "$labDir\nmi-ioctl-client.exe" --mode status --count 1
```

The signature should show `Status : Valid`; the status request should succeed.
`sc.exe create` runs only the first time. To replace a rebuilt lab driver,
stop its service, wait for `STOPPED`, copy the newly signed file over the old
one, then start it again. Keep Bubblewalk's monitor running in a second elevated
terminal as directed by its README. No Bubble service change is needed for a
new IOCTL fixture build.

Sources: [Bubblewalk run instructions](../README.md#run),
[Microsoft embedded driver signatures](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-a-driver-file),
[certificate/private-key distinction](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/inspect-certificates-manage-certificate-stores),
[SignTool options](https://learn.microsoft.com/en-us/windows/desktop/seccrypto/signtool),
and [`sc.exe create`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create).

## Pinned guest sequence

1. In the already configured `26100.1` guest, check `sc.exe query Bubble`;
   if it is `STOPPED`, run `sc.exe start Bubble`. Then start
   `bubble.exe monitor --rounds 120 --verbose`
   before launching either workload. Keep stdout and stderr separately.
2. Run the existing root `Ioctl-Workload.ps1` against the guest's test disk as
   a benign read-only IOCTL baseline.
3. With `NmiIoctlLab` started as above, run
   `nmi-ioctl-client.exe --mode evaluate --count 100 --spacing-ms 20`
   to send natural short requests. Repeat with `--hold-ms 20` only as a labelled
   diagnostic timing control. `--read-only` and `--bad-length` are negative
   controls; see [client usage](ioctl-lab/CLIENT.md).
4. On a disposable guest snapshot, manually map `nmi-fixture.sys` using the
   local kdmapper **without `--free`**. Capture mapper allocation-base output,
   the PE `SizeOfImage` (`dumpbin /headers nmi-fixture.sys`), and the worker's
   `NMI_FIXTURE_START/END` kernel debug lines through an attached kernel debugger
   or configured kernel debug capture. The worker self-terminates after
   30 seconds; revert the snapshot afterward. With kdmapper's default
   header-skipping mode, the allocation base is the first mapped section, so
   use the logged function addresses and PE section RVAs to establish the
   precise executable range; do not treat the allocation base as the PE base.

Keep the lab driver and mapped-worker trials separate for clear attribution.
For `nmi_ioctl`, require a captured sample with the known lab code and dispatch
image during the client trace. For `NMI_UNOWNED_RIP`, require its PC to lie in
the logged mapped allocation range during the worker interval. Report
`nmi_round.targeted/captured/context_recovered_samples/incomplete_samples`
and actual `pulse_interval_ms`; a requested 1 ms with the default 1% duty
budget does not imply 1 kHz sampling. Missing findings can reflect timing or
incomplete capture.

## Validation status

- Static source review confirmed Bubblewalk's IOCTL observer needs the
  `NtDeviceIoControlFile` user-request path and image-backed dispatch frames;
  the mapped worker is therefore a separate provenance workload.
- Both kernel sources compiled with `/W4 /WX` and linked to `.sys` using
  MSVC 14.51 and WDK 10.0.28000.0 in the authoring sandbox.
- The user-mode client independently built as Release x64 with `/W4 /WX`;
  help and invalid-argument CLI checks passed. Ordinary WDK MSBuild linking
  outside the sandbox is unverified. Both project files now evaluate to
  `SignMode=Off` and `EnableTestSign=false`; the prior WDK automatic signing
  error is bypassed in the build graph, with explicit SHA-256 signing above.
- No fixture has been loaded or run. No Bubblewalk detection rate, EDR alert,
  request effect, or guest stability result has been measured.

Sources: [Bubblewalk IOCTL contract](../docs/ioctl-monitor.md),
[provenance contract](../docs/nmi-detection.md),
[Microsoft IOCTL security guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/security-issues-for-i-o-control-codes),
[Microsoft device SDDL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/sddl-for-device-objects).
