# bubblewalk

NMI stack provenance for Windows 11 24H2, ntoskrnl 10.0.26100.1, AMD64.

Build bubble.exe with CMake and bubble.sys with the Windows 11 WDK. Configure
the isolated guest with scripts/Configure-Lab.ps1, load the signed driver and
run `bubble capture bubble.nwu`. Inject one external NMI during the armed
window, then run `bubble analyze bubble.nwu`. Preserve bubble.nwu.images.

The callback copies resident stack bytes. The analyzer recovers interrupted
GPRs and unwinds PE metadata offline. Unowned PCs and non-executable image
addresses produce independent findings. Missing context and failed unwinds
remain incomplete. Module membership does not attest runtime bytes.

[save layout](docs/26100.1.md)
