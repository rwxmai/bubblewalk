# profile: Bind KTHREAD offsets to the exact guest build
[CmdletBinding()]
param(
    [uint32]$ExpectedBuild = 26100,
    [uint32]$StackBaseOffset = 0x38,
    [uint32]$StackLimitOffset = 0x30,
    [ValidateRange(512,65536)][uint32]$CaptureBytes = 65536
)
$ErrorActionPreference = 'Stop'
$actual = [uint32](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
if ($ExpectedBuild -ne $actual -or $actual -ne 26100) {
    throw "Expected Windows 11 build $ExpectedBuild; this guest reports $actual."
}
foreach ($offset in @($StackBaseOffset, $StackLimitOffset)) {
    if ($offset -eq 0 -or $offset -gt 0x1000 -or ($offset % 8) -ne 0) {
        throw 'Offsets must be nonzero, 8-byte aligned and within the supported profile bound.'
    }
}
$service = 'HKLM:\SYSTEM\CurrentControlSet\Services\Bubble'
if (-not (Test-Path $service)) { throw 'Register the Bubble kernel-driver service first.' }
$key = New-Item "$service\Parameters" -Force
$values = @{
    ExpectedBuild = $ExpectedBuild
    EnableLabCapture = 1
    KthreadStackBaseOffset = $StackBaseOffset
    KthreadStackLimitOffset = $StackLimitOffset
    CaptureBytes = $CaptureBytes
}
foreach ($name in $values.Keys) {
    New-ItemProperty -Path $key.PSPath -Name $name -PropertyType DWord -Value $values[$name] -Force | Out-Null
}
Write-Host 'Profile written. DriverEntry will independently compare the offsets with IoGetStackLimits.'
