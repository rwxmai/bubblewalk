# monitor: Stream observed IOCTL dispatches until Ctrl+C
[CmdletBinding()]
param(
    [ValidateRange(1,60000)][int]$IntervalMs = 1,
    [ValidateRange(0,2147483647)][int]$Rounds = 0,
    [string]$Collector = "$PSScriptRoot\..\build\Release\bubble.exe",
    [ValidateRange(1,100)][int]$DutyPercent = 1
)
$ErrorActionPreference = 'Stop'
$collectorPath = (Resolve-Path $Collector).Path
$service = Get-Service -Name Bubble -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'Start the configured Bubble driver before monitoring.' }
& $collectorPath monitor --interval-ms $IntervalMs --rounds $Rounds --duty-percent $DutyPercent
if ($LASTEXITCODE -ne 0) { throw "Monitor stopped with exit code $LASTEXITCODE." }
