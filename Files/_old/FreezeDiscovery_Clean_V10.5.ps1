<#
FreezeDiscovery_Clean_V29_Compatible.ps1
Purpose: Stable freeze diagnostics collector
Design goals:
 - NEVER hang
 - NEVER block on event logs
 - Never use Get-WinEvent, CIM, jobs, or ETW by default
 - Produce output even if subsystems fail
#>

[CmdletBinding()]
param(
    [string]$TargetPath,
    [string]$CaseId,
    [int]$LookbackHours = 48,
    [string]$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery"
)

# ---------------- SAFETY: Relaunch out of ISE ----------------
if ($psISE) {
    Start-Process powershell.exe `
        -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $PSCommandPath, ($args -join ' ')) `
        -Verb RunAs
    exit
}

Set-StrictMode -Version 2
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = "<not provided>" }
if ([string]::IsNullOrWhiteSpace($CaseId))     { $CaseId = "<not provided>" }

# ---------------- Utilities ----------------
function Ensure-Dir($p) {
    if (-not (Test-Path $p)) {
        New-Item -ItemType Directory -Path $p -Force | Out-Null
    }
}

function Log($m) {
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $m
    $line | Out-File $script:LogPath -Append -Encoding UTF8
    Write-Host $line
}

function Write-Json($path,$obj) {
    try { $obj | ConvertTo-Json -Depth 10 | Out-File $path -Encoding UTF8 -Force }
    catch { "{ }" | Out-File $path -Encoding UTF8 -Force }
}

function Write-Text($path,$lines) {
    if (-not $lines) { " " | Out-File $path -Force; return }
    $lines | Out-File $path -Encoding UTF8 -Force
}

# ---------------- Output setup ----------------
Ensure-Dir $OutputRoot
$Bundle = Join-Path $OutputRoot ("Bundle_" + (Get-Date -Format yyyyMMdd_HHmmss))
Ensure-Dir $Bundle
$script:LogPath = Join-Path $Bundle "FreezeDiscovery.log"

Log "=== FreezeDiscovery START (v29‑compatible) ==="
Log ("IsAdmin=" + ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(544))

# ---------------- System Info (REGISTRY ONLY) ----------------
Log "Stage: SystemInfo"
$cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$sys = @{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = @{
        Name    = $cv.ProductName
        Version = $cv.DisplayVersion
        Build   = $cv.CurrentBuildNumber
        UBR     = $cv.UBR
    }
}
Write-Json (Join-Path $Bundle "SystemInfo.json") $sys

# ---------------- Target Context ----------------
Log "Stage: TargetContext"
$PathType = if ($TargetPath -like "\\*") { "UNC" } elseif ($TargetPath -match '^[A-Z]:') { "Local" } else { "Unknown" }
Write-Json (Join-Path $Bundle "TargetContext.json") @{ TargetPath=$TargetPath; PathType=$PathType }

# ---------------- Event Signals (WEVTUTIL — SAFE) ----------------
Log "Stage: EventSignals (wevtutil – safe)"

$sinceMs = ($LookbackHours * 3600000)

$systemText = & wevtutil qe System /q:"*[System[(EventID=41 or EventID=107 or EventID=129 or EventID=153) and TimeCreated[timediff(@SystemTime)<=$sinceMs]]]" /f:text 2>$null
$appText    = & wevtutil qe Application /q:"*[System[(EventID=1002) and TimeCreated[timediff(@SystemTime)<=$sinceMs]]]" /f:text 2>$null

$eventSignals = @{
    StorageTimeoutCount   = ([regex]::Matches($systemText,'Event ID:\s+129|Event ID:\s+153')).Count
    PowerHintCount        = ([regex]::Matches($systemText,'Event ID:\s+41|Event ID:\s+107')).Count
    Application1002Count  = ([regex]::Matches($appText,'Event ID:\s+1002')).Count
    CollectionMethod      = "wevtutil"
}

Write-Json (Join-Path $Bundle "EventSignals.json") $eventSignals

# ---------------- fltmc (DIRECT CALL) ----------------
Log "Stage: fltmc"
$fltFilters = @( & fltmc filters 2>&1 )
$fltInstances = @( & fltmc instances 2>&1 )

Write-Text (Join-Path $Bundle "fltmc_filters_raw.txt") $fltFilters
Write-Text (Join-Path $Bundle "fltmc_instances_raw.txt") $fltInstances

# ---------------- A2: Top Filters by Altitude ----------------
Log "Stage: A2 Filters"
$parsed = $fltFilters | Select-Object -Skip 3 | Where-Object { $_ -match '\S' } | ForEach-Object {
    $p = ($_ -split '\s{2,}').Trim()
    if ($p.Count -ge 3) {
        [pscustomobject]@{ Name=$p[0]; Altitude=$p[2] }
    }
}

$topFilters = $parsed | Sort-Object { [double]$_.Altitude } -Descending | Select-Object -First 5
Write-Json (Join-Path $Bundle "A2_TopFilters.json") $topFilters

# ---------------- A4: Routing (SIMPLE, STABLE) ----------------
Log "Stage: A4 Routing"
$routing = @{
    Queue =
        if ($PathType -eq "UNC") { "Network / VPN" }
        elseif ($eventSignals.StorageTimeoutCount -gt 0) { "Endpoint / Storage" }
        else { "Endpoint / Platform" }

    Confidence =
        if ($eventSignals.StorageTimeoutCount -gt 0 -or $PathType -eq "UNC") { "High" }
        else { "Medium" }

    Score =
        50 +
        (if ($PathType -eq "UNC") { 25 } else { 0 }) +
        (if ($eventSignals.StorageTimeoutCount -gt 0) { 25 } else { 0 })
}
Write-Json (Join-Path $Bundle "RoutingA4.json") $routing

# ---------------- Summaries ----------------
Write-Text (Join-Path $Bundle "Summary_Human.txt") @(
    "FreezeDiscovery Summary"
    "Case: $CaseId"
    "TargetPath: $TargetPath"
    "PathType: $PathType"
    "Queue: $($routing.Queue)"
    "Confidence: $($routing.Confidence)"
)

Write-Text (Join-Path $Bundle "TicketSummary.txt") @(
    "Freeze observed."
    "Routing: $($routing.Queue)"
    "Confidence: $($routing.Confidence)"
)

# ---------------- Zip ----------------
$zip = "$Bundle.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$Bundle\*" -DestinationPath $zip -Force

Log "=== FreezeDiscovery COMPLETE ==="
Write-Output $Bundle
Write-Output $zip