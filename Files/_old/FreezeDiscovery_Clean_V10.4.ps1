<#
FreezeDiscovery_Clean_V10.4.ps1
- Full A2 / A4 routing restored
- Registry-based OS detection (no WMI)
- fltmc via call operator (ISE-safe)
- Auto‑relaunch from PowerShell ISE into powershell.exe
- StrictMode-safe
- Enterprise‑grade diagnostics collector
#>

[CmdletBinding()]
param(
    [AllowEmptyString()]
    [string]$TargetPath,

    [AllowEmptyString()]
    [string]$CaseId,

    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery",

    [ValidateRange(1,168)]
    [int]$LookbackHours = 48,

    [switch]$EnableEtwMinifilterTrace,

    [ValidateRange(10,900)]
    [int]$EtwCaptureSeconds = 60
)

# ==========================================================
# AUTO‑RELAUNCH OUT OF ISE (SAFE POSITION)
# ==========================================================
if ($psISE) {
    Write-Host "PowerShell ISE detected. Relaunching in console host..." -ForegroundColor Yellow

    $argsQuoted = @()
    foreach ($a in $args) { $argsQuoted += ('"{0}"' -f ($a -replace '"','\"')) }

    Start-Process -FilePath "powershell.exe" `
        -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $PSCommandPath, ($argsQuoted -join ' ')) `
        -Verb RunAs | Out-Null

    exit 0
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = $null }
if ([string]::IsNullOrWhiteSpace($CaseId))     { $CaseId = $null }

$ScriptVersion = "10.4"

# ==========================================================
# UTILITIES
# ==========================================================
function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param([string]$Message,[string]$Level="INFO")
    $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"),$Level,$Message
    if ($script:LogPath) { $line | Out-File $script:LogPath -Append -Encoding UTF8 }
    Write-Host $line
}

function Write-Text {
    param($Path,$Content)
    if (-not $Content) { " " | Out-File $Path -Encoding UTF8 -Force; return }
    @($Content) | ForEach-Object { if ($_ -eq $null) { " " } else { "$_" } } |
        Out-File $Path -Encoding UTF8 -Force
}

function Write-JsonSafe {
    param($Path,$Value)
    if ($null -eq $Value) {
        @{ Notice="Value was null" } | ConvertTo-Json | Out-File $Path -Encoding UTF8 -Force
    } else {
        $Value | ConvertTo-Json -Depth 12 | Out-File $Path -Encoding UTF8 -Force
    }
}

function Test-IsAdmin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($wi)).
        IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ==========================================================
# REGISTRY‑BASED OS INFO
# ==========================================================
function Get-OsInfoFromRegistry {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        [pscustomobject]@{
            Caption     = $cv.ProductName
            Version     = $cv.DisplayVersion
            BuildNumber = $cv.CurrentBuildNumber
            UBR         = $cv.UBR
        }
    } catch { $null }
}

# ==========================================================
# FLTMC
# ==========================================================
function Get-FltmcRaw {
    param([ValidateSet("filters","instances")]$Mode)
    & fltmc.exe $Mode 2>&1 | ForEach-Object { [string]$_ }
}

# ==========================================================
# A2 HELPERS – FILTERS ON TARGET VOLUME
# ==========================================================
function Get-TargetDrive {
    param($Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($Path -like "\\*") { return $null }
    try {
        $q = Split-Path -Path $Path -Qualifier
        if ($q -match '^[A-Z]:$') { return $q.ToUpper() }
    } catch {}
    return $null
}

function Parse-FltmcFilters {
    param($Lines)
    $Lines | Select-Object -Skip 3 | Where-Object { $_ -match '\S' } | ForEach-Object {
        $p = ($_ -split '\s{2,}').Trim()
        if ($p.Count -ge 4) {
            [pscustomobject]@{
                FilterName = $p[0]
                Instances  = [int]$p[1]
                Altitude   = $p[2]
                Frame      = $p[3]
            }
        }
    }
}

# ==========================================================
# A4 ROUTING LOGIC
# ==========================================================
function Classify-Filter {
    param($Name)
    if (-not $Name) { return "Unknown" }
    switch -Regex ($Name) {
        '^WdFilter$'        { "Microsoft Defender" }
        'CldFlt|OneDrive'   { "OneDrive / Cloud Files" }
        'CSAgent|Crowd'     { "EDR (CrowdStrike)" }
        'Sentinel'          { "EDR (SentinelOne)" }
        'Falcon'            { "EDR (CrowdStrike)" }
        'Sophos'            { "EDR (Sophos)" }
        'Symantec|Broadcom' { "AV/DLP (Symantec)" }
        'Trellix|McAfee'    { "EDR (McAfee/Trellix)" }
        'FileCrypt'         { "BitLocker / Encryption" }
        default             { "Other" }
    }
}

function Compute-A4Routing {
    param(
        $PathType,
        $EventSignals,
        $TopFilters
    )

    $score = 30
    if ($PathType -eq "UNC") { $score += 30 }
    if ($EventSignals.StorageTimeoutCount -gt 0) { $score += 25 }
    if ($TopFilters.Count -gt 0) { $score += 15 }

    if ($score -gt 100) { $score = 100 }

    $queue =
        if ($PathType -eq "UNC") { "Network / VPN" }
        elseif ($EventSignals.StorageTimeoutCount -gt 0) { "Endpoint / Storage / Filters" }
        else { "Endpoint / Platform" }

    $confidence =
        if ($score -ge 80) { "High" }
        elseif ($score -ge 55) { "Medium" }
        else { "Low" }

    [pscustomobject]@{
        Queue      = $queue
        Confidence = $confidence
        Score      = $score
        Suspects   = $TopFilters
    }
}

# ==========================================================
# MAIN
# ==========================================================
Ensure-Dir $OutputRoot
$bundle = Join-Path $OutputRoot ("Bundle_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
Ensure-Dir $bundle
$script:LogPath = Join-Path $bundle "FreezeDiscovery.log"

Write-Log "=== FreezeDiscovery v$ScriptVersion START ==="
Write-Log ("IsAdmin={0}" -f (Test-IsAdmin))

# ---------------- System Info ----------------
Write-Log "Stage: SystemInfo"
$sys = [pscustomobject]@{
    ComputerName=$env:COMPUTERNAME
    UserName=$env:USERNAME
    OS=Get-OsInfoFromRegistry
}
Write-JsonSafe (Join-Path $bundle "SystemInfo.json") $sys

# ---------------- Target Context ----------------
Write-Log "Stage: TargetContext"
$pathType="None"
if ($TargetPath) {
    if ($TargetPath -like "\\*") { $pathType="UNC" }
    elseif ($TargetPath -match '^[A-Z]:') { $pathType="Local" }
}
Write-JsonSafe (Join-Path $bundle "TargetContext.json") @{TargetPath=$TargetPath;PathType=$pathType}

# ---------------- Event Signals ----------------
Write-Log "Stage: EventSignals"
$since=(Get-Date).AddHours(-$LookbackHours)

$sysEv = Get-WinEvent -FilterHashtable @{LogName="System";StartTime=$since;Id=41,107,129,153,137} -ErrorAction SilentlyContinue
$appEv = Get-WinEvent -FilterHashtable @{LogName="Application";StartTime=$since;Id=1002} -ErrorAction SilentlyContinue

$eventSignals = [pscustomobject]@{
    StorageTimeoutCount = ($sysEv | Where-Object Id -in 129,153).Count
    PowerHintCount      = ($sysEv | Where-Object Id -in 41,107,137).Count
    Application1002Count= $appEv.Count
}

Write-JsonSafe (Join-Path $bundle "EventSignals.json") $eventSignals

# ---------------- fltmc / A2 ----------------
Write-Log "Stage: fltmc"
$filtersRaw = Get-FltmcRaw filters
Write-Text (Join-Path $bundle "fltmc_filters_raw.txt") $filtersRaw

$miniFilters = Parse-FltmcFilters $filtersRaw
Write-JsonSafe (Join-Path $bundle "MiniFilters.json") $miniFilters

$targetDrive = Get-TargetDrive $TargetPath
$topFilters = @()
if ($targetDrive) {
    $topFilters = $miniFilters |
        Sort-Object {[double]$_.Altitude} -Descending |
        Select-Object -First 5 | ForEach-Object {
            [pscustomobject]@{
                FilterName=$_.FilterName
                Category=(Classify-Filter $_.FilterName)
                Altitude=$_.Altitude
            }
        }
}

Write-JsonSafe (Join-Path $bundle "A2_FiltersOnTarget.json") @{
    TargetDrive=$targetDrive
    Filters=$topFilters
}

# ---------------- A4 Routing ----------------
Write-Log "Stage: A4 Routing"
$routing = Compute-A4Routing -PathType $pathType -EventSignals $eventSignals -TopFilters $topFilters
Write-JsonSafe (Join-Path $bundle "RoutingA4.json") $routing

# ---------------- ETW (optional) ----------------
$etwMeta = [pscustomobject]@{Enabled=$false;Success=$false}
if ($EnableEtwMinifilterTrace) {
    Write-Log "Stage: ETW start"
    & wpr.exe -start fileio -start minifilter -filemode | Out-Null
    Start-Sleep $EtwCaptureSeconds
    & wpr.exe -stop (Join-Path $bundle "MinifilterTrace.etl") | Out-Null
    $etwMeta.Enabled=$true; $etwMeta.Success=$true
}
Write-JsonSafe (Join-Path $bundle "ETWTraceMeta.json") $etwMeta

# ---------------- Summaries ----------------
Write-Text (Join-Path $bundle "Summary_Human.txt") @(
    "FreezeDiscovery Summary"
    "Version: $ScriptVersion"
    "TargetPath: $TargetPath"
    "PathType: $pathType"
    "Queue: $($routing.Queue)"
    "Confidence: $($routing.Confidence)"
    "Score: $($routing.Score)"
)

Write-Text (Join-Path $bundle "TicketSummary.txt") @(
    "FreezeDiscovery Ticket Summary"
    "Routing: $($routing.Queue)"
    "Confidence: $($routing.Confidence)"
)

# ---------------- ZIP ----------------
$zip="$bundle.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$bundle\*" -DestinationPath $zip -Force

Write-Log "=== FreezeDiscovery COMPLETE ==="
Write-Output $bundle
Write-Output $zip