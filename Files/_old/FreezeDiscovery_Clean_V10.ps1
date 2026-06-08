<#
 FreezeDiscovery_Clean_V10.ps1
 PS 5.1 / ISE safe
 - Full rewrite
 - Fixes all syntax issues
 - Adds optional ETW (WPR) minifilter + fileio trace
 - Guaranteed artifacts, never crashes
#>

[CmdletBinding()]
param(
    [AllowEmptyString()]
    [string]$TargetPath,

    [AllowEmptyString()]
    [string]$CaseId,

    [string]$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery",

    [switch]$EnableEtwMinifilterTrace,

    [ValidateRange(10,900)]
    [int]$EtwCaptureSeconds = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ==========================================================
# Normalize inputs
# ==========================================================
if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = $null }
if ([string]::IsNullOrWhiteSpace($CaseId))     { $CaseId     = $null }

# ==========================================================
# Utilities
# ==========================================================
function Ensure-Dir {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Text {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [AllowNull()][AllowEmptyString()][AllowEmptyCollection()][object]$Content
    )

    $lines = @()
    if ($null -eq $Content) {
        $lines = @(" ")
    }
    elseif ($Content -is [string]) {
        if ([string]::IsNullOrEmpty($Content)) { $lines = @(" ") }
        else { $lines = @($Content) }
    }
    else {
        $lines = @($Content)
        if ($lines.Count -eq 0) { $lines = @(" ") }
    }

    $safe = foreach ($l in $lines) {
        if ($null -eq $l -or [string]::IsNullOrEmpty([string]$l)) { " " }
        else { [string]$l }
    }

    $safe | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Write-JsonSafe {
    param([Parameter(Mandatory=$true)][string]$Path, $Value)

    if ($null -eq $Value) {
        @{ Notice="Value was null"; Time=(Get-Date).ToString("o") } |
            ConvertTo-Json -Depth 4 |
            Out-File -FilePath $Path -Encoding UTF8 -Force
        return
    }

    $Value |
        ConvertTo-Json -Depth 12 |
        Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Test-IsAdmin {
    try {
        $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
        $wp = New-Object Security.Principal.WindowsPrincipal($wi)
        return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Invoke-External {
    param([string]$Exe,[string[]]$Args)
    & $Exe @Args 2>&1 | ForEach-Object { [string]$_ }
}

# ==========================================================
# ETW / WPR minifilter trace (best‑effort)
# ==========================================================
function Start-WprMinifilterTrace {
    param([string]$Bundle,[int]$Seconds)

    $meta = [pscustomobject]@{
        Enabled   = $true
        Success   = $false
        Error     = $null
        OutputEtl = (Join-Path $Bundle "MinifilterTrace.etl")
    }

    if (-not (Test-IsAdmin)) {
        $meta.Error = "Not elevated"
        return $meta
    }

    try {
        & wpr.exe -cancel | Out-Null
        & wpr.exe -start fileio -start minifilter -filemode | Out-Null
        Start-Sleep -Seconds $Seconds
        & wpr.exe -stop $meta.OutputEtl | Out-Null
        if (Test-Path $meta.OutputEtl) { $meta.Success = $true }
    }
    catch {
        $meta.Error = $_.Exception.Message
        try { & wpr.exe -cancel | Out-Null } catch {}
    }

    return $meta
}

# ==========================================================
# Bundle setup
# ==========================================================
Ensure-Dir -Path $OutputRoot
$bundle = Join-Path $OutputRoot ("Bundle_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
Ensure-Dir -Path $bundle

# ==========================================================
# System info
# ==========================================================
$sys = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = $null
}
try {
    $sys.OS = Get-CimInstance Win32_OperatingSystem |
              Select-Object Caption, Version, BuildNumber
} catch {}
Write-JsonSafe -Path (Join-Path $bundle "SystemInfo.json") -Value $sys

# ==========================================================
# Target context
# ==========================================================
$pathType = "None"
if ($TargetPath) {
    if ($TargetPath -like "\\*") { $pathType = "UNC" }
    elseif ($TargetPath -match "^[A-Za-z]:") { $pathType = "Local" }
}
Write-JsonSafe -Path (Join-Path $bundle "TargetContext.json") -Value @{
    TargetPath = $TargetPath
    PathType   = $pathType
}

# ==========================================================
# Event signals (A3)
# ==========================================================
function Get-EventSignals {
    param([int]$LookbackHours = 48)

    $since = (Get-Date).AddHours(-$LookbackHours)
    $sysIds = 41,107,137,129,153
    $appIds = 1002

    $sysEv = Get-WinEvent -FilterHashtable @{
        LogName="System"; StartTime=$since; Id=$sysIds
    } -ErrorAction SilentlyContinue

    $appEv = Get-WinEvent -FilterHashtable @{
        LogName="Application"; StartTime=$since; Id=$appIds
    } -ErrorAction SilentlyContinue

    $rows = @(
        $sysEv | Select-Object @{n="LogName";e={"System"}},TimeCreated,Id,ProviderName,LevelDisplayName,Message
        $appEv | Select-Object @{n="LogName";e={"Application"}},TimeCreated,Id,ProviderName,LevelDisplayName,Message
    ) | Sort-Object TimeCreated -Descending

    return [pscustomobject]@{
        StorageTimeoutCount  = @($sysEv | Where-Object Id -in 129,153).Count
        PowerHintCount       = @($sysEv | Where-Object Id -in 41,107,137).Count
        Application1002Count = @($appEv).Count
        Events               = $rows
    }
}

$eventSignals = Get-EventSignals
Write-JsonSafe -Path (Join-Path $bundle "EventSignals.json") -Value $eventSignals

$csv = $eventSignals.Events
if (-not $csv) {
    $csv = @([pscustomobject]@{
        LogName=$null;TimeCreated=$null;Id=$null;ProviderName=$null;LevelDisplayName=$null;Message=$null
    })
}
$csv | Export-Csv -Path (Join-Path $bundle "SystemEvents_48h.csv") -NoTypeInformation -Force

# ==========================================================
# ETW trace (optional)
# ==========================================================
$etwMeta = [pscustomobject]@{ Enabled=$false }
if ($EnableEtwMinifilterTrace) {
    $etwMeta = Start-WprMinifilterTrace -Bundle $bundle -Seconds $EtwCaptureSeconds
}
Write-JsonSafe -Path (Join-Path $bundle "ETWTraceMeta.json") -Value $etwMeta

# ==========================================================
# Human summary
# ==========================================================
Write-Text -Path (Join-Path $bundle "Summary_Human.txt") -Content @(
    "FreezeDiscovery Summary"
    "-----------------------"
    "Case: $(if($CaseId){$CaseId}else{'<not provided>'})"
    "TargetPath: $(if($TargetPath){$TargetPath}else{'<not provided>'})"
    "PathType: $pathType"
    ""
    "Signals:"
    " StorageTimeoutCount: $($eventSignals.StorageTimeoutCount)"
    " PowerHintCount: $($eventSignals.PowerHintCount)"
    " Application1002Count: $($eventSignals.Application1002Count)"
    ""
    "ETW Minifilter Trace: $($etwMeta.Success)"
)

# ==========================================================
# Zip bundle
# ==========================================================
$zip = "$bundle.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $bundle "*") -DestinationPath $zip -Force

Write-Output "Bundle folder: $bundle"
Write-Output $zip