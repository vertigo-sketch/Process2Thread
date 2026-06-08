<#
.SYNOPSIS
  FreezeDiscovery (PS 5.1-safe) - Evidence collector for file/app/system freezes with vendor-ready reporting.

.DESCRIPTION
  Local-first paths:
    Tools:   C:\Temp\Process2Thread\handle.exe (optional), procmon.exe (optional)
    Output:  C:\Temp\Process2Thread\FreezeDiscovery\

  Produces:
    - Summary_Human.txt
    - VendorReport.md / VendorReport.txt
    - TargetContext.json
    - VolumeCorrelation.json
    - MiniFilters.json / MiniFilterInstances.json
    - fltmc_filters_raw.txt / fltmc_instances_raw.txt
    - SystemEvents_48h.csv
    - Optional HandleSearch.txt (if TargetPath + handle.exe)
    - Optional ProcmonTrace.pml (if -CaptureProcmon)
    - ZIP bundle

.PARAMETER TargetPath
  Optional file/folder path suspected to be locked/frozen (local or UNC).

.PARAMETER CaseId
  Optional incident/ticket ID included in reports.

.PARAMETER CaptureProcmon
  Captures a short Procmon trace to .PML (requires procmon.exe).

.PARAMETER ProcmonSeconds
  Procmon capture duration (5..600), default 30.

#>

[CmdletBinding()]
param(
  [string]$TargetPath,
  [string]$CaseId,
  [switch]$CaptureProcmon,
  [ValidateRange(5, 600)]
  [int]$ProcmonSeconds = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# -----------------------------
# Constants (your required paths)
# -----------------------------
$ToolRoot   = "C:\Temp\Process2Thread"
$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery"

# -----------------------------
# Utility Functions (PS 5.1-safe)
# -----------------------------

function Test-IsAdmin {
  try {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Ensure-Folder {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function New-BundleFolder {
  Ensure-Folder -Path $OutputRoot
  $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $bundle = Join-Path $OutputRoot ("Bundle_{0}" -f $stamp)
  Ensure-Folder -Path $bundle
  return $bundle
}

function Find-Tool {
  param([Parameter(Mandatory=$true)][string]$FileName)

  $candidates = @(
    (Join-Path $ToolRoot $FileName),
    (Join-Path $PSScriptRoot $FileName),
    "$env:ProgramFiles\Sysinternals\$FileName",
    "$env:ProgramFiles(x86)\Sysinternals\$FileName"
  )

  $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

function Write-Json {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)]$Object,
    [int]$Depth = 8
  )
  $Object | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Write-TextFile {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string[]]$Lines
  )
  # Allow blank lines (""), because summaries/reports need them.
  $Lines | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Get-VpnNetworkSnapshot {
  $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
  $routes = Get-NetRoute -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } |
    Sort-Object -Property RouteMetric

  # Best-effort SMB connections (available on modern Windows)
  $smb = $null
  try { $smb = Get-SmbConnection -ErrorAction SilentlyContinue } catch { $smb = $null }

  [pscustomobject]@{
    UpAdapters    = $adapters | Select-Object Name, InterfaceDescription, LinkSpeed, MacAddress
    DefaultRoutes = $routes   | Select-Object InterfaceAlias, NextHop, RouteMetric
    SmbConnections = $smb | Select-Object ServerName, ShareName, UserName, Dialect, NumOpens, EncryptData
  }
}

function Get-ProcessSnapshotTop {
  # Robust CPU sorting: normalizes null CPU to 0 and avoids Sort-Object CPU pitfalls
  Get-Process |
    Select-Object Name, Id,
      @{Name='CPUSeconds';Expression={ if ($null -eq $_.CPU) { 0 } else { [double]$_.CPU } }},
      @{Name='WorkingSetMB';Expression={ [math]::Round($_.WorkingSet64 / 1MB, 1) }},
      @{Name='Handles';Expression={ $_.Handles }},
      @{Name='Threads';Expression={ $_.Threads.Count }},
      Responding |
    Sort-Object -Property CPUSeconds -Descending |
    Select-Object -First 30
}

function Get-RelevantSystemEvents48h {
  $since = (Get-Date).AddHours(-48)
  $ids = 41,107,137,129,153
  Get-WinEvent -FilterHashtable @{ LogName="System"; StartTime=$since; Id=$ids } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
}

function Get-FltmcRaw {
  param([Parameter(Mandatory=$true)][ValidateSet('filters','instances')][string]$Mode)
  # Capture stdout+stderr for vendor defensibility
  return ,(& fltmc $Mode 2>&1)
}

function Parse-FltmcFilters {
  param([string[]]$Lines)

  if (-not $Lines -or $Lines.Count -lt 4) { return @() }
  $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

  $out = @()
  foreach ($r in $rows) {
    $p = ($r -split '\s{2,}').Trim()
    if ($p.Count -ge 4) {
      $out += [pscustomobject]@{
        FilterName = $p[0]
        Instances  = [int]$p[1]
        Altitude   = $p[2]
        Frame      = $p[3]
      }
    }
  }
  return $out
}

function Parse-FltmcInstances {
  param([string[]]$Lines)

  if (-not $Lines -or $Lines.Count -lt 4) { return @() }
  $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

  $out = @()
  foreach ($r in $rows) {
    $p = ($r -split '\s{2,}').Trim()
    if ($p.Count -ge 4) {
      $out += [pscustomobject]@{
        FilterName = $p[0]
        Volume     = $p[1]
        Instance   = $p[2]
        Altitude   = $p[3]
      }
    }
  }
  return $out
}

function Resolve-TargetContext {
  param([string]$TargetPath)

  $ctx = [ordered]@{
    TargetPath = $TargetPath
    PathType   = "None"
    LocalDrive = $null
    UncServer  = $null
    UncShare   = $null
    Notes      = @()
  }

  if ([string]::IsNullOrWhiteSpace($TargetPath)) {
    $ctx.PathType = "None"
    $ctx.Notes += "No TargetPath provided; correlation is limited."
    return [pscustomobject]$ctx
  }

  if ($TargetPath -match '^[\\]{2}([^\\]+)\\([^\\]+)') {
    $ctx.PathType  = "UNC"
    $ctx.UncServer = $matches[1]
    $ctx.UncShare  = $matches[2]
    $ctx.Notes += "UNC path; correlate using SMB/VPN behavior (drive-letter volume correlation is not applicable)."
    return [pscustomobject]$ctx
  }

  try {
    $qual = Split-Path -Path $TargetPath -Qualifier
    if ($qual -and $qual -match '^[A-Za-z]:$') {
      $ctx.PathType   = "Local"
      $ctx.LocalDrive = $qual.ToUpper()
      $ctx.Notes += "Local path; correlate to fltmc instances on the drive letter (best-effort)."
      return [pscustomobject]$ctx
    }
  } catch {
    $ctx.PathType = "Unknown"
    $ctx.Notes += ("Failed to parse target path: {0}" -f $_.Exception.Message)
    return [pscustomobject]$ctx
  }

  $ctx.PathType = "Unknown"
  $ctx.Notes += "Target path is neither UNC nor a drive-qualified local path."
  return [pscustomobject]$ctx
}

function Convert-AltitudeToNumber {
  param([string]$Altitude)
  try { return [double]$Altitude } catch { return -1 }
}

function Build-VolumeCorrelation {
  param(
    [Parameter(Mandatory=$true)][pscustomobject]$TargetCtx,
    [object[]]$Filters,
    [object[]]$Instances
  )

  $vc = [ordered]@{
    CorrelatedVolume   = $null
    InstancesOnVolume  = @()
    FiltersOnVolume    = @()
    Notes              = @()
  }

  if ($TargetCtx.PathType -eq "Local" -and $TargetCtx.LocalDrive) {
    $vc.CorrelatedVolume = $TargetCtx.LocalDrive

    # Most systems report instances volume as "C:" etc.
    $inst = @($Instances | Where-Object { $_.Volume -eq $TargetCtx.LocalDrive })
    $vc.InstancesOnVolume = $inst

    # Filters on that volume = filters with instances on that volume
    $names = @()
    if ($inst.Count -gt 0) {
      $names = $inst | Select-Object -ExpandProperty FilterName -ErrorAction SilentlyContinue | Sort-Object -Unique
    }

    $fltOnVol = @()
    if ($names.Count -gt 0) {
      $fltOnVol = @($Filters | Where-Object { $names -contains $_.FilterName })
    }

    $vc.FiltersOnVolume = $fltOnVol | Sort-Object -Property @{Expression={ Convert-AltitudeToNumber $_.Altitude }; Descending=$true}

    if ($inst.Count -eq 0) {
      $vc.Notes += "No fltmc instances matched by drive letter. On some systems, fltmc may show device-path volumes."
      $vc.Notes += "Use fltmc_instances_raw.txt to verify the volume naming format."
    }

    return [pscustomobject]$vc
  }

  if ($TargetCtx.PathType -eq "UNC") {
    $vc.CorrelatedVolume = "UNC"
    $vc.Notes += "UNC target: drive-letter volume correlation not applicable; focus on SMB/VPN dependency and redirector behavior."
    return [pscustomobject]$vc
  }

  $vc.Notes += "Target context not suitable for volume correlation."
  return [pscustomobject]$vc
}

function Run-HandleSearch {
  param(
    [Parameter(Mandatory=$true)][string]$HandleExe,
    [Parameter(Mandatory=$true)][string]$TargetPath,
    [Parameter(Mandatory=$true)][string]$OutFile
  )
  # -accepteula prevents interactive prompt
  & $HandleExe -accepteula $TargetPath 2>&1 | Out-File -FilePath $OutFile -Encoding UTF8 -Force
}

function Run-ProcmonCapture {
  param(
    [Parameter(Mandatory=$true)][string]$ProcmonExe,
    [Parameter(Mandatory=$true)][string]$OutFolder,
    [Parameter(Mandatory=$true)][int]$Seconds
  )
  $pml = Join-Path $OutFolder "ProcmonTrace.pml"

  # Start capture
  $argsStart = "/AcceptEula /Quiet /Minimized /BackingFile `"$pml`""
  Start-Process -FilePath $ProcmonExe -ArgumentList $argsStart -WindowStyle Hidden | Out-Null

  Start-Sleep -Seconds $Seconds

  # Stop
  Start-Process -FilePath $ProcmonExe -ArgumentList "/Terminate" -WindowStyle Hidden -Wait | Out-Null

  return $pml
}

function Write-HumanSummary {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [pscustomobject]$Sys,
    [pscustomobject]$TargetCtx,
    [pscustomobject]$VolCorr,
    [object[]]$Events,
    [string[]]$Flags,
    [bool]$IsAdmin,
    [string]$CaseId
  )

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("FreezeDiscovery - Human Summary")
  $lines.Add("----------------------------------------")
  if ($CaseId) { $lines.Add("Case/Ticket: " + $CaseId) }
  $lines.Add("Generated: " + (Get-Date).ToString("o"))
  $lines.Add("Computer: " + $Sys.ComputerName + "   User: " + $Sys.UserName)
  $lines.Add("Admin context: " + $IsAdmin)
  $lines.Add("")

  $lines.Add("Target:")
  $lines.Add("  Path: " + (if ($TargetCtx.TargetPath) { $TargetCtx.TargetPath } else { "<none>" }))
  $lines.Add("  Type: " + $TargetCtx.PathType)
  if ($TargetCtx.PathType -eq "Local") {
    $lines.Add("  Drive: " + $TargetCtx.LocalDrive)
  } elseif ($TargetCtx.PathType -eq "UNC") {
    $lines.Add(("  UNC: \\{0}\{1}" -f $TargetCtx.UncServer, $TargetCtx.UncShare))
  }
  $lines.Add("")

  $lines.Add("Key Findings:")
  if ($Flags -and $Flags.Count -gt 0) {
    foreach ($f in $Flags) { $lines.Add("  - " + $f) }
  } else {
    $lines.Add("  - <none>")
  }
  $lines.Add("")

  $lines.Add("Volume Correlation:")
  $lines.Add("  Correlated volume: " + $VolCorr.CorrelatedVolume)
  if ($VolCorr.FiltersOnVolume -and $VolCorr.FiltersOnVolume.Count -gt 0) {
    $lines.Add("  Filters attached to volume (highest altitude first):")
    foreach ($flt in ($VolCorr.FiltersOnVolume | Select-Object -First 10)) {
      $lines.Add(("    - {0} (Altitude {1})" -f $flt.FilterName, $flt.Altitude))
    }
  } else {
    $lines.Add("  - No filters correlated by drive letter (see VolumeCorrelation.json + fltmc_instances_raw.txt).")
  }

  if ($VolCorr.Notes -and $VolCorr.Notes.Count -gt 0) {
    $lines.Add("")
    $lines.Add("Correlation Notes:")
    foreach ($n in $VolCorr.Notes) { $lines.Add("  - " + $n) }
  }

  # Storage timeout indicators sample
  $stor = @($Events | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 } | Select-Object -First 5)
  if ($stor.Count -gt 0) {
    $lines.Add("")
    $lines.Add("Storage Timeout Indicators (sample):")
    foreach ($e in $stor) {
      $lines.Add(("  - {0} | ID {1} | {2}" -f $e.TimeCreated, $e.Id, $e.ProviderName))
    }
  }

  $lines.Add("")
  $lines.Add("Safe Next Steps:")
  $lines.Add("  1) If UNC/VPN suspected: reproduce once with VPN disconnected (if policy allows) and capture a second bundle.")
  $lines.Add("  2) If 129/153 present: escalate to Endpoint/Platform for storage/driver investigation.")
  $lines.Add("  3) If file-specific: include HandleSearch.txt (requires handle.exe) and/or short Procmon trace during repro.")

  Write-TextFile -Path $Path -Lines $lines.ToArray()
}

function Write-VendorReport {
  param(
    [Parameter(Mandatory=$true)][string]$MdPath,
    [Parameter(Mandatory=$true)][string]$TxtPath,
    [pscustomobject]$Sys,
    [pscustomobject]$TargetCtx,
    [pscustomobject]$VolCorr,
    [object[]]$Filters,
    [object[]]$Instances,
    [object[]]$Events,
    [string[]]$Flags,
    [bool]$IsAdmin,
    [string]$CaseId,
    [string]$HandleSearchPath,
    [string]$ProcmonPath
  )

  $md = New-Object System.Collections.Generic.List[string]

  $md.Add("# Vendor Diagnostic Report - FreezeDiscovery")
  $md.Add("")
  if ($CaseId) { $md.Add(("**Case/Ticket:** {0}  " -f $CaseId)) }
  $md.Add(("**Generated:** {0}  " -f (Get-Date).ToString("o")))
  $md.Add(("**Admin context:** {0}  " -f $IsAdmin))
  $md.Add("")

  $md.Add("## 1. Executive Summary")
  $md.Add("- This bundle captures system context, minifilter presence, and event-log indicators to support investigation of freezes/hangs.")
  $md.Add("- Key findings:")
  if ($Flags -and $Flags.Count -gt 0) {
    foreach ($f in $Flags) { $md.Add(("  - {0}" -f $f)) }
  } else {
    $md.Add("  - <no findings>")
  }
  $md.Add("")

  $md.Add("## 2. Environment")
  $os = $Sys.OS
  $bios = $Sys.BIOS
  $md.Add(("- **ComputerName:** {0}" -f $Sys.ComputerName))
  $md.Add(("- **UserName:** {0}" -f $Sys.UserName))
  $md.Add(("- **OS:** {0} {1} (Build {2})" -f $os.Caption, $os.Version, $os.BuildNumber))
  $md.Add(("- **BIOS:** {0} {1}" -f $bios.Manufacturer, $bios.SMBIOSBIOSVersion))
  $md.Add("")

  $md.Add("## 3. Target Context")
  $md.Add(("- **TargetPath:** {0}" -f (if ($TargetCtx.TargetPath) { $TargetCtx.TargetPath } else { "<none>" })))
  $md.Add(("- **PathType:** {0}" -f $TargetCtx.PathType))
  if ($TargetCtx.PathType -eq "Local") {
    $md.Add(("- **Local drive:** {0}" -f $TargetCtx.LocalDrive))
  } elseif ($TargetCtx.PathType -eq "UNC") {
    $md.Add(("- **UNC server/share:** \\{0}\{1}" -f $TargetCtx.UncServer, $TargetCtx.UncShare))
  }
  $md.Add("")

  $md.Add("## 4. Minifilter Evidence (Kernel I/O Interception)")
  $md.Add("> Minifilters intercept file I/O in kernel mode. Filters attached to the affected volume are prime suspects when user-mode tools do not show a file owner.")
  $md.Add("")
  $md.Add(("- Loaded minifilters (fltmc filters): {0}" -f (@($Filters).Count)))
  $md.Add(("- Minifilter instances (fltmc instances): {0}" -f (@($Instances).Count)))
  $md.Add("")

  if ($TargetCtx.PathType -eq "Local") {
    $md.Add(("### 4.1 Filters correlated to volume {0}" -f $VolCorr.CorrelatedVolume))
    if ($VolCorr.FiltersOnVolume -and $VolCorr.FiltersOnVolume.Count -gt 0) {
      $md.Add("| FilterName | Altitude |")
      $md.Add("|---|---:|")
      foreach ($flt in $VolCorr.FiltersOnVolume) {
        $md.Add(("| {0} | {1} |" -f $flt.FilterName, $flt.Altitude))
      }
    } else {
      $md.Add("_No filters correlated by drive letter. Review `fltmc_instances_raw.txt` for volume naming (may be device paths) and rerun elevated if needed._")
    }
    $md.Add("")
  } elseif ($TargetCtx.PathType -eq "UNC") {
    $md.Add("### 4.1 UNC note")
    $md.Add("_UNC targets do not map to local volumes via fltmc instances. Focus on SMB/VPN dependency and redirector behavior._")
    $md.Add("")
  }

  $md.Add("## 5. Event Log Correlation (last 48h)")
  $md.Add("Relevant IDs: 41, 107, 137, 129, 153")
  $md.Add("")
  $stor = @($Events | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 } | Select-Object -First 20)
  if ($stor.Count -gt 0) {
    $md.Add("### 5.1 Storage timeout/reset indicators (129/153)")
    foreach ($e in $stor) {
      $md.Add(("- {0} | ID {1} | {2}" -f $e.TimeCreated, $e.Id, $e.ProviderName))
    }
  } else {
    $md.Add("_No 129/153 events were found in the capture window._")
  }
  $md.Add("")

  $md.Add("## 6. File Lock Owner Evidence (User-mode)")
  if ($HandleSearchPath -and (Test-Path $HandleSearchPath)) {
    $md.Add("- `HandleSearch.txt` included (Sysinternals handle.exe output).")
  } else {
    $md.Add("- `HandleSearch.txt` not present (TargetPath not provided or handle.exe not available).")
  }
  $md.Add("")

  $md.Add("## 7. Procmon Evidence")
  if ($ProcmonPath -and (Test-Path $ProcmonPath)) {
    $md.Add("- Procmon trace included: `ProcmonTrace.pml`")
    $md.Add("- Vendor should filter for the target path and inspect long-duration I/O, retries, or stalled operations.")
  } else {
    $md.Add("- Procmon trace not captured in this run (optional).")
  }
  $md.Add("")

  $md.Add("## 8. Attachments Included")
  $md.Add("- SystemInfo.json")
  $md.Add("- TopProcesses.csv")
  $md.Add("- LogicalDisks.csv")
  $md.Add("- NetworkVpn.json")
  $md.Add("- MiniFilters.json / MiniFilterInstances.json")
  $md.Add("- fltmc_filters_raw.txt / fltmc_instances_raw.txt")
  $md.Add("- SystemEvents_48h.csv")
  $md.Add("- Summary_Human.txt")
  $md.Add("- VendorReport.md / VendorReport.txt")
  $md.Add("")

  $md.Add("## 9. Vendor Actions Requested")
  $md.Add("- Review minifilter behavior on the affected volume (ordering by altitude).")
  $md.Add("- Validate driver readiness across resume/hibernate if power correlation exists.")
  $md.Add("- If storage timeouts are present (129/153), evaluate whether filters delay I/O completion or trigger retries.")
  $md.Add("")

  $mdText = ($md -join "`r`n")
  $mdText | Out-File -FilePath $MdPath -Encoding UTF8 -Force

  # Plain text version (best-effort)
  $txt = $mdText -replace '\*\*', '' -replace '_', '' -replace '\|', ' '
  $txt | Out-File -FilePath $TxtPath -Encoding UTF8 -Force
}

# -----------------------------
# MAIN EXECUTION
# -----------------------------

$bundle = New-BundleFolder
$isAdmin = Test-IsAdmin

# System info
$sys = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  UserName     = $env:USERNAME
  TimeLocal    = (Get-Date).ToString("o")
  OS           = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
  BIOS         = (Get-CimInstance Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer, ReleaseDate)
}
Write-Json -Path (Join-Path $bundle "SystemInfo.json") -Object $sys -Depth 6

# Process snapshot
$procs = Get-ProcessSnapshotTop
$procs | Export-Csv (Join-Path $bundle "TopProcesses.csv") -NoTypeInformation -Encoding UTF8 -Force

# Disk inventory
Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, Size, FreeSpace |
  Export-Csv (Join-Path $bundle "LogicalDisks.csv") -NoTypeInformation -Encoding UTF8 -Force

# Network/VPN
$net = Get-VpnNetworkSnapshot
Write-Json -Path (Join-Path $bundle "NetworkVpn.json") -Object $net -Depth 8

# fltmc raw + parsed
$rawF = Get-FltmcRaw -Mode filters
$rawF | Out-File (Join-Path $bundle "fltmc_filters_raw.txt") -Encoding UTF8 -Force
$rawI = Get-FltmcRaw -Mode instances
$rawI | Out-File (Join-Path $bundle "fltmc_instances_raw.txt") -Encoding UTF8 -Force

$filters = Parse-FltmcFilters -Lines $rawF
$instances = Parse-FltmcInstances -Lines $rawI
Write-Json -Path (Join-Path $bundle "MiniFilters.json") -Object $filters -Depth 6
Write-Json -Path (Join-Path $bundle "MiniFilterInstances.json") -Object $instances -Depth 8

# Events
$events = Get-RelevantSystemEvents48h
$events | Export-Csv (Join-Path $bundle "SystemEvents_48h.csv") -NoTypeInformation -Encoding UTF8 -Force

# powercfg last wake (best-effort)
try {
  & powercfg /lastwake 2>&1 | Out-File (Join-Path $bundle "powercfg_lastwake.txt") -Encoding UTF8 -Force
} catch {
  "powercfg /lastwake failed: $($_.Exception.Message)" | Out-File (Join-Path $bundle "powercfg_lastwake.txt") -Encoding UTF8 -Force
}

# Tools
$handleExe = Find-Tool -FileName "handle.exe"
$procmonExe = Find-Tool -FileName "procmon.exe"

# Target context + correlation
$targetCtx = Resolve-TargetContext -TargetPath $TargetPath
Write-Json -Path (Join-Path $bundle "TargetContext.json") -Object $targetCtx -Depth 6

$volCorr = Build-VolumeCorrelation -TargetCtx $targetCtx -Filters $filters -Instances $instances
Write-Json -Path (Join-Path $bundle "VolumeCorrelation.json") -Object $volCorr -Depth 10

# Optional handle search
$handleOut = $null
if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
  $handleOut = Join-Path $bundle "HandleSearch.txt"
  if ($handleExe) {
    Run-HandleSearch -HandleExe $handleExe -TargetPath $TargetPath -OutFile $handleOut
  } else {
    Write-TextFile -Path $handleOut -Lines @(
      ("TargetPath: {0}" -f $TargetPath),
      "handle.exe not found. Place handle.exe in C:\Temp\Process2Thread to enable lock-owner discovery."
    )
  }
}

# Optional Procmon
$procmonPml = $null
if ($CaptureProcmon) {
  if ($procmonExe) {
    $procmonPml = Run-ProcmonCapture -ProcmonExe $procmonExe -OutFolder $bundle -Seconds $ProcmonSeconds
  } else {
    Write-TextFile -Path (Join-Path $bundle "ProcmonTrace.txt") -Lines @(
      "Procmon capture requested but procmon.exe not found.",
      "Place procmon.exe in C:\Temp\Process2Thread and rerun with -CaptureProcmon."
    )
  }
}

# Findings (simple, readable heuristics)
$flags = New-Object System.Collections.Generic.List[string]
if (-not $isAdmin) { $flags.Add("Not running elevated: fltmc visibility may be incomplete. Re-run as Administrator for full minifilter enumeration.") }
if ($targetCtx.PathType -eq "UNC") { $flags.Add("Target is UNC path: likely SMB/VPN/network dependency.") }
if (@($events | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 }).Count -gt 0) { $flags.Add("Storage timeouts present (Event 129/153): investigate storage stack and filter/driver interactions.") }
if (@($events | Where-Object { $_.Id -eq 107 -or $_.Id -eq 137 }).Count -gt 0) { $flags.Add("Power/resume indicators present (Event 107/137): possible resume/hibernate correlation.") }
if ($volCorr.FiltersOnVolume -and $volCorr.FiltersOnVolume.Count -gt 0 -and $targetCtx.PathType -eq "Local") {
  $top = ($volCorr.FiltersOnVolume | Select-Object -First 5 | ForEach-Object { "$($_.FilterName) (Alt $($_.Altitude))" }) -join ", "
  $flags.Add(("Filters attached to {0}: {1}" -f $volCorr.CorrelatedVolume, $top))
}
if ($flags.Count -eq 0) { $flags.Add("No dominant signal found; use Procmon/ETW capture during repro for deeper root cause.") }

# Human + vendor reports
Write-HumanSummary -Path (Join-Path $bundle "Summary_Human.txt") -Sys $sys -TargetCtx $targetCtx -VolCorr $volCorr `
  -Events $events -Flags $flags.ToArray() -IsAdmin $isAdmin -CaseId $CaseId

Write-VendorReport -MdPath (Join-Path $bundle "VendorReport.md") -TxtPath (Join-Path $bundle "VendorReport.txt") `
  -Sys $sys -TargetCtx $targetCtx -VolCorr $volCorr -Filters $filters -Instances $instances -Events $events `
  -Flags $flags.ToArray() -IsAdmin $isAdmin -CaseId $CaseId -HandleSearchPath $handleOut -ProcmonPath $procmonPml

# Zip bundle
$zip = $bundle + ".zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $bundle "*") -DestinationPath $zip -Force

Write-Output "Bundle created: $zip"
Write-Output "Key findings:"
$flags | ForEach-Object { Write-Output (" - " + $_) }

exit 0