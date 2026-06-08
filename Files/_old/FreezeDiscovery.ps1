<#
.SYNOPSIS
  FreezeDiscovery - PS 5.1-safe evidence collector for file/app/system freezes.

.DESCRIPTION
  Local-first paths:
    ToolRoot:   C:\Temp\Process2Thread   (optional handle.exe/procmon.exe)
    OutputRoot: C:\Temp\Process2Thread\FreezeDiscovery

  Produces a bundle folder + zip with:
    - SystemInfo.json
    - TopProcesses.csv
    - LogicalDisks.csv
    - Network.json
    - GlobalProtect.json
    - fltmc_filters_raw.txt, fltmc_instances_raw.txt
    - MiniFilters.json, MiniFilterInstances.json
    - TargetContext.json
    - VolumeCorrelation.json
    - SystemEvents_48h.csv (configurable lookback)
    - powercfg_lastwake.txt
    - Optional HandleSearch.txt
    - Optional ProcmonTrace.pml
    - Summary_Human.txt
    - VendorReport.md / VendorReport.txt
    - FreezeDiscovery_Errors.txt

.PARAMETER TargetPath
  Optional file/folder path suspected to be locked/frozen (local or UNC).

.PARAMETER CaseId
  Optional ticket/case ID embedded into reports.

.PARAMETER CaptureProcmon
  If set, capture Procmon trace (requires procmon.exe).

.PARAMETER ProcmonSeconds
  Procmon capture duration (5..600), default 30.

.PARAMETER LookbackHours
  Event log lookback window in hours, default 48.

.PARAMETER ToolRoot
  Location for handle.exe/procmon.exe, default C:\Temp\Process2Thread.

.PARAMETER OutputRoot
  Output root for bundles, default C:\Temp\Process2Thread\FreezeDiscovery.

.PARAMETER RequireAdmin
  If set, script stops if not running elevated (useful for lab runs). Default: best-effort.
#>

[CmdletBinding()]
param(
  [string]$TargetPath,
  [string]$CaseId,
  [switch]$CaptureProcmon,
  [ValidateRange(5,600)]
  [int]$ProcmonSeconds = 30,
  [ValidateRange(1,720)]
  [int]$LookbackHours = 48,
  [string]$ToolRoot   = "C:\Temp\Process2Thread",
  [string]$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery",
  [switch]$RequireAdmin
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# -----------------------------
# StrictMode-safe main variables
# -----------------------------
$bundle      = $null
$errFile     = $null
$isAdmin     = $false
$sys         = $null
$net         = $null
$gp          = $null
$rawF        = @()
$rawI        = @()
$filters     = @()
$instances   = @()
$events      = @()
$targetCtx   = $null
$volCorr     = $null
$flags       = @()
$handleExe   = $null
$procmonExe  = $null
$handleOut   = $null
$procmonPml  = $null

# -----------------------------
# Utility helpers
# -----------------------------
function Ensure-Folder {
  param([Parameter(Mandatory=$true)][string]$Path)
  if (-not (Test-Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function New-BundleFolder {
  param([Parameter(Mandatory=$true)][string]$Root)
  Ensure-Folder -Path $Root
  $stamp  = (Get-Date).ToString("yyyyMMdd_HHmmss")
  $folder = Join-Path $Root ("Bundle_{0}" -f $stamp)
  Ensure-Folder -Path $folder
  return $folder
}

function Test-IsAdmin {
  try {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    return $false
  }
}

function Write-Err {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string]$Message
  )
  $ts = (Get-Date).ToString("o")
  ("[{0}] {1}" -f $ts, $Message) | Out-File -FilePath $Path -Encoding UTF8 -Append -Force
}

function Find-Tool {
  param(
    [Parameter(Mandatory=$true)][string]$FileName,
    [Parameter(Mandatory=$true)][string]$ToolRoot
  )
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
    [int]$Depth = 10
  )
  $Object | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Write-TextFile {
  param(
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][string[]]$Lines
  )
  # Blank lines allowed.
  $Lines | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Get-TextOrDefault {
  param(
    [Parameter(Mandatory=$true)]$Value,
    [Parameter(Mandatory=$true)][string]$Default
  )
  if ($null -eq $Value) { return $Default }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s
}

function Normalize-VolString {
  param([string]$v)
  if ([string]::IsNullOrWhiteSpace($v)) { return $null }
  $s = $v.Trim()
  if ($s.EndsWith("\")) { $s = $s.TrimEnd("\") }
  return $s
}

function AltToNumber {
  param([string]$alt)
  try { return [double]$alt } catch { return -1 }
}

# Best-practice wrapper: return values, don't rely on scope side effects.
function Try-Get {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][scriptblock]$Script,
    [Parameter(Mandatory=$true)][string]$ErrFile
  )
  try {
    return & $Script
  } catch {
    Write-Err -Path $ErrFile -Message ("[{0}] {1}" -f $Name, $_.Exception.Message)
    return $null
  }
}

function Try-Do {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][scriptblock]$Script,
    [Parameter(Mandatory=$true)][string]$ErrFile
  )
  try {
    & $Script | Out-Null
    return $true
  } catch {
    Write-Err -Path $ErrFile -Message ("[{0}] {1}" -f $Name, $_.Exception.Message)
    return $false
  }
}

# -----------------------------
# Collectors
# -----------------------------
function Get-SystemInfo {
  $os = Get-CimInstance Win32_OperatingSystem
  $bios = Get-CimInstance Win32_BIOS
  [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    TimeLocal    = (Get-Date).ToString("o")
    OS           = $os   | Select-Object Caption, Version, BuildNumber
    BIOS         = $bios | Select-Object Manufacturer, SMBIOSBIOSVersion, ReleaseDate
  }
}

function Get-ProcessSnapshotTop {
  Get-Process |
    Select-Object Name, Id,
      @{Name="CPUSeconds";Expression={ if ($null -eq $_.CPU) { 0 } else { [double]$_.CPU } }},
      @{Name="WorkingSetMB";Expression={ [math]::Round($_.WorkingSet64 / 1MB, 1) }},
      @{Name="Handles";Expression={ $_.Handles }},
      @{Name="Threads";Expression={ $_.Threads.Count }},
      Responding |
    Sort-Object -Property CPUSeconds -Descending |
    Select-Object -First 30
}

function Get-LogicalDisks {
  Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID, DriveType, Size, FreeSpace
}

function Get-NetworkSnapshot {
  $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
  $routes   = Get-NetRoute   -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric

  $dns = $null
  try { $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue } catch { }

  $smb = $null
  try { $smb = Get-SmbConnection -ErrorAction SilentlyContinue } catch { }

  [pscustomobject]@{
    UpAdapters     = $adapters | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
    DefaultRoutes  = $routes | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } | Select-Object InterfaceAlias, NextHop, RouteMetric
    RouteSample    = $routes | Select-Object -First 80 InterfaceAlias, DestinationPrefix, NextHop, RouteMetric
    DnsServers     = $dns | Select-Object InterfaceAlias, ServerAddresses
    SmbConnections = $smb | Select-Object ServerName, ShareName, UserName, Dialect, NumOpens, EncryptData
  }
}

function Get-GlobalProtectSnapshot {
  $svc = @()
  foreach ($name in @("PanGPS","PanGPA")) {
    try { $svc += Get-Service -Name $name -ErrorAction Stop } catch { }
  }

  $adapters = @()
  try {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceDescription -match "PANGP|GlobalProtect|PAN" -or $_.Name -match "PANGP|GlobalProtect|PAN" }
  } catch { }

  $routes = $null
  try { $routes = Get-NetRoute -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric } catch { }

  $dns = $null
  try { $dns = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue } catch { }

  $smb = $null
  try { $smb = Get-SmbConnection -ErrorAction SilentlyContinue } catch { }

  [pscustomobject]@{
    Services       = $svc | Select-Object Name, Status, StartType
    Adapters       = $adapters | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress
    DefaultRoutes  = $routes | Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } | Select-Object InterfaceAlias, NextHop, RouteMetric
    RouteSample    = $routes | Select-Object -First 80 InterfaceAlias, DestinationPrefix, NextHop, RouteMetric
    DnsServers     = $dns | Select-Object InterfaceAlias, ServerAddresses
    SmbConnections = $smb | Select-Object ServerName, ShareName, UserName, Dialect, NumOpens, EncryptData
    Notes          = @("GlobalProtect snapshot captured (PanGPS/PanGPA, adapters, routes, DNS, SMB).")
  }
}

function Get-RelevantSystemEvents {
  param([Parameter(Mandatory=$true)][int]$LookbackHours)

  $since = (Get-Date).AddHours(-1 * $LookbackHours)
  $ids = 41,107,137,129,153
  Get-WinEvent -FilterHashtable @{ LogName="System"; StartTime=$since; Id=$ids } -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
}

# -----------------------------
# fltmc capture + parsing
# -----------------------------
function Get-FltmcRaw {
  param([Parameter(Mandatory=$true)][ValidateSet("filters","instances")][string]$Mode)
  return ,(& fltmc $Mode 2>&1)
}

function Parse-FltmcFilters {
  param([string[]]$Lines)

  if (-not $Lines -or $Lines.Count -lt 4) { return @() }
  $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

  $out = @()
  foreach ($r in $rows) {
    $p = ($r -split "\s{2,}").Trim()
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
    $p = ($r -split "\s{2,}").Trim()
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

# -----------------------------
# Target context + volume correlation
# -----------------------------
function Resolve-TargetContext {
  param([string]$TargetPath)

  $ctx = [ordered]@{
    TargetPath = $TargetPath
    PathType   = "None"
    LocalDrive = $null
    VolumeGuid = $null
    UncServer  = $null
    UncShare   = $null
    Notes      = @()
  }

  if ([string]::IsNullOrWhiteSpace($TargetPath)) {
    $ctx.Notes += "No TargetPath provided."
    return [pscustomobject]$ctx
  }

  if ($TargetPath -match '^[\\]{2}([^\\]+)\\([^\\]+)') {
    $ctx.PathType  = "UNC"
    $ctx.UncServer = $matches[1]
    $ctx.UncShare  = $matches[2]
    $ctx.Notes += "UNC target: correlate using GlobalProtect + SMB evidence (no local volume mapping)."
    return [pscustomobject]$ctx
  }

  $qual = $null
  try { $qual = Split-Path -Path $TargetPath -Qualifier } catch { }

  if ($qual -and $qual -match "^[A-Za-z]:$") {
    $drive = $qual.ToUpper()
    $ctx.PathType   = "Local"
    $ctx.LocalDrive = $drive

    # Best-effort GUID mapping via Win32_Volume DeviceID (\\?\Volume{GUID}\)
    try {
      $vol = Get-CimInstance Win32_Volume -Filter ("DriveLetter='{0}'" -f $drive) -ErrorAction Stop
      if ($vol -and $vol.DeviceID) { $ctx.VolumeGuid = [string]$vol.DeviceID }
    } catch {
      $ctx.Notes += "Win32_Volume GUID mapping not available (best-effort only)."
    }

    $ctx.Notes += "Local target: correlate fltmc instances by drive letter and Volume GUID; also include device-path instances for same filters."
    return [pscustomobject]$ctx
  }

  $ctx.PathType = "Unknown"
  $ctx.Notes += "Target path is neither UNC nor drive-qualified."
  return [pscustomobject]$ctx
}

function Build-VolumeCorrelation {
  param(
    [Parameter(Mandatory=$true)][pscustomobject]$TargetCtx,
    [object[]]$Filters,
    [object[]]$Instances
  )

  $vc = [ordered]@{
    CorrelatedVolume        = $null
    MatchedInstances        = @()
    FilterNamesOnTarget     = @()
    FiltersOnTarget         = @()
    DevicePathInstancesAlso = @()
    Notes                  = @()
  }

  if ($TargetCtx.PathType -ne "Local") {
    $vc.CorrelatedVolume = $TargetCtx.PathType
    $vc.Notes += "Not a local path; local minifilter correlation not performed."
    return [pscustomobject]$vc
  }

  $driveNorm = Normalize-VolString $TargetCtx.LocalDrive
  $guidNorm  = $null
  if ($TargetCtx.VolumeGuid) { $guidNorm = Normalize-VolString $TargetCtx.VolumeGuid }

  $vc.CorrelatedVolume = $driveNorm

  # Match instances by drive-letter and GUID representation.
  $matched = @()
  foreach ($inst in @($Instances)) {
    $vnorm = Normalize-VolString $inst.Volume
    if ($null -eq $vnorm) { continue }

    if ($vnorm -eq $driveNorm) { $matched += $inst; continue }

    if ($guidNorm) {
      if ($vnorm -eq $guidNorm) { $matched += $inst; continue }
      if ($vnorm -eq ($guidNorm.TrimEnd("\"))) { $matched += $inst; continue }
    }
  }

  $vc.MatchedInstances = $matched

  $names = @()
  if ($matched.Count -gt 0) {
    $names = $matched | Select-Object -ExpandProperty FilterName -ErrorAction SilentlyContinue | Sort-Object -Unique
  }
  $vc.FilterNamesOnTarget = $names

  $flt = @()
  if ($names.Count -gt 0) {
    $flt = @($Filters | Where-Object { $names -contains $_.FilterName })
  }
  $vc.FiltersOnTarget = $flt | Sort-Object -Property @{Expression={ AltToNumber $_.Altitude }; Descending=$true}

  # Also capture device-path instances for those same filter names (mixed-format endpoints).
  if ($names.Count -gt 0) {
    $vc.DevicePathInstancesAlso = @(
      $Instances | Where-Object { ($names -contains $_.FilterName) -and ($_.Volume -like "\Device\HarddiskVolume*") }
    )
    if ($vc.DevicePathInstancesAlso.Count -gt 0) {
      $vc.Notes += "Device-path instances present for filters on target (mixed fltmc formats observed)."
    }
  }

  if ($matched.Count -eq 0) {
    $vc.Notes += "No instances matched by drive-letter/GUID. Review fltmc_instances_raw.txt; system may report only device paths."
  }

  return [pscustomobject]$vc
}

# -----------------------------
# Optional tools: handle/procmon
# -----------------------------
function Run-HandleSearch {
  param(
    [Parameter(Mandatory=$true)][string]$HandleExe,
    [Parameter(Mandatory=$true)][string]$TargetPath,
    [Parameter(Mandatory=$true)][string]$OutFile
  )
  & $HandleExe -accepteula $TargetPath 2>&1 | Out-File -FilePath $OutFile -Encoding UTF8 -Force
}

function Run-ProcmonCapture {
  param(
    [Parameter(Mandatory=$true)][string]$ProcmonExe,
    [Parameter(Mandatory=$true)][string]$OutFolder,
    [Parameter(Mandatory=$true)][int]$Seconds
  )
  $pml = Join-Path $OutFolder "ProcmonTrace.pml"
  $argsStart = "/AcceptEula /Quiet /Minimized /BackingFile `"$pml`""
  Start-Process -FilePath $ProcmonExe -ArgumentList $argsStart -WindowStyle Hidden | Out-Null
  Start-Sleep -Seconds $Seconds
  Start-Process -FilePath $ProcmonExe -ArgumentList "/Terminate" -WindowStyle Hidden -Wait | Out-Null
  return $pml
}

# -----------------------------
# Findings + Reports
# -----------------------------
function Build-Findings {
  param(
    [pscustomobject]$TargetCtx,
    [pscustomobject]$VolCorr,
    [object[]]$Events,
    [bool]$IsAdmin
  )

  $list = New-Object System.Collections.Generic.List[string]

  if (-not $IsAdmin) {
    $list.Add("Not running elevated: fltmc visibility may be incomplete. Re-run as Administrator for best minifilter results.")
  }

  if ($TargetCtx.PathType -eq "UNC") {
    $list.Add("Target is UNC path: likely SMB/VPN dependency (GlobalProtect).")
  }

  $storCount = @($Events | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 }).Count
  if ($storCount -gt 0) {
    $list.Add("Storage timeout/reset indicators present (Event 129/153). Investigate storage stack and filter/driver interactions.")
  }

  $pwrCount = @($Events | Where-Object { $_.Id -eq 107 -or $_.Id -eq 137 }).Count
  if ($pwrCount -gt 0) {
    $list.Add("Power/resume indicators present (Event 107/137). Possible sleep/hibernate correlation.")
  }

  if ($TargetCtx.PathType -eq "Local" -and $VolCorr.FiltersOnTarget -and $VolCorr.FiltersOnTarget.Count -gt 0) {
    $top = $VolCorr.FiltersOnTarget | Select-Object -First 5 | ForEach-Object { "$($_.FilterName) (Alt $($_.Altitude))" }
    $list.Add(("Filters attached to target volume {0}: {1}" -f $VolCorr.CorrelatedVolume, ($top -join ", ")))
  }

  if ($list.Count -eq 0) {
    $list.Add("No dominant signal detected. Capture short Procmon during repro and/or ETW tracing for deeper analysis.")
  }

  return $list.ToArray()
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

  # Defensive: Sys could be null if SystemInfo collection failed.
  $cn = "<unknown>"
  $un = "<unknown>"
  if ($Sys) {
    $cn = Get-TextOrDefault $Sys.ComputerName "<unknown>"
    $un = Get-TextOrDefault $Sys.UserName "<unknown>"
  }

  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("FreezeDiscovery - Human Summary")
  $lines.Add("----------------------------------------")
  if ($CaseId) { $lines.Add("Case/Ticket: " + $CaseId) }
  $lines.Add("Generated: " + (Get-Date).ToString("o"))
  $lines.Add("Computer: " + $cn + "   User: " + $un)
  $lines.Add("Admin context: " + $IsAdmin)
  $lines.Add("")

  $lines.Add("Target:")
  $lines.Add("  Path: " + (Get-TextOrDefault $TargetCtx.TargetPath "<none>"))
  $lines.Add("  Type: " + (Get-TextOrDefault $TargetCtx.PathType "<unknown>"))

  if ($TargetCtx.PathType -eq "Local") {
    $lines.Add("  Drive: " + (Get-TextOrDefault $TargetCtx.LocalDrive "<unknown>"))
    if ($TargetCtx.VolumeGuid) { $lines.Add("  Volume GUID: " + $TargetCtx.VolumeGuid) }
  } elseif ($TargetCtx.PathType -eq "UNC") {
    $lines.Add(("  UNC: \\{0}\{1}" -f (Get-TextOrDefault $TargetCtx.UncServer "<unknown>"), (Get-TextOrDefault $TargetCtx.UncShare "<unknown>")))
  }

  $lines.Add("")
  $lines.Add("Key Findings:")
  foreach ($f in $Flags) { $lines.Add("  - " + $f) }
  $lines.Add("")

  if ($TargetCtx.PathType -eq "Local") {
    $lines.Add("Volume Correlation:")
    $lines.Add("  Correlated volume: " + (Get-TextOrDefault $VolCorr.CorrelatedVolume "<unknown>"))
    $lines.Add("  Matched instances: " + @($VolCorr.MatchedInstances).Count)
    $lines.Add("  Filters on target: " + @($VolCorr.FiltersOnTarget).Count)
    if ($VolCorr.DevicePathInstancesAlso -and $VolCorr.DevicePathInstancesAlso.Count -gt 0) {
      $lines.Add("  Device-path instances also present: " + @($VolCorr.DevicePathInstancesAlso).Count)
    }

    if ($VolCorr.FiltersOnTarget -and $VolCorr.FiltersOnTarget.Count -gt 0) {
      $lines.Add("  Top filters (highest altitude first):")
      foreach ($flt in ($VolCorr.FiltersOnTarget | Select-Object -First 10)) {
        $lines.Add(("    - {0} (Altitude {1})" -f $flt.FilterName, $flt.Altitude))
      }
    }

    if ($VolCorr.Notes -and $VolCorr.Notes.Count -gt 0) {
      $lines.Add("")
      $lines.Add("Correlation Notes:")
      foreach ($n in $VolCorr.Notes) { $lines.Add("  - " + $n) }
    }
    $lines.Add("")
  }

  $stor = @($Events | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 } | Select-Object -First 5)
  if ($stor.Count -gt 0) {
    $lines.Add("Storage Timeout Indicators (sample):")
    foreach ($e in $stor) {
      $lines.Add(("  - {0} | ID {1} | {2}" -f $e.TimeCreated, $e.Id, $e.ProviderName))
    }
    $lines.Add("")
  }

  $lines.Add("Safe Next Steps:")
  $lines.Add("  1) If UNC/VPN suspected: reproduce once with VPN disconnected (if policy allows) and capture a second bundle.")
  $lines.Add("  2) If Event 129/153 present: escalate to Endpoint/Platform (storage stack/driver/filter).")
  $lines.Add("  3) If file-specific: include HandleSearch.txt (handle.exe) and consider short Procmon capture during reproduction.")
  $lines.Add("")

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

  $cn = "<unknown>"
  $un = "<unknown>"
  $osLine = "<unknown>"
  $biosLine = "<unknown>"
  if ($Sys) {
    $cn = Get-TextOrDefault $Sys.ComputerName "<unknown>"
    $un = Get-TextOrDefault $Sys.UserName "<unknown>"
    if ($Sys.OS) { $osLine = ("{0} {1} (Build {2})" -f $Sys.OS.Caption, $Sys.OS.Version, $Sys.OS.BuildNumber) }
    if ($Sys.BIOS) { $biosLine = ("{0} {1}" -f $Sys.BIOS.Manufacturer, $Sys.BIOS.SMBIOSBIOSVersion) }
  }

  $md = New-Object System.Collections.Generic.List[string]
  $md.Add("# Vendor Diagnostic Report - FreezeDiscovery")
  $md.Add("")
  if ($CaseId) { $md.Add(("**Case/Ticket:** {0}  " -f $CaseId)) }
  $md.Add(("**Generated:** {0}  " -f (Get-Date).ToString("o")))
  $md.Add(("**Admin context:** {0}  " -f $IsAdmin))
  $md.Add("")

  $md.Add("## 1. Executive Summary")
  $md.Add("- This report captures system context, minifilter presence, and GlobalProtect/SMB indicators, plus event-log signals.")
  $md.Add("- Key findings:")
  foreach ($f in $Flags) { $md.Add(("  - {0}" -f $f)) }
  $md.Add("")

  $md.Add("## 2. Environment")
  $md.Add(("- **ComputerName:** {0}" -f $cn))
  $md.Add(("- **UserName:** {0}" -f $un))
  $md.Add(("- **OS:** {0}" -f $osLine))
  $md.Add(("- **BIOS:** {0}" -f $biosLine))
  $md.Add("")

  $md.Add("## 3. Target Context")
  $md.Add(("- **TargetPath:** {0}" -f (Get-TextOrDefault $TargetCtx.TargetPath "<none>")))
  $md.Add(("- **PathType:** {0}" -f (Get-TextOrDefault $TargetCtx.PathType "<unknown>")))
  if ($TargetCtx.PathType -eq "Local") {
    $md.Add(("- **Local drive:** {0}" -f $TargetCtx.LocalDrive))
    if ($TargetCtx.VolumeGuid) { $md.Add(("- **Volume GUID:** {0}" -f $TargetCtx.VolumeGuid)) }
  } elseif ($TargetCtx.PathType -eq "UNC") {
    $md.Add(("- **UNC server/share:** \\{0}\{1}" -f $TargetCtx.UncServer, $TargetCtx.UncShare))
  }
  $md.Add("")

  $md.Add("## 4. Minifilter Evidence")
  $md.Add(("- Loaded minifilters (fltmc filters): {0}" -f (@($Filters).Count)))
  $md.Add(("- Minifilter instances (fltmc instances): {0}" -f (@($Instances).Count)))
  $md.Add("")

  if ($TargetCtx.PathType -eq "Local") {
    $md.Add(("### 4.1 Correlation to target volume {0}" -f $VolCorr.CorrelatedVolume))
    $md.Add(("- Matched instances on target: {0}" -f (@($VolCorr.MatchedInstances).Count)))
    $md.Add(("- Filters on target: {0}" -f (@($VolCorr.FiltersOnTarget).Count)))
    if ($VolCorr.DevicePathInstancesAlso -and $VolCorr.DevicePathInstancesAlso.Count -gt 0) {
      $md.Add(("- Device-path instances also present: {0}" -f (@($VolCorr.DevicePathInstancesAlso).Count)))
    }
    $md.Add("")

    if ($VolCorr.FiltersOnTarget -and $VolCorr.FiltersOnTarget.Count -gt 0) {
      $md.Add("| FilterName | Altitude |")
      $md.Add("|---|---:|")
      foreach ($flt in $VolCorr.FiltersOnTarget) {
        $md.Add(("| {0} | {1} |" -f $flt.FilterName, $flt.Altitude))
      }
    } else {
      $md.Add("_No filters correlated by drive-letter/GUID. Review fltmc_instances_raw.txt for device-path-only output._")
    }
    $md.Add("")
  } else {
    $md.Add("### 4.1 UNC note")
    $md.Add("_UNC targets do not map to local volumes via fltmc instances. Focus on GlobalProtect + SMB evidence._")
    $md.Add("")
  }

  $md.Add("## 5. Event Log Correlation (last window)")
  $md.Add(("LookbackHours: {0}" -f $LookbackHours))
  $md.Add("Relevant IDs: 41, 107, 137, 129, 153")
  $md.Add("")
  $stor = @($Events | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 } | Select-Object -First 20)
  if ($stor.Count -gt 0) {
    foreach ($e in $stor) {
      $md.Add(("- {0} | ID {1} | {2}" -f $e.TimeCreated, $e.Id, $e.ProviderName))
    }
  } else {
    $md.Add("_No 129/153 events found in capture window._")
  }
  $md.Add("")

  $md.Add("## 6. File Lock Owner Evidence")
  if ($HandleSearchPath -and (Test-Path $HandleSearchPath)) {
    $md.Add("- HandleSearch.txt included (Sysinternals handle.exe output).")
  } else {
    $md.Add("- HandleSearch.txt not present (TargetPath not provided or handle.exe unavailable).")
  }
  $md.Add("")

  $md.Add("## 7. Procmon Evidence")
  if ($ProcmonPath -and (Test-Path $ProcmonPath)) {
    $md.Add("- Procmon trace included: ProcmonTrace.pml")
    $md.Add("- Vendor should filter for the target path and inspect long-duration I/O, retries, or stalled operations.")
  } else {
    $md.Add("- Procmon trace not captured in this run (optional).")
  }
  $md.Add("")

  $md.Add("## 8. Attachments Included")
  $md.Add("- SystemInfo.json")
  $md.Add("- TopProcesses.csv")
  $md.Add("- LogicalDisks.csv")
  $md.Add("- Network.json")
  $md.Add("- GlobalProtect.json")
  $md.Add("- MiniFilters.json / MiniFilterInstances.json")
  $md.Add("- fltmc_filters_raw.txt / fltmc_instances_raw.txt")
  $md.Add("- SystemEvents_48h.csv")
  $md.Add("- powercfg_lastwake.txt")
  $md.Add("- Summary_Human.txt")
  $md.Add("- VendorReport.md / VendorReport.txt")
  $md.Add("")

  $mdText = ($md -join "`r`n")
  $mdText | Out-File -FilePath $MdPath -Encoding UTF8 -Force

  $txt = $mdText -replace "\*\*", "" -replace "_", "" -replace "\|", " "
  $txt | Out-File -FilePath $TxtPath -Encoding UTF8 -Force
}

# -----------------------------
# MAIN
# -----------------------------
$bundle  = New-BundleFolder -Root $OutputRoot
$errFile = Join-Path $bundle "FreezeDiscovery_Errors.txt"
$isAdmin = Test-IsAdmin

if ($RequireAdmin -and -not $isAdmin) {
  Write-Err -Path $errFile -Message "RequireAdmin set but script is not elevated. Exiting."
  throw "RequireAdmin set but script is not elevated."
}

# Collect system info
$sys = Try-Get -Name "SystemInfo" -ErrFile $errFile -Script { Get-SystemInfo }
if ($sys) { Write-Json -Path (Join-Path $bundle "SystemInfo.json") -Object $sys -Depth 6 }

# Processes
Try-Do -Name "TopProcesses" -ErrFile $errFile -Script {
  Get-ProcessSnapshotTop | Export-Csv (Join-Path $bundle "TopProcesses.csv") -NoTypeInformation -Encoding UTF8 -Force
} | Out-Null

# Disks
Try-Do -Name "LogicalDisks" -ErrFile $errFile -Script {
  Get-LogicalDisks | Export-Csv (Join-Path $bundle "LogicalDisks.csv") -NoTypeInformation -Encoding UTF8 -Force
} | Out-Null

# Network
$net = Try-Get -Name "Network" -ErrFile $errFile -Script { Get-NetworkSnapshot }
if ($net) { Write-Json -Path (Join-Path $bundle "Network.json") -Object $net -Depth 12 }

# GlobalProtect
$gp = Try-Get -Name "GlobalProtect" -ErrFile $errFile -Script { Get-GlobalProtectSnapshot }
if ($gp) { Write-Json -Path (Join-Path $bundle "GlobalProtect.json") -Object $gp -Depth 12 }

# fltmc raw + parsed
$rawF = Try-Get -Name "fltmc_filters_raw" -ErrFile $errFile -Script { Get-FltmcRaw -Mode "filters" }
if ($rawF) { $rawF | Out-File (Join-Path $bundle "fltmc_filters_raw.txt") -Encoding UTF8 -Force }
$filters = @()
if ($rawF) { $filters = Parse-FltmcFilters -Lines $rawF }
Write-Json -Path (Join-Path $bundle "MiniFilters.json") -Object $filters -Depth 6

$rawI = Try-Get -Name "fltmc_instances_raw" -ErrFile $errFile -Script { Get-FltmcRaw -Mode "instances" }
if ($rawI) { $rawI | Out-File (Join-Path $bundle "fltmc_instances_raw.txt") -Encoding UTF8 -Force }
$instances = @()
if ($rawI) { $instances = Parse-FltmcInstances -Lines $rawI }
Write-Json -Path (Join-Path $bundle "MiniFilterInstances.json") -Object $instances -Depth 10

# Events
$events = Try-Get -Name "SystemEvents" -ErrFile $errFile -Script { Get-RelevantSystemEvents -LookbackHours $LookbackHours }
if ($events) {
  $events | Export-Csv (Join-Path $bundle ("SystemEvents_{0}h.csv" -f $LookbackHours)) -NoTypeInformation -Encoding UTF8 -Force
} else {
  $events = @()
}

# powercfg
Try-Do -Name "powercfg_lastwake" -ErrFile $errFile -Script {
  & powercfg /lastwake 2>&1 | Out-File (Join-Path $bundle "powercfg_lastwake.txt") -Encoding UTF8 -Force
} | Out-Null

# Target context + correlation
$targetCtx = Resolve-TargetContext -TargetPath $TargetPath
Write-Json -Path (Join-Path $bundle "TargetContext.json") -Object $targetCtx -Depth 10

$volCorr = Build-VolumeCorrelation -TargetCtx $targetCtx -Filters $filters -Instances $instances
Write-Json -Path (Join-Path $bundle "VolumeCorrelation.json") -Object $volCorr -Depth 12

# Tools
$handleExe  = Find-Tool -FileName "handle.exe"  -ToolRoot $ToolRoot
$procmonExe = Find-Tool -FileName "procmon.exe" -ToolRoot $ToolRoot

# Optional handle search
if (-not [string]::IsNullOrWhiteSpace($TargetPath)) {
  $handleOut = Join-Path $bundle "HandleSearch.txt"
  if ($handleExe) {
    Try-Do -Name "handle_search" -ErrFile $errFile -Script {
      Run-HandleSearch -HandleExe $handleExe -TargetPath $TargetPath -OutFile $handleOut
    } | Out-Null
  } else {
    Write-TextFile -Path $handleOut -Lines @(
      ("TargetPath: {0}" -f $TargetPath),
      "handle.exe not found. Place handle.exe in C:\Temp\Process2Thread to enable lock-owner discovery."
    )
  }
}

# Optional Procmon
if ($CaptureProcmon) {
  if ($procmonExe) {
    Try-Do -Name "procmon_capture" -ErrFile $errFile -Script {
      $procmonPml = Run-ProcmonCapture -ProcmonExe $procmonExe -OutFolder $bundle -Seconds $ProcmonSeconds
    } | Out-Null
  } else {
    Write-TextFile -Path (Join-Path $bundle "ProcmonTrace.txt") -Lines @(
      "Procmon capture requested but procmon.exe not found.",
      "Place procmon.exe in C:\Temp\Process2Thread and rerun with -CaptureProcmon."
    )
  }
}

# Findings + reports
$flags = Build-Findings -TargetCtx $targetCtx -VolCorr $volCorr -Events $events -IsAdmin $isAdmin

Write-HumanSummary -Path (Join-Path $bundle "Summary_Human.txt") -Sys $sys -TargetCtx $targetCtx -VolCorr $volCorr `
  -Events $events -Flags $flags -IsAdmin $isAdmin -CaseId $CaseId

Write-VendorReport -MdPath (Join-Path $bundle "VendorReport.md") -TxtPath (Join-Path $bundle "VendorReport.txt") `
  -Sys $sys -TargetCtx $targetCtx -VolCorr $volCorr -Filters $filters -Instances $instances -Events $events `
  -Flags $flags -IsAdmin $isAdmin -CaseId $CaseId -HandleSearchPath $handleOut -ProcmonPath $procmonPml

# Zip bundle
$zip = $bundle + ".zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path (Join-Path $bundle "*") -DestinationPath $zip -Force

Write-Output ("Bundle created: {0}" -f $zip)
Write-Output "Key findings:"
foreach ($f in $flags) { Write-Output (" - " + $f) }

exit 0
