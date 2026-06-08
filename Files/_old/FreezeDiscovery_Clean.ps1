[CmdletBinding()]
param(
    [string]$TargetPath,
    [string]$CaseId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# -------------------------
# Safe helpers (NO Lines / NO Object params)
# -------------------------
function Write-Text {
    param([string]$Path, [string[]]$Content)
    $safe = foreach ($l in $Content) {
        if ([string]::IsNullOrEmpty($l)) { " " } else { $l }
    }
    $safe | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Write-JsonSafe {
    param([string]$Path, $Value)
    if ($null -eq $Value) {
        @{ Notice="Value was null"; Time=(Get-Date).ToString("o") } |
            ConvertTo-Json | Out-File $Path -Encoding UTF8 -Force
        return
    }
    $Value | ConvertTo-Json -Depth 6 | Out-File $Path -Encoding UTF8 -Force
}

# =========================
# A2: Filters-on-target-volume summary helpers
# =========================

function Get-TargetDriveFromPath {
    param([string]$TargetPath)

    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $null }
    if ($TargetPath -like "\\*") { return $null }

    try {
        $q = Split-Path -Path $TargetPath -Qualifier
        if ($q -match '^[A-Za-z]:$') { return $q.ToUpper() }
    } catch { }

    return $null
}

function Convert-AltitudeToNumber {
    param([string]$Altitude)
    try { return [double]$Altitude } catch { return -1 }
}

function Build-FiltersOnVolumeSummary {
    param(
        [string]$TargetDrive,
        [object[]]$MiniFilters,
        [object[]]$MiniInstancesMapped
    )

    $instOn = @($MiniInstancesMapped | Where-Object { $_.CanonicalVolume -eq $TargetDrive })
    $perFilter = @()

    $names = $instOn | Select-Object -ExpandProperty FilterName -Unique

    foreach ($name in $names) {
        $instFor = @($instOn | Where-Object { $_.FilterName -eq $name })

        $maxAlt = -1
        foreach ($i in $instFor) {
            $n = Convert-AltitudeToNumber $i.Altitude
            if ($n -gt $maxAlt) { $maxAlt = $n }
        }

        $fltMeta = $MiniFilters | Where-Object { $_.FilterName -eq $name } | Select-Object -First 1

        $perFilter += [pscustomobject]@{
            FilterName           = $name
            MaxAltitude          = $maxAlt
            AttachedInstances    = $instFor.Count
            GlobalInstanceCount  = $fltMeta.Instances
        }
    }

    return ($perFilter | Sort-Object MaxAltitude -Descending)
}

function Write-FiltersOnTargetVolumeArtifacts {
    param(
        [string]$BundlePath,
        [string]$TargetPath,
        [object[]]$MiniFilters,
        [object[]]$MiniInstancesMapped
    )

    $drive = Get-TargetDriveFromPath $TargetPath

    if (-not $drive) {
        Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content @(
            "No local target drive detected."
            "TargetPath: $TargetPath"
            "UNC paths do not correlate to local minifilters."
        )
        return @()
    }

    $filters = Build-FiltersOnVolumeSummary `
        -TargetDrive $drive `
        -MiniFilters $MiniFilters `
        -MiniInstancesMapped $MiniInstancesMapped

    Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $filters

    $lines = @(
        "Filters affecting $drive"
        "------------------------"
    )

    foreach ($f in ($filters | Select-Object -First 10)) {
        $lines += ("- {0} (Altitude {1})" -f $f.FilterName, $f.MaxAltitude)
    }

    Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content $lines

    return ($lines | Select-Object -First 6)
}

# -------------------------
# Output setup
# -------------------------
$root = "C:\Temp\Process2Thread\FreezeDiscovery"
if (-not (Test-Path $root)) { New-Item $root -ItemType Directory | Out-Null }
$bundle = Join-Path $root ("Bundle_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item $bundle -ItemType Directory | Out-Null

# -------------------------
# System info (never crashes)
# -------------------------
$sys = $null
try {
    $sys = [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        UserName     = $env:USERNAME
        OS           = (Get-CimInstance Win32_OperatingSystem |
                        Select-Object Caption, Version, BuildNumber)
    }
} catch {}

Write-JsonSafe -Path (Join-Path $bundle "SystemInfo.json") -Value $sys

# -------------------------
# Target context
# -------------------------
$pathType = "None"
if ($TargetPath) {
    if ($TargetPath -like "\\*") { $pathType = "UNC" }
    elseif ($TargetPath -match "^[A-Za-z]:") { $pathType = "Local" }
}

$targetCtx = [pscustomobject]@{
    TargetPath = $TargetPath
    PathType   = $pathType
}

Write-JsonSafe -Path (Join-Path $bundle "TargetContext.json") -Value $targetCtx

# =========================
# FLTMC capture + parsing
# =========================
function Get-FltmcRaw {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("filters","instances")]
        [string]$Mode
    )
    # Capture stdout+stderr (vendor-defensible)
    $raw = & fltmc.exe $Mode 2>&1
    return ,$raw
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

# =========================
# FLTMC evidence
# =========================
try {
    $rawFilters   = Get-FltmcRaw -Mode "filters"
    $rawInstances = Get-FltmcRaw -Mode "instances"

    $rawFilters   | Out-File (Join-Path $bundle "fltmc_filters_raw.txt")   -Encoding UTF8 -Force
    $rawInstances | Out-File (Join-Path $bundle "fltmc_instances_raw.txt") -Encoding UTF8 -Force

    $miniFilters   = Parse-FltmcFilters   -Lines $rawFilters
    $miniInstances = Parse-FltmcInstances -Lines $rawInstances

# --- NEW: Build volume mapping and enrich instances ---
    $volumeMap = Get-VolumeMap
    Write-JsonSafe -Path (Join-Path $bundle "VolumeMap.json") -Value $volumeMap

    $miniInstancesMapped = Map-FltmcInstances -Instances $miniInstances -VolumeMap $volumeMap

    Write-JsonSafe -Path (Join-Path $bundle "MiniFilters.json") -Value $miniFilters

# --- CHANGE: Write the mapped instances instead of the raw parsed instances ---
    Write-JsonSafe -Path (Join-Path $bundle "MiniFilterInstances.json") -Value $miniInstancesMapped
}
catch {
    Write-Text -Path (Join-Path $bundle "MiniFilter_WARNING.txt") -Content @(
        "MiniFilter capture failed (best-effort collector)."
        ("Error: {0}" -f $_.Exception.Message)
        "Try running PowerShell ISE as Administrator and re-run."
    )
}

# A2: Build and write “filters on target volume” artifacts + get lines to inject into summaries
$FilterSummaryLines = Write-FiltersOnTargetVolumeArtifacts `
    -BundlePath $bundle `
    -TargetPath $TargetPath `
    -MiniFilters $miniFilters `
    -MiniInstancesMapped $miniInstancesMapped

function Parse-FltmcFilters {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -lt 4) { return @() }

    # fltmc output format:
    # Header line
    # Separator line
    # Data lines...
    $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_.Trim() -ne "" }

    $out = @()
    foreach ($r in $rows) {
        # Split on 2+ spaces (column aligned)
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

# =========================
# Volume mapping + normalization (PS 5.1-safe)
# =========================

function Get-VolumeMap {
    # Returns objects: DriveLetter, VolumeGuid, DevicePath (best-effort).
    $map = @()

    # A) DriveLetter <-> Volume GUID via Win32_Volume (usually works)
    try {
        $vols = Get-CimInstance Win32_Volume -ErrorAction Stop |
            Where-Object { $_.DriveLetter -match '^[A-Z]:$' }
    } catch {
        $vols = @()
    }

    foreach ($v in $vols) {
        $map += [pscustomobject]@{
            DriveLetter = $v.DriveLetter
            VolumeGuid  = $v.DeviceID   # often \\?\Volume{GUID}\
            DevicePath  = $null         # filled in below if possible
        }
    }

    # B) DriveLetter <-> DevicePath via QueryDosDevice (very reliable for \Device\HarddiskVolumeX)
    $sig = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DosDevice {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
  public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
"@
    try {
        if (-not ("DosDevice" -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction Stop }
    } catch {
        # If Add-Type fails, mapping still works partially (GUID-based).
    }

    foreach ($entry in $map) {
        try {
            $sb = New-Object System.Text.StringBuilder 1024
            $r = [DosDevice]::QueryDosDevice($entry.DriveLetter, $sb, $sb.Capacity)
            if ($r -gt 0) { $entry.DevicePath = $sb.ToString() }
        } catch { }
    }

    return $map
}

function Normalize-VolumeId {
    param([string]$Volume)

    if ([string]::IsNullOrWhiteSpace($Volume)) { return $null }

    $v = $Volume.Trim()

    # Strip trailing backslash
    if ($v.EndsWith("\")) { $v = $v.TrimEnd("\") }

    # Normalize drive letters
    if ($v -match '^[A-Za-z]:$') { return $v.ToUpper() }

    # Normalize \\?\Volume{GUID}\ to \\?\Volume{GUID}
    if ($v -match '^(\\\\\?\\Volume\{[0-9A-Fa-f\-]+\})') { return $matches[1] }

    # Normalize \??\Volume{GUID} to \\?\Volume{GUID}
    if ($v -match '^(\\\?\?\\Volume\{[0-9A-Fa-f\-]+\})') {
        # turn \??\Volume{GUID} into \\?\Volume{GUID}
        return ("\\?\{0}" -f $matches[1].Substring(4))
    }

    # Device-path volumes remain as-is
    if ($v -like '\Device\HarddiskVolume*') { return $v }

    # Fallback
    return $v
}

function Map-FltmcInstances {
    param(
        [Parameter(Mandatory=$true)][object[]]$Instances,
        [Parameter(Mandatory=$true)][object[]]$VolumeMap
    )

    # Lookups
    $devToDrive  = @{}
    $guidToDrive = @{}

    foreach ($m in $VolumeMap) {
        if ($m.DevicePath -and $m.DriveLetter) { $devToDrive[$m.DevicePath] = $m.DriveLetter }
        if ($m.VolumeGuid -and $m.DriveLetter) { $guidToDrive[(Normalize-VolumeId $m.VolumeGuid)] = $m.DriveLetter }
    }

    $out = @()

    foreach ($i in $Instances) {
        $raw  = $i.Volume
        $norm = Normalize-VolumeId $raw

        $mappedDrive = $null
        if ($norm -match '^[A-Z]:$') { $mappedDrive = $norm }
        elseif ($devToDrive.ContainsKey($norm)) { $mappedDrive = $devToDrive[$norm] }
        elseif ($guidToDrive.ContainsKey($norm)) { $mappedDrive = $guidToDrive[$norm] }

        # Canonical volume: prefer drive letter if known
        $canonical = $null
        if ($mappedDrive) { $canonical = $mappedDrive }
        elseif ($norm -like '\\?\Volume{*') { $canonical = $norm }
        elseif ($norm -like '\Device\HarddiskVolume*') { $canonical = $norm }
        else { $canonical = $norm }

        $out += [pscustomobject]@{
            FilterName       = $i.FilterName
            VolumeRaw        = $raw
            VolumeNormalized = $norm
            MappedDrive      = $mappedDrive
            CanonicalVolume  = $canonical
            Instance         = $i.Instance
            Altitude         = $i.Altitude
        }
    }

    return $out
}

# -------------------------
# Volume mapping helpers (PS 5.1-safe)
# Maps: DriveLetter <-> DevicePath <-> VolumeGuid
# -------------------------

function Get-VolumeM  ap {
    # Returns a list of objects with DriveLetter, DevicePath, VolumeGuid (best-effort).

    $map = @()

    # 1) DriveLetter <-> Volume GUID via Win32_Volume (best effort; usually works)
    $vols = @()
    try {
        $vols = Get-CimInstance Win32_Volume -ErrorAction Stop |
            Where-Object { $_.DriveLetter -match '^[A-Z]:$' }
    } catch {
        $vols = @()
    }

    foreach ($v in $vols) {
        $map += [pscustomobject]@{
            DriveLetter = $v.DriveLetter
            VolumeGuid  = $v.DeviceID       # typically \\?\Volume{GUID}\
            DevicePath  = $null             # filled in next stage if possible
        }
    }

# 2) DriveLetter <-> DevicePath via QueryDosDevice (very reliable for \Device\HarddiskVolumeX)
#    QueryDosDevice("C:") -> "\Device\HarddiskVolumeX"
    $sig = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DosDevice {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
  public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
"@
    try {
        if (-not ("DosDevice" -as [type])) {
        Add-Type -TypeDefinition $sig -ErrorAction Stop
        }
    } catch {
        # If Add-Type fails (rare), we just skip DevicePath enrichment.
    }

    foreach ($entry in $map) {
        try {
            $sb = New-Object System.Text.StringBuilder 1024
            $r = [DosDevice]::QueryDosDevice($entry.DriveLetter, $sb, $sb.Capacity)
            if ($r -gt 0) {
                $entry.DevicePath = $sb.ToString()
            }
        } catch { }
    }

    return $map
}

function Normalize-VolumeId {
    param([string]$Volume)

    if ([string]::IsNullOrWhiteSpace($Volume)) { return $null }

    $v = $Volume.Trim()

    # Strip trailing backslash if present
    if ($v.EndsWith("\")) { $v = $v.TrimEnd("\") }

    # Normalize \\?\Volume{GUID}\ or \??\Volume{GUID}\ to \\?\Volume{GUID}
    if ($v -match '^(\\\\\?\\Volume\{[0-9A-Fa-f\-]+\})') { return $matches[1] }
    if ($v -match '^(\\\?\?\\Volume\{[0-9A-Fa-f\-]+\})') { return "\\?\$($matches[1].Substring(4))" }

    # Normalize drive letter
    if ($v -match '^[A-Za-z]:$') { return $v.ToUpper() }

    # Device path stays as-is
    if ($v -like '\Device\HarddiskVolume*') { return $v }

    return $v
}

function Map-FltmcInstances {
    param(
        [Parameter(Mandatory=$true)][object[]]$Instances,
        [Parameter(Mandatory=$true)][object[]]$VolumeMap
    )

    # Build lookup dictionaries
    $driveToDev  = @{}
    $driveToGuid = @{}
    $devToDrive  = @{}
    $guidToDrive = @{}

    foreach ($m in $VolumeMap) {
        if ($m.DriveLetter) {
            $driveToGuid[$m.DriveLetter] = (Normalize-VolumeId $m.VolumeGuid)
            if ($m.DevicePath) { $driveToDev[$m.DriveLetter] = $m.DevicePath }
        }
        if ($m.DevicePath -and $m.DriveLetter) { $devToDrive[$m.DevicePath] = $m.DriveLetter }
        if ($m.VolumeGuid -and $m.DriveLetter) { $guidToDrive[(Normalize-VolumeId $m.VolumeGuid)] = $m.DriveLetter }
    }

# Enrich each instance with normalized fields
    $out = @()
    foreach ($i in $Instances) {
        $raw = $i.Volume
        $norm = Normalize-VolumeId $raw

        $mappedDrive = $null
        if ($norm -match '^[A-Z]:$') { $mappedDrive = $norm }
        elseif ($devToDrive.ContainsKey($norm)) { $mappedDrive = $devToDrive[$norm] }
        elseif ($guidToDrive.ContainsKey($norm)) { $mappedDrive = $guidToDrive[$norm] }

        # Canonical: drive letter if available, else GUID if that’s what we got, else device path, else raw norm
        $canonical = $null
        if ($mappedDrive) { $canonical = $mappedDrive }
        elseif ($norm -like '\\?\Volume{*') { $canonical = $norm }
        elseif ($norm -like '\Device\HarddiskVolume*') { $canonical = $norm }
        else { $canonical = $norm }

        $out += [pscustomobject]@{
            FilterName       = $i.FilterName
  )
    if ($top.Count -gt 0) {
        $inject += ("Filters affecting {0} (Top 5):" -f $drive)
        foreach ($f in ($summaryObj.Filters | Select-Object -First 5)) {
            $inject += ("  - {0} (Alt {1})" -f $f.FilterName, $f.MaxAltitude)
        }
    }

    return $inject
}

# -------------------------
# Routing logic (simple + reliable)
# -------------------------
$routeQueue = "Endpoint / Platform"
$routeConfidence = "Low"
$routeReason = "Insufficient signals"

if ($pathType -eq "UNC") {
    $routeQueue = "Network / VPN / File Services"
    $routeConfidence = "High"
    $routeReason = "UNC path indicates network / SMB dependency"
}
elseif ($pathType -eq "Local") {
    $routeQueue = "Endpoint / Security (Minifilters)"
    $routeConfidence = "Medium"
    $routeReason = "Local file path; likely storage or filter interaction"
}

$routing = [pscustomobject]@{
    Queue      = $routeQueue
    Confidence = $routeConfidence
    Reason     = $routeReason
}

# -------------------------
# Human summary
# -------------------------
Write-Text -Path (Join-Path $bundle "Summary_Human.txt") -Content @(
    "FreezeDiscovery - Human Summary"
    "--------------------------------"
    "Case: $CaseId"
    "Computer: $($sys.ComputerName)"
    "User: $($sys.UserName)"
    ""
    "TargetPath: $TargetPath"
    "PathType: $pathType"
    ""
    "Routing:"
    "  Queue: $($routing.Queue)"
    "  Confidence: $($routing.Confidence)"
    "  Reason: $($routing.Reason)"
)

# -------------------------
# Ticket summary (Tierâ€‘1 ready)
# -------------------------
Write-Text -Path (Join-Path $bundle "TicketSummary.txt") -Content @(
    "TICKET SUMMARY (FreezeDiscovery)"
    "================================"
    "Case: $CaseId"
    ""
    "COPY / PASTE INTO TICKET"
    "------------------------"
    "Freeze observed."
    "TargetPath: $TargetPath"
    "PathType: $pathType"
    "Routing: $($routing.Queue)"
    "Confidence: $($routing.Confidence)"
    "Reason: $($routing.Reason)"
    ""
    "ATTACHMENTS"
    "- Summary_Human.txt"
    "- SystemInfo.json"
    "- TargetContext.json"
    "- fltmc_filters_raw.txt"
    "- fltmc_instances_raw.txt"
    "- MiniFilters.json"
    "- MiniFilterInstances.json"
    "- VolumeMap.json"
)

# -------------------------
# Zip bundle
# -------------------------
$zip = "$bundle.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$bundle\*" -DestinationPath $zip -Force

Write-Output "Bundle created:"
Write-Output $zip
Write-Output "Routing: $($routing.Queue) (Confidence: $($routing.Confidence))"