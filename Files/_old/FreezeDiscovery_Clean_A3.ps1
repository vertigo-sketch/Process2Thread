[CmdletBinding()]
param(
    [string]$TargetPath,
    [string]$CaseId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# =========================================
# Safe writers (NO -Lines params anywhere)
# =========================================
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
            ConvertTo-Json -Depth 3 | Out-File $Path -Encoding UTF8 -Force
        return
    }
    $Value | ConvertTo-Json -Depth 10 | Out-File $Path -Encoding UTF8 -Force
}

# =========================================
# FLTMC capture + parsing (PS 5.1 safe)
# =========================================
function Get-FltmcRaw {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("filters","instances")]
        [string]$Mode
    )
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

# =========================================
# Volume mapping + normalization (PS 5.1-safe)
# =========================================
function Get-VolumeMap {
    $map = @()

    # A) DriveLetter <-> Volume GUID via Win32_Volume
    $vols = @()
    try {
        $vols = Get-CimInstance Win32_Volume -ErrorAction Stop |
            Where-Object { $_.DriveLetter -match '^[A-Z]:$' }
    } catch { $vols = @() }

    foreach ($v in $vols) {
        $map += [pscustomobject]@{
            DriveLetter = $v.DriveLetter
            VolumeGuid  = $v.DeviceID
            DevicePath  = $null
        }
    }

    # B) DriveLetter <-> DevicePath via QueryDosDevice
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
    } catch { }

    foreach ($entry in $map) {
        try {
            $sb = New-Object System.Text.StringBuilder 1024
            $r  = [DosDevice]::QueryDosDevice($entry.DriveLetter, $sb, $sb.Capacity)
            if ($r -gt 0) { $entry.DevicePath = $sb.ToString() }
        } catch { }
    }

    return $map
}

function Normalize-VolumeId {
    param([string]$Volume)

    if ([string]::IsNullOrWhiteSpace($Volume)) { return $null }
    $v = $Volume.Trim()
    if ($v.EndsWith("\")) { $v = $v.TrimEnd("\") }

    if ($v -match '^[A-Za-z]:$') { return $v.ToUpper() }
    if ($v -match '^(\\\\\?\\Volume\{[0-9A-Fa-f\-]+\})') { return $matches[1] }
    if ($v -match '^(\\\?\?\\Volume\{[0-9A-Fa-f\-]+\})') { return ("\\?\{0}" -f $matches[1].Substring(4)) }
    if ($v -like '\Device\HarddiskVolume*') { return $v }

    return $v
}

function Map-FltmcInstances {
    param(
        [Parameter(Mandatory=$true)][object[]]$Instances,
        [Parameter(Mandatory=$true)][object[]]$VolumeMap
    )

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

# =========================================
# A2: Filters-on-target-volume summary
# =========================================
function Get-TargetDriveFromPath {
    param([string]$TargetPath)

    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $null }
    if ($TargetPath -like "\\*") { return $null }

    try {
        $q = Split-Path -Path $TargetPath -Qualifier
        if ($q -and $q -match '^[A-Za-z]:$') { return $q.ToUpper() }
    } catch { }

    return $null
}

function Convert-AltitudeToNumber {
    param([string]$Altitude)
    try { return [double]$Altitude } catch { return -1 }
}

function Build-FiltersOnVolumeSummary {
    param(
        [Parameter(Mandatory=$true)][string]$TargetDrive,
        [Parameter(Mandatory=$true)][object[]]$MiniFilters,
        [Parameter(Mandatory=$true)][object[]]$MiniInstancesMapped
    )

    $instOn = @($MiniInstancesMapped | Where-Object { $_.CanonicalVolume -eq $TargetDrive })

    $names = @()
    if ($instOn.Count -gt 0) {
        $names = $instOn | Select-Object -ExpandProperty FilterName -Unique
    }

    $perFilter = @()
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
            MaxAltitudeNumeric   = $maxAlt
            MaxAltitude          = $(if ($maxAlt -ge 0) { [string]$maxAlt } else { $instFor[0].Altitude })
            AttachedInstances    = $instFor.Count
            GlobalInstanceCount  = $(if ($fltMeta) { $fltMeta.Instances } else { $null })
            Frame                = $(if ($fltMeta) { $fltMeta.Frame } else { $null })
        }
    }

    $sorted = $perFilter | Sort-Object -Property MaxAltitudeNumeric -Descending

    return [pscustomobject]@{
        TargetDrive   = $TargetDrive
        InstanceCount = $instOn.Count
        FilterCount   = @($sorted).Count
        Filters       = $sorted
    }
}

function Write-FiltersOnTargetVolumeArtifacts {
    param(
        [Parameter(Mandatory=$true)][string]$BundlePath,
        [Parameter(Mandatory=$true)][string]$TargetPath,
        [Parameter(Mandatory=$true)][object[]]$MiniFilters,
        [Parameter(Mandatory=$true)][object[]]$MiniInstancesMapped
    )

    $drive = Get-TargetDriveFromPath -TargetPath $TargetPath

    if (-not $drive) {
        Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content @(
            "FiltersOnTargetVolume Summary"
            "-----------------------------"
            ("TargetPath: {0}" -f $TargetPath)
            "No local drive correlation performed (UNC or no drive-qualified path)."
        )
        Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $null

        return [pscustomobject]@{
            TargetDrive = $null
            Lines = @()
            TopFilters = @()
            Summary = $null
        }
    }

    $summaryObj = Build-FiltersOnVolumeSummary -TargetDrive $drive -MiniFilters $MiniFilters -MiniInstancesMapped $MiniInstancesMapped
    Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $summaryObj

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("FiltersOnTargetVolume Summary")
    $lines.Add("-----------------------------")
    $lines.Add(("TargetPath: {0}" -f $TargetPath))
    $lines.Add(("TargetDrive: {0}" -f $summaryObj.TargetDrive))
    $lines.Add(("Instances matched on drive: {0}" -f $summaryObj.InstanceCount))
    $lines.Add(("Unique filters on drive: {0}" -f $summaryObj.FilterCount))
    $lines.Add("")
    $lines.Add("Top filters by altitude (highest first):")

    $top = @($summaryObj.Filters | Select-Object -First 10)
    if ($top.Count -eq 0) {
        $lines.Add("  <none matched by CanonicalVolume>")
        $lines.Add("  Check that MiniFilterInstances.json includes CanonicalVolume and that mapping is active.")
    } else {
        foreach ($f in $top) {
            $lines.Add(("  - {0} (Alt={1}, Attached={2}, Global={3})" -f $f.FilterName, $f.MaxAltitude, $f.AttachedInstances, $f.GlobalInstanceCount))
        }
    }

    Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content $lines.ToArray()

    $inject = @()
    $top5 = @()
    if ($top.Count -gt 0) {
        $inject += ("Filters affecting {0} (Top 5):" -f $drive)
        foreach ($f in ($summaryObj.Filters | Select-Object -First 5)) {
            $inject += ("  - {0} (Alt {1})" -f $f.FilterName, $f.MaxAltitude)
            $top5 += $f.FilterName
        }
    }

    return [pscustomobject]@{
        TargetDrive = $drive
        Lines = $inject
        TopFilters = $top5
        Summary = $summaryObj
    }
}

# =========================================
# A3: Signal capture + routing confidence
# =========================================
function Get-EventSignals {
    param([int]$LookbackHours = 48)

    $since = (Get-Date).AddHours(-1 * $LookbackHours)
    $ids = 41,107,137,129,153

    $ev = @()
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName="System"; StartTime=$since; Id=$ids } -ErrorAction SilentlyContinue
    } catch { $ev = @() }

    $sig = [pscustomobject]@{
        LookbackHours       = $LookbackHours
        StorageTimeoutCount = @($ev | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 }).Count
        PowerHintCount      = @($ev | Where-Object { $_.Id -eq 41 -or $_.Id -eq 107 -or $_.Id -eq 137 }).Count
        Events              = $ev | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
    }

    return $sig
}

function Get-GlobalProtectSignals {
    # Best-effort: do not fail the script if any cmdlets are blocked.
    $svc = @()
    foreach ($name in @("PanGPS","PanGPA")) {
        try { $svc += Get-Service -Name $name -ErrorAction Stop } catch { }
    }

    $svcRunning = $false
    if (@($svc | Where-Object { $_.Status -eq "Running" }).Count -gt 0) { $svcRunning = $true }

    $adapterUp = $false
    try {
        $ad = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match "PANGP|GlobalProtect" -or $_.Name -match "PANGP|GlobalProtect" }
        if (@($ad | Where-Object { $_.Status -eq "Up" }).Count -gt 0) { $adapterUp = $true }
    } catch { }

    $smbCount = 0
    try {
        $smb = Get-SmbConnection -ErrorAction SilentlyContinue
        $smbCount = @($smb | Where-Object { $_.ServerName }).Count
    } catch { $smbCount = 0 }

    return [pscustomobject]@{
        ServicesFound     = @($svc).Count
        ServiceRunning    = $svcRunning
        AdapterUp         = $adapterUp
        SmbConnectionCount= $smbCount
    }
}

function Compute-RoutingA3 {
    param(
        [string]$PathType,
        [pscustomobject]$EventSignals,
        [pscustomobject]$GpSignals,
        [string[]]$TopFilters,
        [pscustomobject]$A2Summary
    )

    $queue = "Endpoint / Platform"
    $confidence = "Low"
    $reason = "Insufficient signals"

    $stor = $false
    $pwr  = $false
    if ($EventSignals -and $EventSignals.StorageTimeoutCount -gt 0) { $stor = $true }
    if ($EventSignals -and $EventSignals.PowerHintCount -gt 0) { $pwr = $true }

    # A) UNC -> network/vpn
    if ($PathType -eq "UNC") {
        $queue = "Network / VPN (GlobalProtect) / File Services"
        $reason = "UNC path indicates SMB/VPN dependency"
        $confidence = "Medium"
        if ($GpSignals -and ($GpSignals.ServiceRunning -or $GpSignals.AdapterUp)) { $confidence = "High"; $reason += "; GlobalProtect appears active" }
        if ($GpSignals -and ($GpSignals.SmbConnectionCount -gt 0)) { $confidence = "High"; $reason += "; SMB sessions present" }
        return [pscustomobject]@{ Queue=$queue; Confidence=$confidence; Reason=$reason }
    }

    # B) Storage timeouts -> strong storage/driver signal
    if ($stor) {
        $queue = "Endpoint / Platform (Storage) + Security (Filters)"
        $confidence = "High"
        $reason = "Event 129/153 storage timeouts detected"
        if ($TopFilters -and $TopFilters.Count -gt 0) {
            $reason += ("; Top filter(s): " + ($TopFilters | Select-Object -First 3) -join ", ")
        }
        return [pscustomobject]@{ Queue=$queue; Confidence=$confidence; Reason=$reason }
    }

    # C) Power/resume hints -> medium, unless top filters include crypto/security and we have local path
    if ($pwr) {
        $queue = "Endpoint / Platform (Power/Resume) + Storage"
        $confidence = "Medium"
        $reason = "Power/resume indicators (41/107/137) detected"
        if ($TopFilters -and ($TopFilters -match "FileCrypt|WdFilter|Symantec|Crowd|Sentinel|Carbon|Sophos|McAfee|Trend")) {
            $confidence = "High"
            $reason += "; Security/encryption filter(s) present on target volume"
        }
        return [pscustomobject]@{ Queue=$queue; Confidence=$confidence; Reason=$reason }
    }

    # D) Local path, no strong event signals -> filters/platform
    if ($PathType -eq "Local") {
        $queue = "Endpoint / Security (Minifilters) / Platform"
        $confidence = "Medium"
        $reason = "Local path; minifilters and storage stack are common blockers when user-mode owners are not obvious"
        if ($TopFilters -and $TopFilters.Count -gt 0) {
            $reason += ("; Top filter(s): " + ($TopFilters | Select-Object -First 3) -join ", ")
        }
        return [pscustomobject]@{ Queue=$queue; Confidence=$confidence; Reason=$reason }
    }

    return [pscustomobject]@{ Queue=$queue; Confidence=$confidence; Reason=$reason }
}

# =========================================
# MAIN
# =========================================
$root = "C:\Temp\Process2Thread\FreezeDiscovery"
if (-not (Test-Path $root)) { New-Item $root -ItemType Directory | Out-Null }
$bundle = Join-Path $root ("Bundle_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item $bundle -ItemType Directory | Out-Null

# System info (best effort)
$sys = $null
try {
    $sys = [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        UserName     = $env:USERNAME
        OS           = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
    }
} catch { }
Write-JsonSafe -Path (Join-Path $bundle "SystemInfo.json") -Value $sys

# Target context
$pathType = "None"
if ($TargetPath) {
    if ($TargetPath -like "\\*") { $pathType = "UNC" }
    elseif ($TargetPath -match "^[A-Za-z]:") { $pathType = "Local" }
}
$targetCtx = [pscustomobject]@{ TargetPath = $TargetPath; PathType = $pathType }
Write-JsonSafe -Path (Join-Path $bundle "TargetContext.json") -Value $targetCtx

# A3 signals
$eventSignals = Get-EventSignals -LookbackHours 48
Write-JsonSafe -Path (Join-Path $bundle "EventSignals.json") -Value $eventSignals
$eventSignals.Events | Export-Csv (Join-Path $bundle "SystemEvents_48h.csv") -NoTypeInformation -Encoding UTF8 -Force

$gpSignals = Get-GlobalProtectSignals
Write-JsonSafe -Path (Join-Path $bundle "GlobalProtectSignals.json") -Value $gpSignals

# =========================
# FLTMC evidence + mapping + A2
# =========================
$miniFilters = @()
$miniInstancesMapped = @()
$A2 = $null

try {
    $rawFilters   = Get-FltmcRaw -Mode "filters"
    $rawInstances = Get-FltmcRaw -Mode "instances"

    $rawFilters   | Out-File (Join-Path $bundle "fltmc_filters_raw.txt")   -Encoding UTF8 -Force
    $rawInstances | Out-File (Join-Path $bundle "fltmc_instances_raw.txt") -Encoding UTF8 -Force

    $miniFilters   = Parse-FltmcFilters   -Lines $rawFilters
    $miniInstances = Parse-FltmcInstances -Lines $rawInstances

    $volumeMap = Get-VolumeMap
    Write-JsonSafe -Path (Join-Path $bundle "VolumeMap.json") -Value $volumeMap

    $miniInstancesMapped = Map-FltmcInstances -Instances $miniInstances -VolumeMap $volumeMap

    Write-JsonSafe -Path (Join-Path $bundle "MiniFilters.json") -Value $miniFilters
    Write-JsonSafe -Path (Join-Path $bundle "MiniFilterInstances.json") -Value $miniInstancesMapped

    $A2 = Write-FiltersOnTargetVolumeArtifacts `
        -BundlePath $bundle `
        -TargetPath $TargetPath `
        -MiniFilters $miniFilters `
        -MiniInstancesMapped $miniInstancesMapped
}
catch {
    Write-Text -Path (Join-Path $bundle "MiniFilter_WARNING.txt") -Content @(
        "MiniFilter capture failed (best-effort collector)."
        ("Error: {0}" -f $_.Exception.Message)
        "Try running PowerShell ISE as Administrator and re-run."
    )
    $A2 = [pscustomobject]@{ Lines=@(); TopFilters=@(); Summary=$null; TargetDrive=$null }
}

# A3 routing decision
$topFilters = @()
if ($A2 -and $A2.TopFilters) { $topFilters = $A2.TopFilters }
$routing = Compute-RoutingA3 -PathType $pathType -EventSignals $eventSignals -GpSignals $gpSignals -TopFilters $topFilters -A2Summary $A2.Summary
Write-JsonSafe -Path (Join-Path $bundle "Routing.json") -Value $routing

# Human summary
$humanLines = @(
    "FreezeDiscovery - Human Summary"
    "--------------------------------"
    ("Case: {0}" -f $CaseId)
    ("Computer: {0}" -f $sys.ComputerName)
    ("User: {0}" -f $sys.UserName)
    ""
    ("TargetPath: {0}" -f $TargetPath)
    ("PathType: {0}" -f $pathType)
    ""
    "Routing (A3):"
    ("  Queue: {0}" -f $routing.Queue)
    ("  Confidence: {0}" -f $routing.Confidence)
    ("  Reason: {0}" -f $routing.Reason)
)

if ($A2 -and $A2.Lines -and $A2.Lines.Count -gt 0) {
    $humanLines += ""
    $humanLines += $A2.Lines
}

Write-Text -Path (Join-Path $bundle "Summary_Human.txt") -Content $humanLines

# Ticket summary
$ticketLines = @(
    "TICKET SUMMARY (FreezeDiscovery)"
    "================================"
    ("Case: {0}" -f $CaseId)
    ""
    "COPY / PASTE INTO TICKET"
    "------------------------"
    "Freeze observed."
    ("TargetPath: {0}" -f $TargetPath)
    ("PathType: {0}" -f $pathType)
    ("Routing: {0}" -f $routing.Queue)
    ("Confidence: {0}" -f $routing.Confidence)
    ("Reason: {0}" -f $routing.Reason)
    ""
    "ATTACHMENTS"
    "- TicketSummary.txt"
    "- Summary_Human.txt"
    "- SystemInfo.json"
    "- TargetContext.json"
    "- Routing.json"
    "- EventSignals.json"
    "- SystemEvents_48h.csv"
    "- GlobalProtectSignals.json"
    "- fltmc_filters_raw.txt"
    "- fltmc_instances_raw.txt"
    "- MiniFilters.json"
    "- MiniFilterInstances.json"
    "- VolumeMap.json"
    "- FiltersOnTargetVolume.txt"
    "- FiltersOnTargetVolume.json"
)

if ($A2 -and $A2.Lines -and $A2.Lines.Count -gt 0) {
    $ticketLines += ""
    $ticketLines += $A2.Lines
}

Write-Text -Path (Join-Path $bundle "TicketSummary.txt") -Content $ticketLines

# Zip bundle
$zip = "$bundle.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$bundle\*" -DestinationPath $zip -Force

Write-Output "Bundle created:"
Write-Output $zip
Write-Output ("Routing: {0} (Confidence: {1})" -f $routing.Queue, $routing.Confidence)