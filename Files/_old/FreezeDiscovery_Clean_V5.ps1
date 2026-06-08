<#
  FreezeDiscoveryClean_V5.ps1
  - PS 5.1 / ISE safe
  - Robust fltmc instances parsing (supports columns: Frame, SprtFtrs, VlStatus)
  - Preserves extra instance columns + RawLine (Option A)
  - Safe file writers (no empty-string binding failures)
#>

[CmdletBinding()]
param(
    [string]$TargetPath,
    [string]$CaseId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ==========================================================
# Utility
# ==========================================================
function Ensure-Dir {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

# ==========================================================
# Safe writers
#   - Fixes: Cannot bind argument to parameter 'Content' because it is an empty string
#   - Guarantees file exists even with empty/null input
# ==========================================================
function Write-Text {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [object]$Content
    )

    # Normalize Content -> string[]
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

    # Sanitize elements
    $safe = foreach ($l in $lines) {
        if ($null -eq $l -or [string]::IsNullOrEmpty([string]$l)) { " " } else { [string]$l }
    }

    $safe | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Write-JsonSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        $Value
    )

    # Always write JSON even when Value is null
    if ($null -eq $Value) {
        @{ Notice="Value was null"; Time=(Get-Date).ToString("o") } |
            ConvertTo-Json -Depth 4 |
            Out-File -FilePath $Path -Encoding UTF8 -Force
        return
    }

    $Value | ConvertTo-Json -Depth 12 | Out-File -FilePath $Path -Encoding UTF8 -Force
}

# ==========================================================
# FLTMC capture + parsing (PS 5.1 safe)
# ==========================================================
function Get-FltmcRaw {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("filters","instances")]
        [string]$Mode
    )

    $raw = & fltmc.exe $Mode 2>&1
    return @($raw | ForEach-Object { [string]$_ })
}

function Parse-FltmcFilters {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -lt 4) { return @() }
    $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_ -and $_.Trim() -ne "" }

    $out = @()
    foreach ($r in $rows) {
        $p = ($r -split '\s{2,}').Trim()
        # Typical: FilterName, Instances, Altitude, Frame
        if ($p.Count -ge 4) {
            $out += [pscustomobject]@{
                FilterName = $p[0]
                Instances  = ([int]$p[1])
                Altitude   = $p[2]
                Frame      = $p[3]
                RawLine    = $r
            }
        }
    }
    return $out
}

function Parse-FltmcInstances {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -lt 4) { return @() }
    $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_ -and $_.Trim() -ne "" }

    $out = @()
    foreach ($r in $rows) {
        $p = ($r -split '\s{2,}').Trim()
        if (-not $p -or $p.Count -lt 5) { continue }

        # Modern shape (what you pasted):
        #   With Volume: Filter, Volume, Altitude, Instance, Frame, SprtFtrs, VlStatus   (Count >= 7)
        #   No Volume:   Filter, Altitude, Instance, Frame, SprtFtrs, VlStatus          (Count == 6)
        #
        # Fallback older shape:
        #   With Volume (older): Filter, Volume, Altitude, Instance, Frame, Flags       (Count == 6)
        #   No Volume (older):   Filter, Altitude, Instance, Frame, Flags               (Count == 5)

        $filter  = $p[0]
        $volume  = $null
        $alt     = $null
        $inst    = $null
        $frame   = $null
        $sprt    = $null
        $vlstat  = $null

        if ($p.Count -ge 7) {
            # Filter, Volume, Altitude, Instance, Frame, SprtFtrs, VlStatus
            $volume = $p[1]
            $alt    = $p[2]
            $inst   = $p[3]
            $frame  = $p[4]
            $sprt   = $p[5]
            $vlstat = $p[6]
        }
        elseif ($p.Count -eq 6) {
            # Could be "no volume modern" OR "with volume older"
            # Detect by checking whether token[1] looks like a volume name (C:, \\?\Volume{, \Device\)
            $t1 = [string]$p[1]
            $looksLikeVolume = $false
            if ($t1 -match '^[A-Za-z]:$') { $looksLikeVolume = $true }
            elseif ($t1 -like '\\?\Volume{*') { $looksLikeVolume = $true }
            elseif ($t1.StartsWith('\Device\')) { $looksLikeVolume = $true }
            elseif ($t1.StartsWith('\??\')) { $looksLikeVolume = $true }

            if ($looksLikeVolume) {
                # Older "with volume": Filter, Volume, Altitude, Instance, Frame, Flags (store Flags -> SprtFtrs)
                $volume = $p[1]
                $alt    = $p[2]
                $inst   = $p[3]
                $frame  = $p[4]
                $sprt   = $p[5]
                $vlstat = $null
            }
            else {
                # Modern "no volume": Filter, Altitude, Instance, Frame, SprtFtrs, VlStatus
                $volume = $null
                $alt    = $p[1]
                $inst   = $p[2]
                $frame  = $p[3]
                $sprt   = $p[4]
                $vlstat = $p[5]
            }
        }
        elseif ($p.Count -eq 5) {
            # Older "no volume": Filter, Altitude, Instance, Frame, Flags (store Flags -> SprtFtrs)
            $volume = $null
            $alt    = $p[1]
            $inst   = $p[2]
            $frame  = $p[3]
            $sprt   = $p[4]
            $vlstat = $null
        }
        else {
            # Best-effort: attempt the most common with-volume mapping if possible
            if ($p.Count -ge 6) {
                $volume = $p[1]
                $alt    = $p[2]
                $inst   = $p[3]
                $frame  = $p[4]
                $sprt   = $p[5]
            } elseif ($p.Count -ge 5) {
                $alt    = $p[1]
                $inst   = $p[2]
                $frame  = $p[3]
                $sprt   = $p[4]
            }
        }

        $out += [pscustomobject]@{
            FilterName = $filter
            Volume     = $volume
            Altitude   = $alt
            Instance   = $inst
            Frame      = $frame
            SprtFtrs   = $sprt
            VlStatus   = $vlstat
            RawLine    = $r
        }
    }

    return $out
}

# ==========================================================
# Volume mapping + normalization (PS 5.1-safe)
# ==========================================================
function Get-VolumeMap {
    $map = @()

    # DriveLetter <-> Volume GUID via Win32_Volume
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

    # DriveLetter <-> DevicePath via QueryDosDevice
    $sig = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DosDevice {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
  public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
"@
    try { if (-not ("DosDevice" -as [type])) { Add-Type -TypeDefinition $sig -ErrorAction Stop } } catch { }

    foreach ($entry in $map) {
        try {
            $sb = New-Object System.Text.StringBuilder 2048
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

    # \\?\Volume{GUID}
    if ($v -match '^(\\\\\?\\Volume\{[0-9A-Fa-f\-]+\})') { return $matches[1] }

    # \??\Volume{GUID} -> \\?\Volume{GUID}
    if ($v.StartsWith('\??\')) { return ('\\?\' + $v.Substring(4)) }

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
        elseif ($norm -and $devToDrive.ContainsKey($norm)) { $mappedDrive = $devToDrive[$norm] }
        elseif ($norm -and $guidToDrive.ContainsKey($norm)) { $mappedDrive = $guidToDrive[$norm] }

        $canonical = $null
        if ($mappedDrive) { $canonical = $mappedDrive }
        else { $canonical = $norm }

        $out += [pscustomobject]@{
            FilterName       = $i.FilterName
            VolumeRaw        = $raw
            VolumeNormalized = $norm
            MappedDrive      = $mappedDrive
            CanonicalVolume  = $canonical
            Instance         = $i.Instance
            Altitude         = $i.Altitude

            # Preserve extra columns (Option A)
            Frame            = $i.Frame
            SprtFtrs         = $i.SprtFtrs
            VlStatus         = $i.VlStatus
            RawLine          = $i.RawLine
        }
    }

    return $out
}

# ==========================================================
# A2: Filters-on-target-volume summary
# ==========================================================
function Get-TargetDriveFromPath {
    param([string]$TargetPath)

    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $null }
    if ($TargetPath -like "\\*") { return $null } # UNC

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
    if ($instOn.Count -gt 0) { $names = $instOn | Select-Object -ExpandProperty FilterName -Unique }

    $perFilter = @()
    foreach ($name in $names) {
        $instFor = @($instOn | Where-Object { $_.FilterName -eq $name })

        $maxAlt = -1
        foreach ($ii in $instFor) {
            $n = Convert-AltitudeToNumber $ii.Altitude
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
            Lines       = @()
            TopFilters  = @()
            Summary     = $null
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
        $lines.Add("  Check MiniFilterInstances.json includes CanonicalVolume and mapping is active.")
    } else {
        foreach ($f in $top) {
            $lines.Add(("  - {0} (Alt={1}, Attached={2}, Global={3})" -f $f.FilterName, $f.MaxAltitude, $f.AttachedInstances, $f.GlobalInstanceCount))
        }
    }

    Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content $lines.ToArray()

    $inject = @()
    $top5   = @()
    if ($top.Count -gt 0) {
        $inject += ("Filters affecting {0} (Top 5):" -f $drive)
        foreach ($f in ($summaryObj.Filters | Select-Object -First 5)) {
            $inject += ("  - {0} (Alt {1})" -f $f.FilterName, $f.MaxAltitude)
            $top5   += $f.FilterName
        }
    }

    return [pscustomobject]@{
        TargetDrive = $drive
        Lines       = $inject
        TopFilters  = $top5
        Summary     = $summaryObj
    }
}

# ==========================================================
# A3 signals
# ==========================================================
function Get-EventSignals {
    param([int]$LookbackHours = 48)

    $since = (Get-Date).AddHours(-1 * $LookbackHours)
    $ids   = 41,107,137,129,153

    $ev = @()
    try {
        $ev = Get-WinEvent -FilterHashtable @{ LogName="System"; StartTime=$since; Id=$ids } -ErrorAction SilentlyContinue
    } catch { $ev = @() }

    return [pscustomobject]@{
        LookbackHours       = $LookbackHours
        StorageTimeoutCount = @($ev | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 }).Count
        PowerHintCount      = @($ev | Where-Object { $_.Id -eq 41 -or $_.Id -eq 107 -or $_.Id -eq 137 }).Count
        Events              = $ev | Select-Object TimeCreated, Id, ProviderName, LevelDisplayName, Message
    }
}

function Get-GlobalProtectSignals {
    $svc = @()
    foreach ($name in @("PanGPS","PanGPA")) { try { $svc += Get-Service -Name $name -ErrorAction Stop } catch { } }

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
        ServicesFound      = @($svc).Count
        ServiceRunning     = $svcRunning
        AdapterUp          = $adapterUp
        SmbConnectionCount = $smbCount
    }
}

# ==========================================================
# A4: Classification + confidence + suspects
# ==========================================================
function Classify-FilterName {
    param([string]$FilterName)

    if ([string]::IsNullOrWhiteSpace($FilterName)) { return "Unknown" }

    if ($FilterName -ieq "WdFilter")   { return "Microsoft Defender (AV)" }
    if ($FilterName -ieq "FileCrypt")  { return "Microsoft Encryption (BitLocker/FileCrypt)" }
    if ($FilterName -ieq "luafv")      { return "Microsoft UAC Virtualization" }
    if ($FilterName -ieq "Wof")        { return "Microsoft WOF (Compression)" }

    if ($FilterName -match "CldFlt|OneDrive")      { return "Microsoft OneDrive/Cloud Files" }
    if ($FilterName -match "CSAgent|Crowd|Falcon") { return "EDR (CrowdStrike)" }
    if ($FilterName -match "Sentinel")            { return "EDR (SentinelOne)" }
    if ($FilterName -match "Carbon|Cb")           { return "EDR (Carbon Black)" }
    if ($FilterName -match "Cylance")             { return "EDR (Cylance)" }
    if ($FilterName -match "Sophos")              { return "AV/EDR (Sophos)" }
    if ($FilterName -match "Symantec")            { return "AV/DLP (Symantec/Broadcom)" }
    if ($FilterName -match "McAfee|Trellix")      { return "AV/EDR (McAfee/Trellix)" }
    if ($FilterName -match "Trend")               { return "AV/EDR (Trend Micro)" }
    if ($FilterName -match "Forcepoint")          { return "DLP (Forcepoint)" }
    if ($FilterName -match "DigitalGuardian|DG")  { return "DLP (Digital Guardian)" }
    if ($FilterName -match "Netskope")            { return "Security (Netskope)" }
    if ($FilterName -match "Zscaler")             { return "Security (Zscaler)" }
    if ($FilterName -match "Acronis|Veeam|Commvault|Rubrik") { return "Backup/Recovery" }
    if ($FilterName -match "Search|Index")        { return "Indexing/Search" }

    return "Other/Unknown"
}

function Score-RoutingConfidence {
    param(
        [string]$PathType,
        [pscustomobject]$EventSignals,
        [pscustomobject]$GpSignals,
        [string[]]$TopFilters,
        [pscustomobject]$A2Summary
    )

    $score = 30

    $stor = ($EventSignals -and $EventSignals.StorageTimeoutCount -gt 0)
    $pwr  = ($EventSignals -and $EventSignals.PowerHintCount -gt 0)

    $gpActive  = ($GpSignals -and ($GpSignals.ServiceRunning -or $GpSignals.AdapterUp))
    $smbActive = ($GpSignals -and ($GpSignals.SmbConnectionCount -gt 0))

    $securityHit = $false
    if ($TopFilters) {
        foreach ($f in $TopFilters) {
            $cat = Classify-FilterName $f
            if ($cat -match "Defender|Encryption|EDR|DLP|Security") { $securityHit = $true }
        }
    }

    if ($PathType -eq "UNC") {
        $score = 70
        if ($gpActive)  { $score += 15 }
        if ($smbActive) { $score += 15 }
    }
    elseif ($stor) {
        $score = 80
        if ($securityHit) { $score += 10 }
        if ($A2Summary -and $A2Summary.FilterCount -gt 0) { $score += 5 }
    }
    elseif ($pwr) {
        $score = 55
        if ($securityHit) { $score += 15 }
        if ($A2Summary -and $A2Summary.FilterCount -gt 0) { $score += 5 }
    }
    elseif ($PathType -eq "Local") {
        $score = 45
        if ($securityHit) { $score += 15 }
        if ($A2Summary -and $A2Summary.FilterCount -gt 0) { $score += 5 }
    }

    if ($score -gt 100) { $score = 100 }
    if ($score -lt 0)   { $score = 0 }

    $label = "Low"
    if ($score -ge 80) { $label = "High" }
    elseif ($score -ge 55) { $label = "Medium" }

    return [pscustomobject]@{ Score = $score; Label = $label }
}

function Compute-RoutingA4 {
    param(
        [string]$PathType,
        [pscustomobject]$EventSignals,
        [pscustomobject]$GpSignals,
        [string[]]$TopFilters,
        [pscustomobject]$A2Summary
    )

    $queue  = "Endpoint / Platform"
    $reason = "Insufficient signals"

    if ($PathType -eq "UNC") {
        $queue  = "Network / VPN (GlobalProtect) / File Services"
        $reason = "UNC target indicates SMB/VPN dependency"
    }
    else {
        if ($EventSignals -and $EventSignals.StorageTimeoutCount -gt 0) {
            $queue  = "Endpoint / Platform (Storage) + Security (Filters)"
            $reason = "Storage timeouts (Event 129/153) detected"
        }
        elseif ($EventSignals -and $EventSignals.PowerHintCount -gt 0) {
            $queue  = "Endpoint / Platform (Power/Resume) + Storage"
            $reason = "Power/resume hints (41/107/137) detected"
        }
        elseif ($PathType -eq "Local") {
            $queue  = "Endpoint / Security (Minifilters) / Platform"
            $reason = "Local path; filters/storage stack commonly block I/O"
        }
    }

    $suspects = @()
    if ($TopFilters) {
        foreach ($f in ($TopFilters | Select-Object -First 10)) {
            $suspects += [pscustomobject]@{
                FilterName = $f
                Category   = (Classify-FilterName $f)
            }
        }
    }

    $conf = Score-RoutingConfidence -PathType $PathType -EventSignals $EventSignals -GpSignals $GpSignals -TopFilters $TopFilters -A2Summary $A2Summary

    if ($suspects.Count -gt 0) {
        $reason = $reason + "; Suspect filter(s): " + (($suspects | Select-Object -First 3 | ForEach-Object { $_.FilterName }) -join ", ")
    }

    return [pscustomobject]@{
        Queue      = $queue
        Confidence = $conf.Label
        Score      = $conf.Score
        Reason     = $reason
        Suspects   = $suspects
        Signals    = [pscustomobject]@{
            PathType            = $PathType
            StorageTimeoutCount = $(if ($EventSignals) { $EventSignals.StorageTimeoutCount } else { 0 })
            PowerHintCount      = $(if ($EventSignals) { $EventSignals.PowerHintCount } else { 0 })
            GPServiceRunning    = $(if ($GpSignals) { $GpSignals.ServiceRunning } else { $false })
            GPAdapterUp         = $(if ($GpSignals) { $GpSignals.AdapterUp } else { $false })
            SmbConnectionCount  = $(if ($GpSignals) { $GpSignals.SmbConnectionCount } else { 0 })
        }
    }
}

function Write-SuspectFiltersTxt {
    param([string]$Path, [pscustomobject]$Routing)

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("Suspect Filters (A4)")
    $lines.Add("-------------------")
    $lines.Add(("Queue: {0}" -f $Routing.Queue))
    $lines.Add(("Confidence: {0} ({1}/100)" -f $Routing.Confidence, $Routing.Score))
    $lines.Add(("Reason: {0}" -f $Routing.Reason))
    $lines.Add("")

    if ($Routing.Suspects -and $Routing.Suspects.Count -gt 0) {
        $lines.Add("Top Suspects:")
        foreach ($s in ($Routing.Suspects | Select-Object -First 10)) {
            $lines.Add(("  - {0} :: {1}" -f $s.FilterName, $s.Category))
        }
    } else {
        $lines.Add("No suspect filters identified (no top filters available).")
    }

    Write-Text -Path $Path -Content $lines.ToArray()
}

# ==========================================================
# MAIN
# ==========================================================
$root = "C:\Temp\Process2Thread\FreezeDiscovery"
Ensure-Dir -Path $root

$bundle = Join-Path $root ("Bundle_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
Ensure-Dir -Path $bundle

# System info (ensure object exists even if CIM fails)
$sys = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = $null
}
try {
    $sys.OS = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber)
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

# Always write CSV with headers
$eventsForCsv = @($eventSignals.Events)
if (-not $eventsForCsv -or $eventsForCsv.Count -eq 0) {
    $eventsForCsv = @([pscustomobject]@{
        TimeCreated      = $null
        Id               = $null
        ProviderName     = $null
        LevelDisplayName = $null
        Message          = $null
    })
}
$eventsForCsv | Export-Csv -Path (Join-Path $bundle "SystemEvents_48h.csv") -NoTypeInformation -Encoding UTF8 -Force

$gpSignals = Get-GlobalProtectSignals
Write-JsonSafe -Path (Join-Path $bundle "GlobalProtectSignals.json") -Value $gpSignals

# FLTMC + mapping + A2
$miniFilters          = @()
$miniInstancesMapped  = @()
$A2                   = $null

try {
    $rawFilters   = Get-FltmcRaw -Mode "filters"
    $rawInstances = Get-FltmcRaw -Mode "instances"

    $rawFilters   | Out-File -FilePath (Join-Path $bundle "fltmc_filters_raw.txt")   -Encoding UTF8 -Force
    $rawInstances | Out-File -FilePath (Join-Path $bundle "fltmc_instances_raw.txt") -Encoding UTF8 -Force

    $miniFilters   = Parse-FltmcFilters   -Lines $rawFilters
    $miniInstances = Parse-FltmcInstances -Lines $rawInstances

    $volumeMap = Get-VolumeMap
    Write-JsonSafe -Path (Join-Path $bundle "VolumeMap.json") -Value $volumeMap

    $miniInstancesMapped = Map-FltmcInstances -Instances $miniInstances -VolumeMap $volumeMap

    Write-JsonSafe -Path (Join-Path $bundle "MiniFilters.json")         -Value $miniFilters
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

# A4 routing
$topFilters = @()
if ($A2 -and $A2.TopFilters) { $topFilters = @($A2.TopFilters) }

$routing = Compute-RoutingA4 -PathType $pathType -EventSignals $eventSignals -GpSignals $gpSignals -TopFilters $topFilters -A2Summary $A2.Summary

# Guarantee artifacts exist (routing + suspects + classification)
if ($null -eq $routing) {
    $routing = [pscustomobject]@{
        Queue      = "Unknown"
        Confidence = "Low"
        Score      = 0
        Reason     = "Routing not computed"
        Suspects   = @()
        Signals    = [pscustomobject]@{ PathType=$pathType }
    }
}
if ($null -eq $routing.Suspects) {
    $routing | Add-Member -NotePropertyName Suspects -NotePropertyValue @() -Force
}

Write-JsonSafe -Path (Join-Path $bundle "RoutingA4.json") -Value $routing
Write-SuspectFiltersTxt -Path (Join-Path $bundle "SuspectFilters.txt") -Routing $routing
Write-JsonSafe -Path (Join-Path $bundle "FilterClassification.json") -Value $routing.Suspects

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
    "Routing (A4):"
    ("  Queue: {0}" -f $routing.Queue)
    ("  Confidence: {0} ({1}/100)" -f $routing.Confidence, $routing.Score)
    ("  Reason: {0}" -f $routing.Reason)
)

if ($A2 -and $A2.Lines -and @($A2.Lines).Count -gt 0) {
    $humanLines += ""
    $humanLines += @($A2.Lines)
}

if ($routing.Suspects -and @($routing.Suspects).Count -gt 0) {
    $humanLines += ""
    $humanLines += "Suspect filters (Top 5):"
    foreach ($s in ($routing.Suspects | Select-Object -First 5)) {
        $humanLines += ("  - {0} :: {1}" -f $s.FilterName, $s.Category)
    }
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
    ("Confidence: {0} ({1}/100)" -f $routing.Confidence, $routing.Score)
    ("Reason: {0}" -f $routing.Reason)
    ""
    "ATTACHMENTS"
    "- TicketSummary.txt"
    "- Summary_Human.txt"
    "- SystemInfo.json"
    "- TargetContext.json"
    "- RoutingA4.json"
    "- SuspectFilters.txt"
    "- FilterClassification.json"
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

if ($A2 -and $A2.Lines -and @($A2.Lines).Count -gt 0) {
    $ticketLines += ""
    $ticketLines += @($A2.Lines)
}

if ($routing.Suspects -and @($routing.Suspects).Count -gt 0) {
    $ticketLines += ""
    $ticketLines += "Suspect filters (Top 5):"
    foreach ($s in ($routing.Suspects | Select-Object -First 5)) {
        $ticketLines += ("  - {0} :: {1}" -f $s.FilterName, $s.Category)
    }
}

Write-Text -Path (Join-Path $bundle "TicketSummary.txt") -Content $ticketLines

# Zip bundle
$zip = "$bundle.zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path (Join-Path $bundle "*") -DestinationPath $zip -Force

Write-Output "Bundle folder: $bundle"
Write-Output $zip
Write-Output ("Routing: {0} (Confidence: {1} {2}/100)" -f $routing.Queue, $routing.Confidence, $routing.Score)