<#
FreezeDiscovery_Clean_V10_1.ps1
- PS 5.1 / ISE safe
- Best practices: StrictMode 2.0, safe writers, robust parsing, best-effort collection, guaranteed artifacts
- Adds optional ETW trace: WPR fileio + minifilter -> MinifilterTrace.etl + ETWTraceMeta.json
#>

[CmdletBinding()]
param(
    [AllowEmptyString()]
    [string]$TargetPath,

    [AllowEmptyString()]
    [string]$CaseId,

    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery",

    [ValidateRange(1, 168)]
    [int]$LookbackHours = 48,

    [switch]$EnableEtwMinifilterTrace,

    [ValidateRange(10, 900)]
    [int]$EtwCaptureSeconds = 60
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ==========================================================
# Normalize Inputs (empty -> $null)
# ==========================================================
if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = $null }
if ([string]::IsNullOrWhiteSpace($CaseId))     { $CaseId = $null }

# ==========================================================
# Globals
# ==========================================================
$script:BundlePath = $null
$script:LogPath    = $null
$script:Version    = "10.1"

# ==========================================================
# Utility
# ==========================================================
function Ensure-Dir {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "{0} [{1}] {2}" -f $ts, $Level, $Message

    if ($script:LogPath) {
        try { $line | Out-File -FilePath $script:LogPath -Encoding UTF8 -Append -Force } catch { }
    }

    if ($Level -eq "ERROR") { Write-Host $line -ForegroundColor Red }
    elseif ($Level -eq "WARN") { Write-Host $line -ForegroundColor Yellow }
    elseif ($Level -eq "DEBUG") { Write-Host $line -ForegroundColor DarkGray }
    else { Write-Host $line }
}

function Write-Text {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)]
        [AllowNull()][AllowEmptyString()][AllowEmptyCollection()]
        [object]$Content
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
        if ($null -eq $l -or [string]::IsNullOrEmpty([string]$l)) { " " } else { [string]$l }
    }

    $safe | Out-File -FilePath $Path -Encoding UTF8 -Force
}

function Write-JsonSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        $Value
    )

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
    } catch {
        return $false
    }
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [Parameter()][string[]]$Arguments = @(),
        [Parameter()][int]$TimeoutSeconds = 0
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ($Arguments -join " ")
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow  = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    $null = $p.Start()

    if ($TimeoutSeconds -gt 0) {
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            try { $p.Kill() } catch { }
            return [pscustomobject]@{ ExitCode=-1; StdOut=""; StdErr=("Timed out after {0}s" -f $TimeoutSeconds) }
        }
    } else {
        $p.WaitForExit() | Out-Null
    }

    return [pscustomobject]@{
        ExitCode = $p.ExitCode
        StdOut   = $p.StandardOutput.ReadToEnd()
        StdErr   = $p.StandardError.ReadToEnd()
    }
}

# ==========================================================
# FLTMC capture + parsing
# ==========================================================
function Get-FltmcRaw {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("filters","instances")]
        [string]$Mode
    )

    $r = Invoke-ExternalCommand -FilePath "fltmc.exe" -Arguments @($Mode)
    $lines = @()
    if ($r.StdOut) { $lines += ($r.StdOut -split "`r?`n") }
    if ($r.StdErr) { $lines += ($r.StdErr -split "`r?`n") }
    return @($lines | ForEach-Object { [string]$_ })
}

function Parse-FltmcFilters {
    param([string[]]$Lines)

    if (-not $Lines -or $Lines.Count -lt 4) { return @() }

    $rows = $Lines | Select-Object -Skip 3 | Where-Object { $_ -and $_.Trim() -ne "" }
    $out = @()

    foreach ($r in $rows) {
        $p = ($r -split '\s{2,}').Trim()
        if ($p.Count -ge 4) {
            $inst = $null
            try { $inst = [int]$p[1] } catch { $inst = $null }

            $out += [pscustomobject]@{
                FilterName = $p[0]
                Instances  = $inst
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

        $filter = $p[0]
        $volume = $null
        $alt    = $null
        $inst   = $null
        $frame  = $null
        $sprt   = $null
        $vlstat = $null

        if ($p.Count -ge 7) {
            $volume = $p[1]; $alt = $p[2]; $inst = $p[3]; $frame = $p[4]; $sprt = $p[5]; $vlstat = $p[6]
        }
        elseif ($p.Count -eq 6) {
            $t1 = [string]$p[1]
            $looksLikeVolume = $false

            if ($t1 -match '^[A-Za-z]:$') { $looksLikeVolume = $true }
            elseif ($t1 -like '\\?\Volume{*') { $looksLikeVolume = $true }
            elseif ($t1.StartsWith('\Device\')) { $looksLikeVolume = $true }
            elseif ($t1.StartsWith('\??\')) { $looksLikeVolume = $true }

            if ($looksLikeVolume) {
                $volume = $p[1]; $alt = $p[2]; $inst = $p[3]; $frame = $p[4]; $sprt = $p[5]
            } else {
                $alt = $p[1]; $inst = $p[2]; $frame = $p[3]; $sprt = $p[4]; $vlstat = $p[5]
            }
        }
        elseif ($p.Count -eq 5) {
            $alt = $p[1]; $inst = $p[2]; $frame = $p[3]; $sprt = $p[4]
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
# Volume mapping + normalization
# ==========================================================
function Get-VolumeMap {
    $map = @()
    $vols = @()

    try {
        $vols = Get-CimInstance Win32_Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -match '^[A-Z]:$' }
    } catch { $vols = @() }

    foreach ($v in $vols) {
        $map += [pscustomobject]@{
            DriveLetter = $v.DriveLetter
            VolumeGuid  = $v.DeviceID
            DevicePath  = $null
        }
    }

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
            Add-Type -TypeDefinition $sig -ErrorAction Stop | Out-Null
        }
    } catch { }

    foreach ($entry in $map) {
        try {
            $sb = New-Object System.Text.StringBuilder 2048
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
    if ($v.EndsWith("\")) { $v = $v.TrimEnd("\") }

    if ($v -match '^[A-Za-z]:$') { return $v.ToUpper() }
    if ($v -match '^(\\\?\\Volume\{[0-9A-Fa-f\-]+\})') { return $matches[1] }
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

        $canonical = $(if ($mappedDrive) { $mappedDrive } else { $norm })

        $out += [pscustomobject]@{
            FilterName       = $i.FilterName
            VolumeRaw        = $raw
            VolumeNormalized = $norm
            MappedDrive      = $mappedDrive
            CanonicalVolume  = $canonical
            Instance         = $i.Instance
            Altitude         = $i.Altitude
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
            FilterName          = $name
            MaxAltitudeNumeric  = $maxAlt
            MaxAltitude         = $(if ($maxAlt -ge 0) { [string]$maxAlt } else { $instFor[0].Altitude })
            AttachedInstances   = $instFor.Count
            GlobalInstanceCount = $(if ($fltMeta) { $fltMeta.Instances } else { $null })
            Frame               = $(if ($fltMeta) { $fltMeta.Frame } else { $null })
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
        [AllowNull()][AllowEmptyString()][string]$TargetPath,
        [Parameter(Mandatory=$true)][object[]]$MiniFilters,
        [Parameter(Mandatory=$true)][object[]]$MiniInstancesMapped
    )

    $tpDisplay = $(if ([string]::IsNullOrWhiteSpace($TargetPath)) { "<not provided>" } else { $TargetPath })
    $drive = Get-TargetDriveFromPath -TargetPath $TargetPath

    if (-not $drive) {
        Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content @(
            "FiltersOnTargetVolume Summary"
            "-----------------------------"
            ("TargetPath: {0}" -f $tpDisplay)
            "No local drive correlation performed (UNC, no drive-qualified path, or TargetPath not provided)."
        )
        Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $null

        return [pscustomobject]@{ TargetDrive=$null; Lines=@(); TopFilters=@(); Summary=$null }
    }

    $summaryObj = Build-FiltersOnVolumeSummary -TargetDrive $drive -MiniFilters $MiniFilters -MiniInstancesMapped $MiniInstancesMapped
    Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $summaryObj

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("FiltersOnTargetVolume Summary")
    $lines.Add("-----------------------------")
    $lines.Add(("TargetPath: {0}" -f $tpDisplay))
    $lines.Add(("TargetDrive: {0}" -f $summaryObj.TargetDrive))
    $lines.Add(("Instances matched on drive: {0}" -f $summaryObj.InstanceCount))
    $lines.Add(("Unique filters on drive: {0}" -f $summaryObj.FilterCount))
    $lines.Add(" ")
    $lines.Add("Top filters by altitude (highest first):")

    $top = @($summaryObj.Filters | Select-Object -First 10)
    if ($top.Count -eq 0) {
        $lines.Add(" <none matched by CanonicalVolume>")
        $lines.Add(" Check MiniFilterInstances.json includes CanonicalVolume and mapping is active.")
    } else {
        foreach ($f in $top) {
            $lines.Add((" - {0} (Alt={1}, Attached={2}, Global={3})" -f $f.FilterName, $f.MaxAltitude, $f.AttachedInstances, $f.GlobalInstanceCount))
        }
    }

    Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content $lines.ToArray()

    $inject = @()
    $top5 = @()
    if ($top.Count -gt 0) {
        $inject += ("Filters affecting {0} (Top 5):" -f $drive)
        foreach ($f in ($summaryObj.Filters | Select-Object -First 5)) {
            $inject += (" - {0} (Alt {1})" -f $f.FilterName, $f.MaxAltitude)
            $top5 += $f.FilterName
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
    $sysIds = 41,107,137,129,153
    $appIds = 1002

    $sysEv = @()
    $appEv = @()

    try { $sysEv = Get-WinEvent -FilterHashtable @{ LogName="System"; StartTime=$since; Id=$sysIds } -ErrorAction SilentlyContinue } catch { $sysEv = @() }
    try { $appEv = Get-WinEvent -FilterHashtable @{ LogName="Application"; StartTime=$since; Id=$appIds } -ErrorAction SilentlyContinue } catch { $appEv = @() }

    $sysRows = @($sysEv | Select-Object @{Name="LogName";Expression={"System"}}, TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    $appRows = @($appEv | Select-Object @{Name="LogName";Expression={"Application"}}, TimeCreated, Id, ProviderName, LevelDisplayName, Message)
    $allRows = @($sysRows + $appRows) | Sort-Object -Property TimeCreated -Descending

    return [pscustomobject]@{
        LookbackHours        = $LookbackHours
        StorageTimeoutCount  = @($sysEv | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 }).Count
        PowerHintCount       = @($sysEv | Where-Object { $_.Id -eq 41 -or $_.Id -eq 107 -or $_.Id -eq 137 }).Count
        Application1002Count = @($appEv | Where-Object { $_.Id -eq 1002 }).Count
        Events               = $allRows
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
            Where-Object { $_.InterfaceDescription -match "GlobalProtect|PANGP" -or $_.Name -match "GlobalProtect|PANGP" }
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
# A4 routing
# ==========================================================
function Classify-FilterName {
    param([string]$FilterName)

    if ([string]::IsNullOrWhiteSpace($FilterName)) { return "Unknown" }
    if ($FilterName -ieq "WdFilter")  { return "Microsoft Defender (AV)" }
    if ($FilterName -ieq "FileCrypt") { return "Microsoft Encryption (BitLocker/FileCrypt)" }
    if ($FilterName -ieq "luafv")     { return "Microsoft UAC Virtualization" }
    if ($FilterName -ieq "Wof")       { return "Microsoft WOF (Compression)" }

    if ($FilterName -match '(?i)CldFlt|OneDrive')               { return "Microsoft OneDrive/Cloud Files" }
    if ($FilterName -match '(?i)CSAgent|CrowdStrike|Falcon')    { return "EDR (CrowdStrike)" }
    if ($FilterName -match '(?i)Sentinel')                      { return "EDR (SentinelOne)" }
    if ($FilterName -match '(?i)Carbon|Cb')                     { return "EDR (Carbon Black)" }
    if ($FilterName -match '(?i)Cylance')                       { return "EDR (Cylance)" }
    if ($FilterName -match '(?i)Sophos')                        { return "AV/EDR (Sophos)" }
    if ($FilterName -match '(?i)Symantec')                      { return "AV/DLP (Symantec/Broadcom)" }
    if ($FilterName -match '(?i)McAfee|Trellix')                { return "AV/EDR (McAfee/Trellix)" }
    if ($FilterName -match '(?i)Trend')                         { return "AV/EDR (Trend Micro)" }
    if ($FilterName -match '(?i)Forcepoint')                    { return "DLP (Forcepoint)" }
    if ($FilterName -match '(?i)DigitalGuardian|DG')            { return "DLP (Digital Guardian)" }
    if ($FilterName -match '(?i)Netskope')                      { return "Security (Netskope)" }
    if ($FilterName -match '(?i)Zscaler')                       { return "Security (Zscaler)" }
    if ($FilterName -match '(?i)Acronis|Veeam|Commvault|Rubrik') { return "Backup/Recovery" }
    if ($FilterName -match '(?i)Search|Index')                  { return "Indexing/Search" }

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
            if ($cat -match 'Defender|Encryption|EDR|DLP|Security') { $securityHit = $true }
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
    if ($score -lt 0) { $score = 0 }

    $label = "Low"
    if ($score -ge 80) { $label = "High" }
    elseif ($score -ge 55) { $label = "Medium" }

    return [pscustomobject]@{ Score=$score; Label=$label }
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
    } else {
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
            $suspects += [pscustomobject]@{ FilterName=$f; Category=(Classify-FilterName $f) }
        }
    }

    $conf = Score-RoutingConfidence -PathType $PathType -EventSignals $EventSignals -GpSignals $GpSignals -TopFilters $TopFilters -A2Summary $A2Summary

    if ($suspects.Count -gt 0) {
        $top3 = ($suspects | Select-Object -First 3 | ForEach-Object { $_.FilterName }) -join ", "
        $reason = $reason + "; Suspect filter(s): " + $top3
    }

    return [pscustomobject]@{
        Queue      = $queue
        Confidence = $conf.Label
        Score      = $conf.Score
        Reason     = $reason
        Suspects   = $suspects
        Signals    = [pscustomobject]@{
            PathType             = $PathType
            StorageTimeoutCount  = $(if ($EventSignals) { $EventSignals.StorageTimeoutCount } else { 0 })
            PowerHintCount       = $(if ($EventSignals) { $EventSignals.PowerHintCount } else { 0 })
            Application1002Count = $(if ($EventSignals) { $EventSignals.Application1002Count } else { 0 })
            GPServiceRunning     = $(if ($GpSignals) { $GpSignals.ServiceRunning } else { $false })
            GPAdapterUp          = $(if ($GpSignals) { $GpSignals.AdapterUp } else { $false })
            SmbConnectionCount   = $(if ($GpSignals) { $GpSignals.SmbConnectionCount } else { 0 })
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
            $lines.Add((" - {0} :: {1}" -f $s.FilterName, $s.Category))
        }
    } else {
        $lines.Add("No suspect filters identified (no top filters available).")
    }

    Write-Text -Path $Path -Content $lines.ToArray()
}

# ==========================================================
# ETW/WPR trace capture (Minifilter + FileIO)
# ==========================================================
function Get-WprPath {
    try { return (Get-Command wpr.exe -ErrorAction Stop).Source } catch { return $null }
}

function Start-WprMinifilterTrace {
    param(
        [Parameter(Mandatory=$true)][string]$BundlePath,
        [Parameter(Mandatory=$true)][int]$CaptureSeconds
    )

    $etlPath = Join-Path $BundlePath "MinifilterTrace.etl"

    $meta = [pscustomobject]@{
        Enabled        = $true
        Tool           = "wpr.exe"
        Profiles       = @("fileio","minifilter")
        FileMode       = "filemode"
        CaptureSeconds = $CaptureSeconds
        StartTimeUtc   = (Get-Date).ToUniversalTime().ToString("o")
        StopTimeUtc    = $null
        OutputEtl      = $etlPath
        Admin          = (Test-IsAdmin)
        WprFound       = $false
        Success        = $false
        Error          = $null
        ExitCodeStart  = $null
        ExitCodeStop   = $null
    }

    $wpr = Get-WprPath
    if (-not $wpr) { $meta.Error = "wpr.exe not found (not in PATH)."; return $meta }
    $meta.WprFound = $true

    if (-not $meta.Admin) { $meta.Error = "ETW trace requires elevation. Re-run PowerShell as Administrator."; return $meta }

    try { Invoke-ExternalCommand -FilePath $wpr -Arguments @("-cancel") | Out-Null } catch { }

    try {
        $rStart = Invoke-ExternalCommand -FilePath $wpr -Arguments @("-start","fileio","-start","minifilter","-filemode")
        $meta.ExitCodeStart = $rStart.ExitCode
        if ($rStart.ExitCode -ne 0) {
            $meta.Error = ("wpr start failed. ExitCode={0}. {1}" -f $rStart.ExitCode, $rStart.StdErr).Trim()
            return $meta
        }

        Start-Sleep -Seconds $CaptureSeconds

        if (Test-Path -LiteralPath $etlPath) { Remove-Item -LiteralPath $etlPath -Force -ErrorAction SilentlyContinue }

        $rStop = Invoke-ExternalCommand -FilePath $wpr -Arguments @("-stop", ('"{0}"' -f $etlPath))
        $meta.ExitCodeStop = $rStop.ExitCode
        $meta.StopTimeUtc  = (Get-Date).ToUniversalTime().ToString("o")

        if ($rStop.ExitCode -ne 0) {
            $meta.Error = ("wpr stop failed. ExitCode={0}. {1}" -f $rStop.ExitCode, $rStop.StdErr).Trim()
            try { Invoke-ExternalCommand -FilePath $wpr -Arguments @("-cancel") | Out-Null } catch { }
            return $meta
        }

        if (Test-Path -LiteralPath $etlPath) { $meta.Success = $true }
        else { $meta.Error = "wpr stop completed but ETL was not created." }
    }
    catch {
        $meta.Error = $_.Exception.Message
        try { Invoke-ExternalCommand -FilePath $wpr -Arguments @("-cancel") | Out-Null } catch { }
    }

    return $meta
}

# ==========================================================
# MAIN
# ==========================================================
Ensure-Dir -Path $OutputRoot

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$script:BundlePath = Join-Path $OutputRoot ("Bundle_" + $timestamp)
Ensure-Dir -Path $script:BundlePath

$script:LogPath = Join-Path $script:BundlePath "FreezeDiscovery.log"

Write-Log -Message ("=== FreezeDiscovery Clean v{0} START ===" -f $script:Version)
Write-Log -Message ("BundlePath={0}" -f $script:BundlePath)
Write-Log -Message ("IsAdmin={0}" -f (Test-IsAdmin))

# System info
$sys = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = $null
}
try { $sys.OS = Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber } catch { }
Write-JsonSafe -Path (Join-Path $script:BundlePath "SystemInfo.json") -Value $sys

# Target context
$pathType = "None"
if ($TargetPath) {
    if ($TargetPath -like "\\*") { $pathType = "UNC" }
    elseif ($TargetPath -match '^[A-Za-z]:') { $pathType = "Local" }
}
Write-JsonSafe -Path (Join-Path $script:BundlePath "TargetContext.json") -Value ([pscustomobject]@{ TargetPath=$TargetPath; PathType=$pathType })

# A3 signals
$eventSignals = Get-EventSignals -LookbackHours $LookbackHours
Write-JsonSafe -Path (Join-Path $script:BundlePath "EventSignals.json") -Value $eventSignals

# Export merged events
$eventsForCsv = @($eventSignals.Events)
if (-not $eventsForCsv -or $eventsForCsv.Count -eq 0) {
    $eventsForCsv = @([pscustomobject]@{ LogName=$null; TimeCreated=$null; Id=$null; ProviderName=$null; LevelDisplayName=$null; Message=$null })
}
$eventsForCsv | Export-Csv -Path (Join-Path $script:BundlePath "SystemEvents_48h.csv") -NoTypeInformation -Encoding UTF8 -Force

# GlobalProtect signals
$gpSignals = Get-GlobalProtectSignals
Write-JsonSafe -Path (Join-Path $script:BundlePath "GlobalProtectSignals.json") -Value $gpSignals

# FLTMC + mapping + A2
$miniFilters = @()
$miniInstancesMapped = @()
$A2 = $null

try {
    $rawFilters   = Get-FltmcRaw -Mode "filters"
    $rawInstances = Get-FltmcRaw -Mode "instances"

    $rawFilters   | Out-File -FilePath (Join-Path $script:BundlePath "fltmc_filters_raw.txt") -Encoding UTF8 -Force
    $rawInstances | Out-File -FilePath (Join-Path $script:BundlePath "fltmc_instances_raw.txt") -Encoding UTF8 -Force

    $miniFilters   = Parse-FltmcFilters -Lines $rawFilters
    $miniInstances = Parse-FltmcInstances -Lines $rawInstances

    $volumeMap = Get-VolumeMap
    Write-JsonSafe -Path (Join-Path $script:BundlePath "VolumeMap.json") -Value $volumeMap

    $miniInstancesMapped = Map-FltmcInstances -Instances $miniInstances -VolumeMap $volumeMap

    Write-JsonSafe -Path (Join-Path $script:BundlePath "MiniFilters.json") -Value $miniFilters
    Write-JsonSafe -Path (Join-Path $script:BundlePath "MiniFilterInstances.json") -Value $miniInstancesMapped
}
catch {
    Write-Text -Path (Join-Path $script:BundlePath "MiniFilter_WARNING.txt") -Content @(
        "MiniFilter capture failed (best-effort collector)."
        ("Error: {0}" -f $_.Exception.Message)
        "Try running PowerShell as Administrator and re-run."
    )
    Write-JsonSafe -Path (Join-Path $script:BundlePath "MiniFilters.json") -Value $miniFilters
    Write-JsonSafe -Path (Join-Path $script:BundlePath "MiniFilterInstances.json") -Value $miniInstancesMapped
}
finally {
    try {
        $A2 = Write-FiltersOnTargetVolumeArtifacts -BundlePath $script:BundlePath -TargetPath $TargetPath -MiniFilters $miniFilters -MiniInstancesMapped $miniInstancesMapped
    }
    catch {
        Write-Text -Path (Join-Path $script:BundlePath "FiltersOnTargetVolume.txt") -Content @(
            "FiltersOnTargetVolume Summary"
            "-----------------------------"
            ("TargetPath: {0}" -f $(if ($TargetPath) { $TargetPath } else { "<not provided>" }))
            "A2 summary could not be generated."
            ("Error: {0}" -f $_.Exception.Message)
        )
        Write-JsonSafe -Path (Join-Path $script:BundlePath "FiltersOnTargetVolume.json") -Value $null
        $A2 = [pscustomobject]@{ Lines=@(); TopFilters=@(); Summary=$null; TargetDrive=$null }
    }
}

# A4 routing
$topFilters = @()
if ($A2 -and $A2.TopFilters) { $topFilters = @($A2.TopFilters) }

$routing = Compute-RoutingA4 -PathType $pathType -EventSignals $eventSignals -GpSignals $gpSignals -TopFilters $topFilters -A2Summary $A2.Summary
if ($null -eq $routing) {
    $routing = [pscustomobject]@{ Queue="Unknown"; Confidence="Low"; Score=0; Reason="Routing not computed"; Suspects=@(); Signals=[pscustomobject]@{PathType=$pathType} }
}
if ($null -eq $routing.Suspects) { $routing | Add-Member -NotePropertyName Suspects -NotePropertyValue @() -Force }

Write-JsonSafe -Path (Join-Path $script:BundlePath "RoutingA4.json") -Value $routing
Write-SuspectFiltersTxt -Path (Join-Path $script:BundlePath "SuspectFilters.txt") -Routing $routing
Write-JsonSafe -Path (Join-Path $script:BundlePath "FilterClassification.json") -Value $routing.Suspects

# ----------------------------------------------------------
# ETW meta MUST ALWAYS have Success/Error properties (StrictMode-safe)
# ----------------------------------------------------------
$etwMeta = [pscustomobject]@{
    Enabled        = $false
    Tool           = "wpr.exe"
    Profiles       = @("fileio","minifilter")
    FileMode       = "filemode"
    CaptureSeconds = $EtwCaptureSeconds
    StartTimeUtc   = $null
    StopTimeUtc    = $null
    OutputEtl      = (Join-Path $script:BundlePath "MinifilterTrace.etl")
    Admin          = (Test-IsAdmin)
    WprFound       = $false
    Success        = $false
    Error          = $null
    ExitCodeStart  = $null
    ExitCodeStop   = $null
}

if ($EnableEtwMinifilterTrace) {
    $etwMeta = Start-WprMinifilterTrace -BundlePath $script:BundlePath -CaptureSeconds $EtwCaptureSeconds
}
Write-JsonSafe -Path (Join-Path $script:BundlePath "ETWTraceMeta.json") -Value $etwMeta

# Human summary
$humanLines = @(
    "FreezeDiscovery - Human Summary"
    "--------------------------------"
    ("Version: {0}" -f $script:Version)
    ("Case: {0}" -f $(if ($CaseId) { $CaseId } else { "<not provided>" }))
    ("Computer: {0}" -f $sys.ComputerName)
    ("User: {0}" -f $sys.UserName)
    ""
    ("TargetPath: {0}" -f $(if ($TargetPath) { $TargetPath } else { "<not provided>" }))
    ("PathType: {0}" -f $pathType)
    ""
    ("Signals (last {0}h):" -f $LookbackHours)
    (" StorageTimeoutCount (129/153): {0}" -f $eventSignals.StorageTimeoutCount)
    (" PowerHintCount (41/107/137): {0}" -f $eventSignals.PowerHintCount)
    (" Application1002Count: {0}" -f $eventSignals.Application1002Count)
    ""
    "Routing (A4):"
    (" Queue: {0}" -f $routing.Queue)
    (" Confidence: {0} ({1}/100)" -f $routing.Confidence, $routing.Score)
    (" Reason: {0}" -f $routing.Reason)
)

if ($A2 -and $A2.Lines -and @($A2.Lines).Count -gt 0) {
    $humanLines += ""
    $humanLines += @($A2.Lines)
}

$humanLines += ""
$humanLines += "ETW Trace (WPR fileio+minifilter):"
$humanLines += (" Enabled: {0}" -f $etwMeta.Enabled)
$humanLines += (" Success: {0}" -f $etwMeta.Success)
$humanLines += (" ETL: {0}" -f $etwMeta.OutputEtl)
if ($etwMeta.Error) { $humanLines += (" Error: {0}" -f $etwMeta.Error) }

if ($routing.Suspects -and @($routing.Suspects).Count -gt 0) {
    $humanLines += ""
    $humanLines += "Suspect filters (Top 5):"
    foreach ($s in ($routing.Suspects | Select-Object -First 5)) {
        $humanLines += (" - {0} :: {1}" -f $s.FilterName, $s.Category)
    }
}

Write-Text -Path (Join-Path $script:BundlePath "Summary_Human.txt") -Content $humanLines

# Ticket summary
$ticketLines = @(
    "TICKET SUMMARY (FreezeDiscovery)"
    "================================"
    ("Version: {0}" -f $script:Version)
    ("Case: {0}" -f $(if ($CaseId) { $CaseId } else { "<not provided>" }))
    ""
    "COPY / PASTE INTO TICKET"
    "------------------------"
    "Freeze observed."
    ("TargetPath: {0}" -f $(if ($TargetPath) { $TargetPath } else { "<not provided>" }))
    ("PathType: {0}" -f $pathType)
    ""
    ("Signals (last {0}h):" -f $LookbackHours)
    ("- StorageTimeoutCount (System 129/153): {0}" -f $eventSignals.StorageTimeoutCount)
    ("- PowerHintCount (System 41/107/137): {0}" -f $eventSignals.PowerHintCount)
    ("- Application1002Count (Application 1002): {0}" -f $eventSignals.Application1002Count)
    ""
    ("Routing: {0}" -f $routing.Queue)
    ("Confidence: {0} ({1}/100)" -f $routing.Confidence, $routing.Score)
    ("Reason: {0}" -f $routing.Reason)
    ""
    "ATTACHMENTS"
    "- TicketSummary.txt"
    "- Summary_Human.txt"
    "- FreezeDiscovery.log"
    "- SystemInfo.json"
    "- TargetContext.json"
    "- RoutingA4.json"
    "- SuspectFilters.txt"
    "- FilterClassification.json"
    "- EventSignals.json"
    ("- SystemEvents_48h.csv (includes System + Application(1002), last {0}h)" -f $LookbackHours)
    "- GlobalProtectSignals.json"
    "- fltmc_filters_raw.txt"
    "- fltmc_instances_raw.txt"
    "- MiniFilters.json"
    "- MiniFilterInstances.json"
    "- VolumeMap.json"
    "- FiltersOnTargetVolume.txt"
    "- FiltersOnTargetVolume.json"
    "- ETWTraceMeta.json"
)
if ($EnableEtwMinifilterTrace) { $ticketLines += "- MinifilterTrace.etl (WPR: fileio + minifilter)" }

Write-Text -Path (Join-Path $script:BundlePath "TicketSummary.txt") -Content $ticketLines

# Zip bundle
$zip = "$($script:BundlePath).zip"
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
Compress-Archive -Path (Join-Path $script:BundlePath "*") -DestinationPath $zip -Force

Write-Log -Message ("=== FreezeDiscovery Clean v{0} END ===" -f $script:Version)

Write-Output ("Bundle folder: {0}" -f $script:BundlePath)
Write-Output $zip
Write-Output ("Routing: {0} (Confidence: {1} {2}/100)" -f $routing.Queue, $routing.Confidence, $routing.Score)