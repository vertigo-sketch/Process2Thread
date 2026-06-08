<#
================================================================================
FreezeDiscovery_Clean_V8.ps1

VERSION  : V8
AUTHOR   : FreezeDiscovery Framework
REQUIRES : PowerShell 5.1+, Run as Administrator

CHANGELOG (V7 -> V8)
--------------------------------------------------------------------------------
[FIX]  Write-FiltersOnTargetVolumeArtifacts was an empty stub causing mandatory
       parameter prompts at runtime - fully implemented in V8
[FIX]  All other function bodies that were empty/stripped stubs fully rewritten
[FIX]  PS 5.1 compatibility sweep - removed all PS7-only syntax
[FIX]  $PID reserved variable replaced with $ProcessId throughout
[FIX]  Null/empty array guards added to all foreach loops
[FIX]  fltmc parsing hardened against variable column counts
[ADD]  Full classification engine (EDR, CloudSync, Backup, VPN, OS, Unknown)
[ADD]  Full A4 routing logic with Queue + Confidence + Score + Reason
[ADD]  Score-RoutingConfidence scoring model (0-100)
[ADD]  Application Event ID 1001 merged into SystemEvents_48h.csv
[ADD]  GlobalProtect service + adapter detection
[ADD]  Human-readable Summary_Human.txt
[ADD]  Copy-paste TicketSummary.txt with full attachment list
[ADD]  Zip bundle via Compress-Archive
================================================================================
#>

[CmdletBinding()]
param(
    [AllowEmptyString()][string]$TargetPath,
    [AllowEmptyString()][string]$CaseId
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ==============================================================================
# SECTION 1 - NORMALIZE INPUTS
# ==============================================================================
if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = $null }
if ([string]::IsNullOrWhiteSpace($CaseId))     { $CaseId     = $null }

# ==============================================================================
# SECTION 2 - UTILITY FUNCTIONS
# ==============================================================================
function Ensure-Dir {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
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
    } elseif ($Content -is [string]) {
        if ([string]::IsNullOrEmpty($Content)) { $lines = @(" ") }
        else { $lines = @($Content) }
    } else {
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
        @{ Notice = "Value was null"; Time = (Get-Date).ToString("o") } |
            ConvertTo-Json -Depth 4 |
            Out-File -FilePath $Path -Encoding UTF8 -Force
        return
    }
    $Value | ConvertTo-Json -Depth 12 | Out-File -FilePath $Path -Encoding UTF8 -Force
}

# ==============================================================================
# SECTION 3 - FLTMC CAPTURE AND PARSING
# ==============================================================================
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
    $rows = @($Lines | Select-Object -Skip 3 | Where-Object { $_ -and $_.Trim() -ne "" })
    $out  = @()
    foreach ($r in $rows) {
        $p = @(($r -split '\s{2,}') | ForEach-Object { $_.Trim() })
        if ($p.Count -ge 3) {
            $out += [pscustomobject]@{
                FilterName   = $p[0]
                NumInstances = if ($p.Count -ge 2) { $p[1] } else { "0" }
                Altitude     = if ($p.Count -ge 3) { $p[2] } else { "" }
                Frame        = if ($p.Count -ge 4) { $p[3] } else { "" }
            }
        }
    }
    return $out
}

function Parse-FltmcInstances {
    param([string[]]$Lines)
    if (-not $Lines -or $Lines.Count -lt 4) { return @() }
    $rows = @($Lines | Select-Object -Skip 3 | Where-Object { $_ -and $_.Trim() -ne "" })
    $out  = @()
    foreach ($r in $rows) {
        $p = @(($r -split '\s{2,}') | ForEach-Object { $_.Trim() })
        if (-not $p -or $p.Count -lt 3) { continue }
        $filter    = $p[0]
        $volume    = $null
        $altitude  = $null
        $frame     = $null
        $volumeGuid= $null
        # Detect if col[1] looks like a volume/drive
        $looksLikeVolume = $false
        if ($p.Count -ge 4) {
            $t1 = [string]$p[1]
            if ($t1 -match '^[A-Za-z]:$')          { $looksLikeVolume = $true }
            elseif ($t1 -like '\\?\Volume{*')       { $looksLikeVolume = $true }
            elseif ($t1.StartsWith('\Device\'))     { $looksLikeVolume = $true }
            elseif ($t1.StartsWith('\??\'))         { $looksLikeVolume = $true }
        }
        if ($looksLikeVolume -and $p.Count -ge 4) {
            $volume   = $p[1]
            $altitude = if ($p.Count -ge 3) { $p[2] } else { "" }
            $frame    = if ($p.Count -ge 4) { $p[3] } else { "" }
        } else {
            $volume   = $null
            $altitude = if ($p.Count -ge 2) { $p[1] } else { "" }
            $frame    = if ($p.Count -ge 3) { $p[2] } else { "" }
        }
        # Extract GUID from volume string
        if ($volume -and $volume -match '\{([0-9A-Fa-f\-]+)\}') {
            $volumeGuid = $matches[1]
        }
        $out += [pscustomobject]@{
            FilterName = $filter
            VolumeName = $volume
            Altitude   = $altitude
            Frame      = $frame
            VolumeGuid = $volumeGuid
            RawLine    = $r
        }
    }
    return $out
}

# ==============================================================================
# SECTION 4 - VOLUME MAPPING
# ==============================================================================
function Get-VolumeMap {
    $map  = @()
    $vols = @()
    try {
        $vols = @(Get-CimInstance Win32_Volume -ErrorAction Stop |
                  Where-Object { $_.DriveLetter -match '^[A-Z]:$' })
    } catch { $vols = @() }

    # P/Invoke QueryDosDevice to resolve device paths
    $sig = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class DosDeviceV8 {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
}
"@
    try {
        if (-not ([System.Management.Automation.PSTypeName]"DosDeviceV8").Type) {
            Add-Type -TypeDefinition $sig -ErrorAction Stop
        }
    } catch { }

    foreach ($v in $vols) {
        $devicePath = $null
        try {
            $sb = New-Object System.Text.StringBuilder 4096
            $driveLetter = $v.DriveLetter.TrimEnd('\')
            $r = [DosDeviceV8]::QueryDosDevice($driveLetter, $sb, $sb.Capacity)
            if ($r -gt 0) { $devicePath = $sb.ToString() }
        } catch { }

        $driveType = "Unknown"
        try {
            switch ($v.DriveType) {
                2 { $driveType = "Removable" }
                3 { $driveType = "Fixed" }
                4 { $driveType = "Network" }
                5 { $driveType = "CDRom" }
                6 { $driveType = "RAM" }
                default { $driveType = "Unknown" }
            }
        } catch { }

        $map += [pscustomobject]@{
            DriveLetter = $v.DriveLetter.TrimEnd('\')
            VolumeGuid  = $v.DeviceID
            DevicePath  = $devicePath
            DriveType   = $driveType
            Label       = $v.Label
        }
    }
    return $map
}

function Normalize-VolumeId {
    param([string]$Volume)
    if ([string]::IsNullOrWhiteSpace($Volume)) { return $null }
    $v = $Volume.Trim().TrimEnd('\').ToLower()
    return $v
}

function Map-FltmcInstances {
    param(
        [Parameter(Mandatory=$true)][object[]]$Instances,
        [Parameter(Mandatory=$true)][object[]]$VolumeMap
    )
    # Build lookup: DevicePath -> DriveLetter
    $devToLetter  = @{}
    $guidToLetter = @{}
    foreach ($m in @($VolumeMap)) {
        if ($m.DevicePath -and $m.DriveLetter) {
            $devToLetter[$m.DevicePath.ToLower()] = $m.DriveLetter
        }
        if ($m.VolumeGuid -and $m.DriveLetter) {
            $guidToLetter[$m.VolumeGuid.ToLower()] = $m.DriveLetter
        }
    }
    $out = @()
    foreach ($i in @($Instances)) {
        $raw         = $i.VolumeName
        $norm        = Normalize-VolumeId $raw
        $driveLetter = $null

        if ($norm -match '^[a-z]:$') {
            $driveLetter = $norm.ToUpper()
        } elseif ($norm -and $devToLetter.ContainsKey($norm)) {
            $driveLetter = $devToLetter[$norm]
        } elseif ($i.VolumeGuid) {
            $gLow = $i.VolumeGuid.ToLower()
            foreach ($k in $guidToLetter.Keys) {
                if ($k -like "*$gLow*") {
                    $driveLetter = $guidToLetter[$k]
                    break
                }
            }
        }

        $out += [pscustomobject]@{
            FilterName   = $i.FilterName
            VolumeName   = $raw
            VolumeNorm   = $norm
            DriveLetter  = $driveLetter
            Altitude     = $i.Altitude
            Frame        = $i.Frame
            VolumeGuid   = $i.VolumeGuid
            RawLine      = $i.RawLine
        }
    }
    return $out
}

# ==============================================================================
# SECTION 5 - A2: FILTERS ON TARGET VOLUME
# ==============================================================================
function Get-TargetDriveFromPath {
    param([string]$TargetPath)
    if ([string]::IsNullOrWhiteSpace($TargetPath)) { return $null }
    if ($TargetPath -like '\\*') { return $null }  # UNC - no local drive
    try {
        $q = Split-Path -Path $TargetPath -Qualifier -ErrorAction Stop
        if ($q -match '^[A-Za-z]:$') { return $q.ToUpper() }
    } catch { }
    return $null
}

function Convert-AltitudeToNumber {
    param([string]$Altitude)
    if ([string]::IsNullOrWhiteSpace($Altitude)) { return -1 }
    try { return [double]$Altitude } catch { return -1 }
}

function Build-FiltersOnVolumeSummary {
    param(
        [Parameter(Mandatory=$true)][string]$TargetDrive,
        [Parameter(Mandatory=$true)][object[]]$MiniFilters,
        [Parameter(Mandatory=$true)][object[]]$MiniInstancesMapped
    )

    # Filter instances that are on the target drive
    $instOnDrive = @($MiniInstancesMapped |
                     Where-Object { $_.DriveLetter -and
                                    $_.DriveLetter.ToUpper() -eq $TargetDrive.ToUpper() })

    $uniqueNames = @($instOnDrive | Select-Object -ExpandProperty FilterName -Unique)

    $perFilter = @()
    foreach ($name in $uniqueNames) {
        $instForFilter = @($instOnDrive | Where-Object { $_.FilterName -eq $name })
        $maxAlt = -1
        foreach ($ii in $instForFilter) {
            $n = Convert-AltitudeToNumber $ii.Altitude
            if ($n -gt $maxAlt) { $maxAlt = $n }
        }
        $fltMeta = @($MiniFilters | Where-Object { $_.FilterName -eq $name })[0]
        $perFilter += [pscustomobject]@{
            FilterName        = $name
            MaxAltitude       = $maxAlt
            AttachedInstances = $instForFilter.Count
            GlobalInstances   = if ($fltMeta) { $fltMeta.NumInstances } else { "N/A" }
            Frame             = if ($fltMeta) { $fltMeta.Frame } else { "" }
        }
    }

    $sorted     = @($perFilter | Sort-Object MaxAltitude -Descending)
    $top5       = @($sorted | Select-Object -First 5 | Select-Object -ExpandProperty FilterName)

    $summaryLines = @()
    $summaryLines += "Filters on target drive $TargetDrive (by altitude descending):"
    if ($sorted.Count -eq 0) {
        $summaryLines += "  <none matched>"
    } else {
        foreach ($f in $sorted) {
            $summaryLines += ("  - {0}  Alt={1}  Attached={2}  Global={3}" -f
                              $f.FilterName, $f.MaxAltitude,
                              $f.AttachedInstances, $f.GlobalInstances)
        }
    }

    $oneLiner = if ($sorted.Count -gt 0) {
        "Drive $TargetDrive : $($sorted.Count) filter(s). Top: $($top5 -join ', ')"
    } else {
        "Drive $TargetDrive : no filters matched"
    }

    return [pscustomobject]@{
        TargetDrive   = $TargetDrive
        Filters       = $sorted
        TopFilters    = $top5
        FilterCount   = $sorted.Count
        InstanceCount = $instOnDrive.Count
        Lines         = $summaryLines
        Summary       = $oneLiner
    }
}

function Write-FiltersOnTargetVolumeArtifacts {
    param(
        [Parameter(Mandatory=$true)][string]$BundlePath,
        [AllowNull()][AllowEmptyString()][string]$TargetPath,
        [Parameter(Mandatory=$true)][object[]]$MiniFilters,
        [Parameter(Mandatory=$true)][object[]]$MiniInstancesMapped
    )

    $tpDisplay = if ([string]::IsNullOrWhiteSpace($TargetPath)) { "<not provided>" } else { $TargetPath }
    $drive     = Get-TargetDriveFromPath -TargetPath $TargetPath

    # No drive correlation possible
    if (-not $drive) {
        $nodriveLines = @(
            "FiltersOnTargetVolume Summary",
            "-----------------------------",
            ("TargetPath  : {0}" -f $tpDisplay),
            "Result      : No local drive correlation performed.",
            "              Path is UNC, drive-letter absent, or TargetPath not provided."
        )
        Write-Text    -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content $nodriveLines
        Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $null
        return [pscustomobject]@{
            TargetDrive = $null
            Lines       = @()
            TopFilters  = @()
            Summary     = $null
        }
    }

    # Build summary object
    $summaryObj = Build-FiltersOnVolumeSummary `
                    -TargetDrive         $drive `
                    -MiniFilters         $MiniFilters `
                    -MiniInstancesMapped $MiniInstancesMapped

    # Write JSON
    Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $summaryObj

    # Write TXT
    $txtLines = @(
        "FiltersOnTargetVolume Summary",
        "-----------------------------",
        ("TargetPath      : {0}" -f $tpDisplay),
        ("TargetDrive     : {0}" -f $summaryObj.TargetDrive),
        ("Instances on drive : {0}" -f $summaryObj.InstanceCount),
        ("Unique filters  : {0}" -f $summaryObj.FilterCount),
        ""
    )
    $txtLines += $summaryObj.Lines
    Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content $txtLines

    # Inject lines (used in human summary)
    $injectLines = @()
    if ($summaryObj.FilterCount -gt 0) {
        $injectLines += ("Filters on {0} (Top 5):" -f $drive)
        foreach ($f in ($summaryObj.Filters | Select-Object -First 5)) {
            $injectLines += ("  - {0}  (Alt={1})" -f $f.FilterName, $f.MaxAltitude)
        }
    }

    return [pscustomobject]@{
        TargetDrive = $drive
        Lines       = $injectLines
        TopFilters  = $summaryObj.TopFilters
        Summary     = $summaryObj
    }
}

# ==============================================================================
# SECTION 6 - A3: EVENT SIGNALS
# ==============================================================================
function Get-EventSignals {
    param([int]$LookbackHours = 48)
    $since  = (Get-Date).AddHours(-$LookbackHours)
    $sysIds = @(41, 107, 129, 137, 153)
    $appIds = @(1001)

    $sysEv = @()
    $appEv = @()

    try {
        $sysEv = @(Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            StartTime = $since
            Id        = $sysIds
        } -ErrorAction SilentlyContinue)
    } catch { $sysEv = @() }

    try {
        $appEv = @(Get-WinEvent -FilterHashtable @{
            LogName   = "Application"
            StartTime = $since
            Id        = $appIds
        } -ErrorAction SilentlyContinue)
    } catch { $appEv = @() }

    $storageCount = @($sysEv | Where-Object { $_.Id -eq 129 -or $_.Id -eq 153 }).Count
    $powerCount   = @($sysEv | Where-Object { $_.Id -eq 41  -or $_.Id -eq 107 -or $_.Id -eq 137 }).Count
    $app1001Count = @($appEv | Where-Object { $_.Id -eq 1001 }).Count

    $sysRows = @($sysEv | Select-Object `
        @{Name="LogName";Expression={"System"}},
        TimeCreated, Id,
        @{Name="Source";Expression={$_.ProviderName}},
        LevelDisplayName,
        @{Name="Message";Expression={ if ($_.Message) { $_.Message.Substring(0, [Math]::Min(300,$_.Message.Length)) } else { "" } }})

    $appRows = @($appEv | Select-Object `
        @{Name="LogName";Expression={"Application"}},
        TimeCreated, Id,
        @{Name="Source";Expression={$_.ProviderName}},
        LevelDisplayName,
        @{Name="Message";Expression={ if ($_.Message) { $_.Message.Substring(0, [Math]::Min(300,$_.Message.Length)) } else { "" } }})

    $allRows = @($sysRows + $appRows) | Sort-Object TimeCreated -Descending

    return [pscustomobject]@{
        LookbackHours        = $LookbackHours
        StorageTimeoutCount  = $storageCount
        PowerHintCount       = $powerCount
        Application1001Count = $app1001Count
        Events               = $allRows
    }
}

function Get-GlobalProtectSignals {
    $svcList    = @()
    $isRunning  = $false
    $adapterUp  = $false
    $smbCount   = 0

    foreach ($svcName in @("PanGPS", "PanGPA")) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop
            $svcList += [pscustomobject]@{
                Name   = $svcName
                Status = $svc.Status.ToString()
            }
            if ($svc.Status -eq "Running") { $isRunning = $true }
        } catch { }
    }

    try {
        $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.InterfaceDescription -match "PANGP|GlobalProtect" -or
                           $_.Name                 -match "PANGP|GlobalProtect" })
        if (@($adapters | Where-Object { $_.Status -eq "Up" }).Count -gt 0) {
            $adapterUp = $true
        }
    } catch { }

    try {
        $smb      = @(Get-SmbConnection -ErrorAction SilentlyContinue)
        $smbCount = @($smb | Where-Object { $_.ServerName }).Count
    } catch { $smbCount = 0 }

    return [pscustomobject]@{
        ServiceStatuses = $svcList
        IsRunning       = $isRunning
        AdapterUp       = $adapterUp
        SmbCount        = $smbCount
        IsConnected     = ($isRunning -or $adapterUp)
    }
}

# ==============================================================================
# SECTION 7 - A4: CLASSIFICATION AND ROUTING
# ==============================================================================
function Classify-FilterName {
    param([string]$FilterName)
    if ([string]::IsNullOrWhiteSpace($FilterName)) {
        return [pscustomobject]@{
            FilterName = $FilterName
            Category   = "Unknown"
            Vendor     = "Unknown"
            RiskLevel  = "Low"
        }
    }
    $fn = $FilterName.ToLower()

    # EDR / Security
    if ($fn -match "csagent|cspcm|crowdstrike|csstatic")     { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="CrowdStrike";        RiskLevel="High" } }
    if ($fn -match "wdfilter|mpfilter|mpsdrv|wdnisdrv")     { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Microsoft Defender"; RiskLevel="Medium" } }
    if ($fn -match "carbonblack|cbk7|cbstream")              { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Carbon Black";       RiskLevel="High" } }
    if ($fn -match "cylance")                                 { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Cylance";           RiskLevel="High" } }
    if ($fn -match "sentinelmonitor|sentinel")                { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="SentinelOne";       RiskLevel="High" } }
    if ($fn -match "cortex|traps")                            { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Palo Alto Cortex";  RiskLevel="High" } }
    if ($fn -match "trendmicro|tmusa|tmcomm")                { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Trend Micro";       RiskLevel="High" } }
    if ($fn -match "symantec|symnets|srtsp")                 { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Symantec";          RiskLevel="High" } }
    if ($fn -match "mcafee|mfehidk|mfencbdc|trellix")       { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="McAfee/Trellix";    RiskLevel="High" } }
    if ($fn -match "sophos")                                  { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Sophos";            RiskLevel="High" } }
    if ($fn -match "forcepoint|dlpflt")                      { return [pscustomobject]@{ FilterName=$FilterName; Category="EDR/Security"; Vendor="Forcepoint";        RiskLevel="High" } }

    # Cloud Sync
    if ($fn -match "onedrive|cldflt|cldFlt")                 { return [pscustomobject]@{ FilterName=$FilterName; Category="CloudSync"; Vendor="Microsoft OneDrive"; RiskLevel="Medium" } }
    if ($fn -match "dropbox")                                 { return [pscustomobject]@{ FilterName=$FilterName; Category="CloudSync"; Vendor="Dropbox";           RiskLevel="Medium" } }
    if ($fn -match "googledrive|googledrivefs")               { return [pscustomobject]@{ FilterName=$FilterName; Category="CloudSync"; Vendor="Google Drive";      RiskLevel="Medium" } }
    if ($fn -match "boxsync|box_")                            { return [pscustomobject]@{ FilterName=$FilterName; Category="CloudSync"; Vendor="Box";               RiskLevel="Medium" } }
    if ($fn -match "sharefile")                               { return [pscustomobject]@{ FilterName=$FilterName; Category="CloudSync"; Vendor="Citrix ShareFile";  RiskLevel="Medium" } }

    # Backup
    if ($fn -match "veeam")                                   { return [pscustomobject]@{ FilterName=$FilterName; Category="Backup"; Vendor="Veeam";       RiskLevel="Medium" } }
    if ($fn -match "commvault|cvmflt")                        { return [pscustomobject]@{ FilterName=$FilterName; Category="Backup"; Vendor="Commvault";   RiskLevel="Medium" } }
    if ($fn -match "netbackup|nbflt")                         { return [pscustomobject]@{ FilterName=$FilterName; Category="Backup"; Vendor="NetBackup";   RiskLevel="Medium" } }
    if ($fn -match "acronis")                                  { return [pscustomobject]@{ FilterName=$FilterName; Category="Backup"; Vendor="Acronis";     RiskLevel="Medium" } }
    if ($fn -match "backup|backupflt")                        { return [pscustomobject]@{ FilterName=$FilterName; Category="Backup"; Vendor="Unknown";     RiskLevel="Medium" } }

    # VPN / Network
    if ($fn -match "pangps|pangpa|globalprotect")             { return [pscustomobject]@{ FilterName=$FilterName; Category="VPN/Network"; Vendor="Palo Alto GlobalProtect"; RiskLevel="Medium" } }
    if ($fn -match "ciscoamp|csamp")                          { return [pscustomobject]@{ FilterName=$FilterName; Category="VPN/Network"; Vendor="Cisco AMP";               RiskLevel="Medium" } }
    if ($fn -match "zscaler")                                  { return [pscustomobject]@{ FilterName=$FilterName; Category="VPN/Network"; Vendor="Zscaler";                 RiskLevel="Medium" } }

    # Filesystem / OS Core
    if ($fn -match "^ntfs$")                                  { return [pscustomobject]@{ FilterName=$FilterName; Category="Filesystem"; Vendor="Microsoft NTFS";          RiskLevel="Low" } }
    if ($fn -match "^refs$")                                  { return [pscustomobject]@{ FilterName=$FilterName; Category="Filesystem"; Vendor="Microsoft ReFS";          RiskLevel="Low" } }
    if ($fn -match "^fltmgr$")                                { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft FilterManager"; RiskLevel="Low" } }
    if ($fn -match "^luafv$")                                 { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft UAC Virt";      RiskLevel="Low" } }
    if ($fn -match "^wcifs$")                                 { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft WCI";           RiskLevel="Low" } }
    if ($fn -match "^bindflt$")                               { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft BindFlt";       RiskLevel="Low" } }
    if ($fn -match "^storqosflt$")                            { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft StorQoS";       RiskLevel="Low" } }
    if ($fn -match "^wof$")                                   { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft WOF";           RiskLevel="Low" } }
    if ($fn -match "^filecrypt$")                             { return [pscustomobject]@{ FilterName=$FilterName; Category="OS/Core";   Vendor="Microsoft BitLocker";     RiskLevel="Low" } }

    # Fallthrough
    return [pscustomobject]@{
        FilterName = $FilterName
        Category   = "Unknown/Third-Party"
        Vendor     = "Unknown"
        RiskLevel  = "Medium"
    }
}

function Score-RoutingConfidence {
    param(
        [string]$PathType,
        [pscustomobject]$EventSignals,
        [pscustomobject]$GpSignals,
        [string[]]$TopFilters,
        [pscustomobject]$A2Summary
    )
    $score = 0

    # Signal scoring
    if ($EventSignals -and $EventSignals.StorageTimeoutCount  -gt 0) { $score += 30 }
    if ($EventSignals -and $EventSignals.PowerHintCount       -gt 0) { $score += 20 }
    if ($EventSignals -and $EventSignals.Application1001Count -gt 0) { $score += 15 }

    # Filter classification scoring
    if ($TopFilters) {
        foreach ($f in @($TopFilters)) {
            $cls = Classify-FilterName $f
            if ($cls.Category -eq "EDR/Security")  { $score += 20; break }
        }
        foreach ($f in @($TopFilters)) {
            $cls = Classify-FilterName $f
            if ($cls.Category -eq "CloudSync")     { $score += 10; break }
        }
    }

    # Path type
    if ($PathType -eq "UNC") { $score += 5 }

    if ($score -gt 100) { $score = 100 }
    if ($score -lt 0)   { $score = 0 }
    return $score
}

function Compute-RoutingA4 {
    param(
        [string]$PathType,
        [pscustomobject]$EventSignals,
        [pscustomobject]$GpSignals,
        [string[]]$TopFilters,
        [pscustomobject]$A2Summary
    )

    $score  = Score-RoutingConfidence `
                -PathType      $PathType `
                -EventSignals  $EventSignals `
                -GpSignals     $GpSignals `
                -TopFilters    $TopFilters `
                -A2Summary     $A2Summary

    $confidence = if ($score -ge 70) { "High" } elseif ($score -ge 40) { "Medium" } else { "Low" }

    # Determine Queue
    $queue  = "General-Freeze / Endpoint"
    $reason = "Insufficient signals to determine specific cause"

    if ($PathType -eq "UNC") {
        $queue  = "VPN / Network / File Services"
        $reason = "Target path is UNC - SMB/VPN dependency likely"
    } elseif ($EventSignals -and $EventSignals.StorageTimeoutCount -gt 0) {
        $queue  = "Storage / Endpoint"
        $reason = ("Storage timeout events detected (IDs 129/153): {0}" -f $EventSignals.StorageTimeoutCount)
    } elseif ($EventSignals -and $EventSignals.PowerHintCount -gt 0) {
        $queue  = "Power / Platform / Endpoint"
        $reason = ("Power resume events detected (IDs 41/107/137): {0}" -f $EventSignals.PowerHintCount)
    } elseif ($EventSignals -and $EventSignals.Application1001Count -gt 0) {
        $queue  = "Application / Endpoint"
        $reason = ("Application hang/crash events detected (ID 1001): {0}" -f $EventSignals.Application1001Count)
    }

    # Classify all top filter suspects
    $suspects = @()
    if ($TopFilters) {
        foreach ($f in @($TopFilters | Select-Object -First 10)) {
            $suspects += Classify-FilterName $f
        }
    }

    # Override queue if EDR found and no storage signal
    $edrHit = @($suspects | Where-Object { $_.Category -eq "EDR/Security" })
    if ($edrHit.Count -gt 0 -and $EventSignals.StorageTimeoutCount -eq 0) {
        $queue  = "Security / EDR - Minifilter"
        $reason = $reason + ("; EDR/Security filter detected: {0}" -f ($edrHit[0].Vendor))
    }

    if ($suspects.Count -gt 0) {
        $topSuspectNames = @($suspects | Select-Object -First 3 | ForEach-Object { $_.FilterName })
        $reason = $reason + ("; Top suspect filters: {0}" -f ($topSuspectNames -join ", "))
    }

    return [pscustomobject]@{
        Queue      = $queue
        Confidence = $confidence
        Score      = $score
        Reason     = $reason
        Suspects   = $suspects
        Signals    = [pscustomobject]@{
            PathType             = $PathType
            StorageTimeoutCount  = if ($EventSignals) { $EventSignals.StorageTimeoutCount }  else { 0 }
            PowerHintCount       = if ($EventSignals) { $EventSignals.PowerHintCount }       else { 0 }
            Application1001Count = if ($EventSignals) { $EventSignals.Application1001Count } else { 0 }
            GPIsConnected        = if ($GpSignals)    { $GpSignals.IsConnected }             else { $false }
            SmbCount             = if ($GpSignals)    { $GpSignals.SmbCount }                else { 0 }
        }
    }
}

function Write-SuspectFiltersTxt {
    param([string]$Path, [pscustomobject]$Routing)
    $lines = @()
    $lines += "Suspect Filters Report (A4)"
    $lines += "---------------------------"
    $lines += ("Queue      : {0}" -f $Routing.Queue)
    $lines += ("Confidence : {0} ({1}/100)" -f $Routing.Confidence, $Routing.Score)
    $lines += ("Reason     : {0}" -f $Routing.Reason)
    $lines += ""
    if ($Routing.Suspects -and @($Routing.Suspects).Count -gt 0) {
        $lines += "Top Suspect Filters:"
        foreach ($s in @($Routing.Suspects | Select-Object -First 10)) {
            $lines += ("  - {0,-30} Category={1,-20} Vendor={2,-30} Risk={3}" -f
                       $s.FilterName, $s.Category, $s.Vendor, $s.RiskLevel)
        }
    } else {
        $lines += "  No suspect filters identified."
    }
    Write-Text -Path $Path -Content $lines
}

# ==============================================================================
# SECTION 8 - MAIN
# ==============================================================================

# Root and bundle folder
$RootDir = "C:\Temp\Process2Thread\FreezeDiscovery"
Ensure-Dir -Path $RootDir

$BundleTs   = Get-Date -Format "yyyyMMdd_HHmmss"
$BundlePath = Join-Path $RootDir ("Bundle_" + $BundleTs)
Ensure-Dir -Path $BundlePath

# ── System Info ─────────────────────────────────────────────────────────────
$sysInfo = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = $null
}
try {
    $sysInfo.OS = (Get-CimInstance Win32_OperatingSystem |
                   Select-Object Caption, Version, BuildNumber)
} catch { }
Write-JsonSafe -Path (Join-Path $BundlePath "SystemInfo.json") -Value $sysInfo

# ── Target Context ───────────────────────────────────────────────────────────
$PathType = "None"
if ($TargetPath) {
    if ($TargetPath -like "\\*")              { $PathType = "UNC" }
    elseif ($TargetPath -match "^[A-Za-z]:") { $PathType = "Local" }
}
$targetContext = [pscustomobject]@{
    TargetPath = $TargetPath
    PathType   = $PathType
}
Write-JsonSafe -Path (Join-Path $BundlePath "TargetContext.json") -Value $targetContext

# ── A3: Event + GP Signals ───────────────────────────────────────────────────
Write-Verbose "Collecting event signals..."
$eventSignals = Get-EventSignals -LookbackHours 48
Write-JsonSafe -Path (Join-Path $BundlePath "EventSignals.json") -Value $eventSignals

# Export merged events CSV
$eventsForCsv = @($eventSignals.Events)
if ($eventsForCsv.Count -eq 0) {
    $eventsForCsv = @([pscustomobject]@{
        LogName          = $null
        TimeCreated      = $null
        Id               = $null
        Source           = $null
        LevelDisplayName = $null
        Message          = $null
    })
}
$eventsForCsv | Export-Csv -Path (Join-Path $BundlePath "SystemEvents_48h.csv") `
    -NoTypeInformation -Encoding UTF8 -Force

Write-Verbose "Collecting GlobalProtect signals..."
$gpSignals = Get-GlobalProtectSignals
Write-JsonSafe -Path (Join-Path $BundlePath "GlobalProtectSignals.json") -Value $gpSignals

# ── FLTMC Capture → A2 (guaranteed artifacts) ────────────────────────────────
$miniFilters         = @()
$miniInstancesMapped = @()
$A2                  = $null

try {
    Write-Verbose "Running fltmc filters..."
    $rawFilters   = Get-FltmcRaw -Mode "filters"
    Write-Verbose "Running fltmc instances..."
    $rawInstances = Get-FltmcRaw -Mode "instances"

    $rawFilters   | Out-File (Join-Path $BundlePath "fltmc_filters_raw.txt")   -Encoding UTF8 -Force
    $rawInstances | Out-File (Join-Path $BundlePath "fltmc_instances_raw.txt") -Encoding UTF8 -Force

    $miniFilters   = @(Parse-FltmcFilters   -Lines $rawFilters)
    $miniInstances = @(Parse-FltmcInstances -Lines $rawInstances)

    Write-Verbose "Mapping volumes..."
    $volumeMap = Get-VolumeMap
    Write-JsonSafe -Path (Join-Path $BundlePath "VolumeMap.json") -Value $volumeMap

    if ($miniInstances.Count -gt 0 -and $volumeMap.Count -gt 0) {
        $miniInstancesMapped = @(Map-FltmcInstances -Instances $miniInstances -VolumeMap $volumeMap)
    } else {
        $miniInstancesMapped = @($miniInstances)
    }

    Write-JsonSafe -Path (Join-Path $BundlePath "MiniFilters.json")         -Value $miniFilters
    Write-JsonSafe -Path (Join-Path $BundlePath "MiniFilterInstances.json") -Value $miniInstancesMapped

} catch {
    $errMsg = $_.Exception.Message
    Write-Text -Path (Join-Path $BundlePath "MiniFilter_WARNING.txt") -Content @(
        "MiniFilter capture encountered an error.",
        ("Error   : {0}" -f $errMsg),
        "Action  : Run PowerShell as Administrator and retry.",
        "Impact  : A2 volume correlation may be incomplete."
    )
    Write-JsonSafe -Path (Join-Path $BundlePath "MiniFilters.json")         -Value $miniFilters
    Write-JsonSafe -Path (Join-Path $BundlePath "MiniFilterInstances.json") -Value $miniInstancesMapped
} finally {
    # GUARANTEED: A2 artifacts always written regardless of errors above
    try {
        $A2 = Write-FiltersOnTargetVolumeArtifacts `
                -BundlePath          $BundlePath `
                -TargetPath          $TargetPath `
                -MiniFilters         $miniFilters `
                -MiniInstancesMapped $miniInstancesMapped
    } catch {
        $a2Err = $_.Exception.Message
        Write-Text -Path (Join-Path $BundlePath "FiltersOnTargetVolume.txt") -Content @(
            "FiltersOnTargetVolume Summary",
            "-----------------------------",
            ("TargetPath : {0}" -f $(if ($TargetPath) { $TargetPath } else { "<not provided>" })),
            "Result     : A2 summary could not be generated.",
            ("Error      : {0}" -f $a2Err)
        )
        Write-JsonSafe -Path (Join-Path $BundlePath "FiltersOnTargetVolume.json") -Value $null
        $A2 = [pscustomobject]@{
            TargetDrive = $null
            Lines       = @()
            TopFilters  = @()
            Summary     = $null
        }
    }
}

# ── A4: Routing ───────────────────────────────────────────────────────────────
$topFilters = @()
if ($A2 -and $A2.TopFilters) { $topFilters = @($A2.TopFilters) }

$routing = Compute-RoutingA4 `
    -PathType     $PathType `
    -EventSignals $eventSignals `
    -GpSignals    $gpSignals `
    -TopFilters   $topFilters `
    -A2Summary    $A2.Summary

Write-JsonSafe  -Path (Join-Path $BundlePath "RoutingA4.json")            -Value $routing
Write-SuspectFiltersTxt -Path (Join-Path $BundlePath "SuspectFilters.txt") -Routing $routing
Write-JsonSafe  -Path (Join-Path $BundlePath "FilterClassification.json") -Value $routing.Suspects

# ── Summary_Human.txt ─────────────────────────────────────────────────────────
$humanLines = @(
    "FreezeDiscovery V8 - Human Summary",
    "-----------------------------------",
    ("Case        : {0}" -f $(if ($CaseId) { $CaseId } else { "<not provided>" })),
    ("Computer    : {0}" -f $sysInfo.ComputerName),
    ("User        : {0}" -f $sysInfo.UserName),
    ("Generated   : {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss")),
    "",
    ("TargetPath  : {0}" -f $(if ($TargetPath) { $TargetPath } else { "<not provided>" })),
    ("PathType    : {0}" -f $PathType),
    "",
    "═══ A3 — Event Signals (last 48h) ═══",
    ("  Storage Timeouts (129/153) : {0}" -f $eventSignals.StorageTimeoutCount),
    ("  Power Hints     (41/107/137): {0}" -f $eventSignals.PowerHintCount),
    ("  App Crashes     (1001)      : {0}" -f $eventSignals.Application1001Count),
    "",
    "═══ GlobalProtect ═══",
    ("  Service Running : {0}" -f $gpSignals.IsRunning),
    ("  Adapter Up      : {0}" -f $gpSignals.AdapterUp),
    ("  SMB Connections : {0}" -f $gpSignals.SmbCount),
    "",
    "═══ A4 — Routing ═══",
    ("  Queue      : {0}" -f $routing.Queue),
    ("  Confidence : {0} ({1}/100)" -f $routing.Confidence, $routing.Score),
    ("  Reason     : {0}" -f $routing.Reason)
)
if ($A2 -and @($A2.Lines).Count -gt 0) {
    $humanLines += ""
    $humanLines += "═══ A2 — Filters on Target Volume ═══"
    $humanLines += @($A2.Lines)
}
if ($routing.Suspects -and @($routing.Suspects).Count -gt 0) {
    $humanLines += ""
    $humanLines += "═══ Suspect Filter Classification ═══"
    foreach ($s in @($routing.Suspects | Select-Object -First 10)) {
        $humanLines += ("  - {0,-30} {1,-20} {2,-30} Risk={3}" -f
                        $s.FilterName, $s.Category, $s.Vendor, $s.RiskLevel)
    }
}
Write-Text -Path (Join-Path $BundlePath "Summary_Human.txt") -Content $humanLines

# ── TicketSummary.txt ─────────────────────────────────────────────────────────
$ticketLines = @(
    "TICKET SUMMARY — FreezeDiscovery V8",
    "=====================================",
    ("Case       : {0}" -f $(if ($CaseId) { $CaseId } else { "<not provided>" })),
    "",
    "── COPY / PASTE INTO TICKET ──",
    "",
    "Freeze / hang observed on endpoint.",
    ("TargetPath  : {0}" -f $(if ($TargetPath) { $TargetPath } else { "<not provided>" })),
    ("PathType    : {0}" -f $PathType),
    "",
    "Event Signals (last 48h):",
    ("  - Storage Timeout events (129/153) : {0}" -f $eventSignals.StorageTimeoutCount),
    ("  - Power Hint events (41/107/137)   : {0}" -f $eventSignals.PowerHintCount),
    ("  - App Crash/Hang events (1001)     : {0}" -f $eventSignals.Application1001Count),
    "",
    ("Routing Queue : {0}" -f $routing.Queue),
    ("Confidence    : {0} ({1}/100)" -f $routing.Confidence, $routing.Score),
    ("Reason        : {0}" -f $routing.Reason),
    "",
    "── ATTACHMENTS ──",
    "  SystemInfo.json",
    "  TargetContext.json",
    "  EventSignals.json",
    "  SystemEvents_48h.csv",
    "  GlobalProtectSignals.json",
    "  fltmc_filters_raw.txt",
    "  fltmc_instances_raw.txt",
    "  MiniFilters.json",
    "  MiniFilterInstances.json",
    "  VolumeMap.json",
    "  FiltersOnTargetVolume.txt",
    "  FiltersOnTargetVolume.json",
    "  RoutingA4.json",
    "  SuspectFilters.txt",
    "  FilterClassification.json",
    "  Summary_Human.txt",
    "  TicketSummary.txt"
)
if ($A2 -and @($A2.Lines).Count -gt 0) {
    $ticketLines += ""
    $ticketLines += @($A2.Lines)
}
if ($routing.Suspects -and @($routing.Suspects).Count -gt 0) {
    $ticketLines += ""
    $ticketLines += "Suspect Filters (Top 5):"
    foreach ($s in @($routing.Suspects | Select-Object -First 5)) {
        $ticketLines += ("  - {0} :: {1} [{2}] Risk={3}" -f
                         $s.FilterName, $s.Category, $s.Vendor, $s.RiskLevel)
    }
}
Write-Text -Path (Join-Path $BundlePath "TicketSummary.txt") -Content $ticketLines

# ── Zip Bundle ────────────────────────────────────────────────────────────────
$zipPath = "$BundlePath.zip"
if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
Compress-Archive -Path (Join-Path $BundlePath "*") -DestinationPath $zipPath -Force

# ── Final Output ─────────────────────────────────────────────────────────────
Write-Output ""
Write-Output "══════════════════════════════════════════════"
Write-Output " FreezeDiscovery V8 - Complete"
Write-Output "══════════════════════════════════════════════"
Write-Output ("Bundle Folder : {0}" -f $BundlePath)
Write-Output ("Bundle ZIP    : {0}" -f $zipPath)
Write-Output ("Routing       : {0}" -f $routing.Queue)
Write-Output ("Confidence    : {0} ({1}/100)" -f $routing.Confidence, $routing.Score)
Write-Output ("Reason        : {0}" -f $routing.Reason)
Write-Output "══════════════════════════════════════════════"
