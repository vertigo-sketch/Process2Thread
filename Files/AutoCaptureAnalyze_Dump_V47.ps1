<# =====================================================================
 AutoCaptureAnalyze_Dump_V47.ps1
 Tier‑B Hang Analysis (PIDSAFE)
 ===================================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===============================
# CONFIG
# ===============================
$ObservationWindowSeconds = 15
$CooldownSeconds = 300

$ScriptRoot = $PSScriptRoot
$OutputRoot = Join-Path $ScriptRoot "TierB_Output"
$DumpRoot   = Join-Path $OutputRoot "Dumps"
$LogPath    = Join-Path $OutputRoot "AutoCapture.log"

New-Item -ItemType Directory -Path $DumpRoot -Force | Out-Null

# ===============================
# LOGGING
# ===============================
function Write-Log {
    param([string]$Message)
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

# ===============================
# PROCESS SNAPSHOT
# ===============================
function Get-ProcessSnapshot {
    $snap = @{}
    foreach ($p in Get-Process -ErrorAction SilentlyContinue) {
        $snap[$p.Id] = @{
            Name       = $p.ProcessName
            CPU        = $p.CPU
            Threads    = $p.Threads.Count
            Responding = $p.Responding
        }
    }
    return $snap
}

# ===============================
# UI HANG DETECTION
# ===============================
function Test-UIHang {
    param($Before, $After)

    if (-not $After.Responding -and
        $After.Threads -ge $Before.Threads -and
        ($After.CPU - $Before.CPU) -lt 0.1) {
        return $true
    }
    return $false
}

# ===============================
# COOLDOWN LOGIC
# ===============================
$global:CooldownTable = @{}

function In-Cooldown {
    param([int]$ProcId)
    return ($global:CooldownTable.ContainsKey($ProcId) -and
            (Get-Date) -lt $global:CooldownTable[$ProcId])
}

function Mark-Captured {
    param([int]$ProcId)
    $global:CooldownTable[$ProcId] = (Get-Date).AddSeconds($CooldownSeconds)
}

# ===============================
# DUMP CAPTURE
# ===============================
function Invoke-ProcDump {
    param(
        [int]$TargetProcId,
        [string]$DumpPath
    )

    & procdump.exe -accepteula -ma -h $TargetProcId $DumpPath 1>$null 2>$null
    return (Test-Path $DumpPath)
}

# ===============================
# CDB ANALYSIS
# ===============================
function Invoke-Cdb {
    param(
        [string]$DumpPath,
        [string]$OutPath
    )

    $cmds = @"
.symfix
.reload
~*
~* kb
~* e !teb
q
"@

    $cmdLine = $cmds -replace "`r?`n", ";"
    & cdb.exe -z $DumpPath -c $cmdLine > $OutPath 2>&1
}

# ===============================
# TIER‑B PARSING
# ===============================
function Parse-CdbThreads {
    param([string]$Path)

    $threads = @{}
    $currentTid = $null
    $stack = @()

    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*\.\s*(\d+)\s+Id:') {
            if ($currentTid -ne $null) { $threads[$currentTid] = $stack }
            $currentTid = [int]$Matches[1]
            $stack = @()
        }
        elseif ($currentTid -ne $null -and $line -match 'ntdll!') {
            $stack += $line.Trim()
        }
    }

    if ($currentTid -ne $null) { $threads[$currentTid] = $stack }
    return $threads
}

function Get-WaitInfo {
    param([string[]]$Stack)

    foreach ($frame in $Stack) {
        if ($frame -match 'ntdll!(Nt[A-Za-z]+)') {
            $sys = $Matches[1]
            $class = switch -Regex ($sys) {
                'Nt(Read|Write|Create)File' { 'FileIO' }
                'NtDeviceIoControlFile'     { 'DeviceIO' }
                'NtWait'                    { 'ExecutiveWait' }
                'NtDelayExecution'          { 'Scheduler' }
                default                     { 'Other' }
            }
            return @{ Wait=$sys; Class=$class }
        }
    }
    return $null
}

function Get-MinifilterSnapshot {
    return (fltmc 2>$null | Select-Object -Skip 1)
}

function Build-TierBReport {
    param($Threads, $Filters)

    $total = $Threads.Count
    $blocked = 0
    $waitMap = @{}
    $fileIOSeen = $false

    foreach ($t in $Threads.Keys) {
        $info = Get-WaitInfo $Threads[$t]
        if ($info) {
            $blocked++
            if (-not $waitMap.ContainsKey($info.Wait)) {
                $waitMap[$info.Wait] = 0
            }
            $waitMap[$info.Wait]++
            if ($info.Class -eq 'FileIO') { $fileIOSeen = $true }
        }
    }

    $top = $waitMap.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1

    $score = 0
    if ($blocked / [double]$total -ge 0.5) { $score += 20 }
    if ($blocked -gt 0 -and $top.Value / [double]$blocked -ge 0.6) { $score += 20 }
    if ($fileIOSeen) { $score += 15 }
    if ($Filters.Count -gt 0) { $score += 10 }

    return @{
        TotalThreads    = $total
        BlockedThreads  = $blocked
        TopWait         = $top.Key
        TopWaitCount    = $top.Value
        Minifilters     = $Filters.Count
        ConfidenceScore = $score
    }
}

# ===============================
# MAIN LOOP
# ===============================
Write-Log "=== AutoCaptureAnalyze_Dump_V47 START (Tier‑B, PIDSAFE) ==="

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($ProcId in $before.Keys) {

        if (-not $after.ContainsKey($ProcId)) { continue }
        if (In-Cooldown $ProcId) { continue }

        if (Test-UIHang $before[$ProcId] $after[$ProcId]) {

            Write-Log "UIHANG DETECTED ProcId=$ProcId ($($before[$ProcId].Name))"
            $ts = Get-Date -Format yyyyMMdd_HHmmss

            $dumpPath = Join-Path $DumpRoot "UIHang_${ProcId}_$ts.dmp"
            $cdbPath  = Join-Path $DumpRoot "UIHang_${ProcId}_$ts.cdb.log"

            if (Invoke-ProcDump -TargetProcId $ProcId -DumpPath $dumpPath) {

                Invoke-Cdb -DumpPath $dumpPath -OutPath $cdbPath

                $threads = Parse-CdbThreads $cdbPath
                $filters = Get-MinifilterSnapshot
                $tierB   = Build-TierBReport -Threads $threads -Filters $filters

                Write-Log "TIERB Threads=$($tierB.BlockedThreads)/$($tierB.TotalThreads)"
                Write-Log "TIERB TopWait=$($tierB.TopWait) Count=$($tierB.TopWaitCount)"
                Write-Log "TIERB Minifilters=$($tierB.Minifilters)"
                Write-Log "TIERB Confidence=$($tierB.ConfidenceScore)"
                Write-Log "TIERB KernelEvidence=UNAVAILABLE (policy‑restricted)"

                Mark-Captured $ProcId
            }
        }
    }

} while ($true)

Write-Log "=== AutoCapture V44 END ==="