<# =====================================================================
 AutoCaptureAnalyze_Dump_V46.ps1
 Tier‑B (Dump‑Centric) Evidence Collection
 ===================================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===============================
# CONFIGURATION
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
    param([Parameter(Mandatory)][string]$Message)

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
# UI HANG HEURISTIC
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
# COOLDOWN TRACKING
# ===============================

$global:Cooldown = @{}

function In-Cooldown {
    param([int]$Pid)

    if ($global:Cooldown.ContainsKey($Pid)) {
        if ((Get-Date) -lt $global:Cooldown[$Pid]) {
            return $true
        }
    }
    return $false
}

function Mark-Captured {
    param([int]$Pid)
    $global:Cooldown[$Pid] = (Get-Date).AddSeconds($CooldownSeconds)
}

# ===============================
# PROC DUMP
# ===============================

function Invoke-ProcDump {
    param(
        [Parameter(Mandatory)][int]$TargetProcId,
        [Parameter(Mandatory)][string]$DumpPath
    )

    $exe = "procdump.exe"
    & $exe -accepteula -ma -h $TargetProcId $DumpPath 1>$null 2>$null
    return (Test-Path $DumpPath)
}

# ===============================
# CDB INVOCATION
# ===============================

function Invoke-Cdb {
    param(
        [Parameter(Mandatory)][string]$DumpPath,
        [Parameter(Mandatory)][string]$OutPath
    )

    $cmds = @"
.symfix
.reload
~*
~* kb
~* e !teb
q
"@

    $cdb = "cdb.exe"
    $cmdLine = $cmds -replace "`r?`n", ";"
    & $cdb -z $DumpPath -c $cmdLine > $OutPath 2>&1
}

# ===============================
# TIER‑B PARSING
# ===============================

function Parse-CdbThreads {
    param([string]$Path)

    $threads = @{}
    $current = $null
    $stack   = @()

    foreach ($line in Get-Content $Path) {
        if ($line -match '^\s*\.\s*(\d+)\s+Id:') {
            if ($current -ne $null) {
                $threads[$current] = $stack
            }
            $current = [int]$Matches[1]
            $stack = @()
        }
        elseif ($current -ne $null -and $line -match 'ntdll!') {
            $stack += $line.Trim()
        }
    }

    if ($current -ne $null) {
        $threads[$current] = $stack
    }

    return $threads
}

function Get-WaitInfo {
    param([string[]]$Stack)

    foreach ($f in $Stack) {
        if ($f -match 'ntdll!(Nt[A-Za-z]+)') {
            $sys = $Matches[1]
            $class = switch -Regex ($sys) {
                'Nt(Read|Write|Create)File' { 'FileIO' }
                'NtDeviceIoControlFile'     { 'DeviceIO' }
                'NtWait'                    { 'ExecutiveWait' }
                'NtDelayExecution'          { 'Scheduler' }
                default                     { 'Other' }
            }
            return @{ Wait = $sys; Class = $class }
        }
    }
    return $null
}

# ===============================
# MINIFILTER SNAPSHOT
# ===============================

function Get-MinifilterSnapshot {
    $filters = fltmc 2>$null
    return ($filters | Select-Object -Skip 1)
}

# ===============================
# TIER‑B AGGREGATION
# ===============================

function Build-TierBReport {
    param(
        [hashtable]$Threads,
        [string[]]$Filters
    )

    $total = $Threads.Count
    $blocked = 0
    $waits = @{}
    $fileIO = $false

    foreach ($t in $Threads.Keys) {
        $info = Get-WaitInfo $Threads[$t]
        if ($info) {
            $blocked++
            if (-not $waits.ContainsKey($info.Wait)) {
                $waits[$info.Wait] = 0
            }
            $waits[$info.Wait]++
            if ($info.Class -eq 'FileIO') { $fileIO = $true }
        }
    }

    $top = $waits.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1

    $score = 0
    if ($blocked / [double]$total -ge 0.5) { $score += 20 }
    if ($blocked -gt 0 -and $top.Value / [double]$blocked -ge 0.6) { $score += 20 }
    if ($fileIO) { $score += 15 }
    if ($Filters.Count -gt 0) { $score += 10 }

    return @{
        TotalThreads     = $total
        BlockedThreads   = $blocked
        TopWait          = $top.Key
        TopWaitCount     = $top.Value
        MinifilterCount  = $Filters.Count
        ConfidenceScore  = $score
    }
}

# ===============================
# MAIN LOOP
# ===============================

Write-Log "=== AutoCaptureAnalyze_Dump_V46 START (Tier‑B) ==="

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($pid in $before.Keys) {

        if (-not $after.ContainsKey($pid)) { continue }
        if (In-Cooldown $pid) { continue }

        if (Test-UIHang $before[$pid] $after[$pid]) {

            Write-Log "UIHANG DETECTED PID=$pid ($($before[$pid].Name))"
            $ts = Get-Date -Format yyyyMMdd_HHmmss

            $dumpPath = Join-Path $DumpRoot "UIHang_${pid}_$ts.dmp"
            $cdbPath  = Join-Path $DumpRoot "UIHang_${pid}_$ts.cdb.log"

            if (Invoke-ProcDump -TargetProcId $pid -DumpPath $dumpPath) {
                Invoke-Cdb -DumpPath $dumpPath -OutPath $cdbPath

                $threads = Parse-CdbThreads $cdbPath
                $filters = Get-MinifilterSnapshot
                $tierB   = Build-TierBReport -Threads $threads -Filters $filters

                Write-Log "TIERB Threads=$($tierB.BlockedThreads)/$($tierB.TotalThreads)"
                Write-Log "TIERB TopWait=$($tierB.TopWait) Count=$($tierB.TopWaitCount)"
                Write-Log "TIERB Minifilters=$($tierB.MinifilterCount)"
                Write-Log "TIERB ConfidenceScore=$($tierB.ConfidenceScore)"
                Write-Log "TIERB KernelEvidence=UNAVAILABLE (policy-restricted)"

                Mark-Captured $pid
            }
        }
    }

} while ($true)
``

Write-Log "=== AutoCapture V44 END ==="