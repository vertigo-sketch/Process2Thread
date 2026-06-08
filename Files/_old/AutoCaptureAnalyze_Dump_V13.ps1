<#
AutoCaptureAnalyze_Dump.ps1
Version: 13

Change History:
- V13 (2026-03-25)
  * FIX: Renamed all $Pid/$pid variables/parameters to avoid collision with read-only $PID
  * Kept V12 defensive snapshot + batch sampling + threadstate-only freeze detection
- V12
  * Defensive property access; global trap; progress logging
- V11
  * ThreadState-only detection; batch sampling

Purpose:
- Monitor all processes
- Trigger dump+analyze on:
    1) UI hang (Responding=false on windowed processes)
    2) Frozen/suspended background app (CPU flat + high % threads waiting)
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds   = 5,
    [double]$CpuDeltaThreshold     = 0.01,
    [int]$WaitingThreadPercent     = 80,   # % of threads in ThreadState=5
    [int]$CooldownSeconds          = 600,  # Per-process dump cooldown
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile           = 'Mini'
)

# ==============================
# Resolve script root (ISE-safe)
# ==============================
if ($PSScriptRoot) {
    $ScriptRoot = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $ScriptRoot = (Get-Location).Path
}

$DumpRoot = Join-Path $ScriptRoot "Dumps"
$LogRoot  = Join-Path $ScriptRoot "Logs"
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

$LogPath = Join-Path $LogRoot "AutoCapture.log"

# ==============================
# Tool paths
# ==============================
$ProcDumpPath = "C:\Tools\Sysinternals\procdump.exe"
$CdbPath      = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump: $ProcDumpPath" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe: $CdbPath" }

# ==============================
# Logging
# ==============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Message" | Out-File -Encoding UTF8 -Append $LogPath
}

# Global trap so we always see why it stopped
trap {
    Write-Log ("FATAL: {0}" -f $_.Exception.Message)
    Write-Log ("FATAL: {0}" -f $_.ScriptStackTrace)
    break
}

Write-Log "=== AutoCapture V13 START ==="
Write-Log "ScriptRoot=$ScriptRoot"
Write-Log "ObservationWindowSeconds=$ObservationWindowSeconds MonitorIntervalSeconds=$MonitorIntervalSeconds"
Write-Log "CpuDeltaThreshold=$CpuDeltaThreshold WaitingThreadPercent=$WaitingThreadPercent CooldownSeconds=$CooldownSeconds DumpProfile=$DumpProfile"

# ==============================
# Safe process snapshot helpers
# ==============================
function Get-SafeProcSnapshot {
    param([System.Diagnostics.Process]$Proc)

    $procId = $null
    $procName = $null
    try { $procId = [int]$Proc.Id } catch { return $null }
    try { $procName = [string]$Proc.Name } catch { $procName = "Unknown" }

    $cpu = 0.0
    $mwh = 0
    $resp = $null

    try { $cpu = [double]$Proc.CPU } catch { $cpu = 0.0 }
    try { $mwh = [int64]$Proc.MainWindowHandle } catch { $mwh = 0 }

    # Only ask Responding if there is a window handle; still guard it.
    if ($mwh -ne 0) {
        try { $resp = [bool]$Proc.Responding } catch { $resp = $null }
    }

    return [PSCustomObject]@{
        ProcId          = $procId
        Name            = $procName
        CPU             = $cpu
        MainWindowHandle= $mwh
        Responding      = $resp
    }
}

# ==============================
# Thread summary (SAFE)
# ==============================
function Get-ThreadSummary {
    param([int]$TargetProcId)

    try {
        $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$TargetProcId" -ErrorAction Stop
    } catch {
        return $null
    }

    if (-not $threads) { return $null }

    $total = $threads.Count
    if ($total -le 0) { return $null }

    $waiting = ($threads | Where-Object { $_.ThreadState -eq 5 }).Count

    [PSCustomObject]@{
        TotalThreads   = $total
        WaitingThreads = $waiting
        WaitingPercent = [math]::Round(($waiting / $total) * 100, 2)
    }
}

# ==============================
# Dump + Analyze
# ==============================
function Capture-Dump {
    param(
        [int]$TargetProcId,
        [string]$ProcName
    )

    $stamp    = Get-Date -Format yyyyMMdd_HHmmss
    $dumpPath = Join-Path $DumpRoot ("{0}_{1}_{2}.dmp" -f $ProcName, $TargetProcId, $stamp)

    $switch = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    Write-Log "Dumping Name=$ProcName ProcId=$TargetProcId Profile=$DumpProfile Path=$dumpPath"

    $proc = Start-Process -FilePath $ProcDumpPath `
        -ArgumentList "-accepteula $switch $TargetProcId `"$dumpPath`"" `
        -WindowStyle Hidden -PassThru

    $ok = $proc.WaitForExit(60000)
    if (-not $ok) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
        throw "ProcDump timeout for ProcId=$TargetProcId"
    }

    if (-not (Test-Path $dumpPath)) {
        throw "Dump not created for ProcId=$TargetProcId"
    }

    return $dumpPath
}

function Analyze-Dump {
    param([string]$DumpPath)

    $log = [IO.Path]::ChangeExtension($DumpPath, ".cdb.log")
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'

    Write-Log "Analyzing Dump=$DumpPath Log=$log"

    $proc = Start-Process -FilePath $CdbPath `
        -ArgumentList "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" `
        -WindowStyle Hidden -PassThru

    $ok = $proc.WaitForExit(180000)
    if (-not $ok) {
        try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
        Write-Log "WARN: cdb timeout; killed. Dump=$DumpPath"
    }

    return $log
}

# ==============================
# Cooldown tracking
# ==============================
$LastCapture = @{}

function In-Cooldown {
    param([int]$TargetProcId)

    if ($LastCapture.ContainsKey($TargetProcId)) {
        return (((Get-Date) - $LastCapture[$TargetProcId]).TotalSeconds -lt $CooldownSeconds)
    }
    return $false
}

# ==============================
# Main loop (BATCHED, DEFENSIVE)
# ==============================
while ($true) {
    $passStart = Get-Date
    Write-Log ("PASS START {0}" -f $passStart.ToString("HH:mm:ss"))

    # Snapshot A
    $snapA = @{}

    $procsA = @()
    try { $procsA = Get-Process -ErrorAction Stop } catch {
        Write-Log "ERROR: Get-Process(A) failed: $($_.Exception.Message)"
        Start-Sleep $MonitorIntervalSeconds
        continue
    }

    foreach ($p in $procsA) {
        $s = Get-SafeProcSnapshot -Proc $p
        if ($s -eq $null) { continue }
        $snapA[$s.ProcId] = $s
    }
    Write-Log ("SnapshotA complete. Count={0}" -f $snapA.Count)

    Write-Log ("Sleep begin {0}s" -f $ObservationWindowSeconds)
    Start-Sleep -Seconds $ObservationWindowSeconds
    Write-Log "Sleep end"

    # Snapshot B + compare
    $procsB = @()
    try { $procsB = Get-Process -ErrorAction Stop } catch {
        Write-Log "ERROR: Get-Process(B) failed: $($_.Exception.Message)"
        Start-Sleep $MonitorIntervalSeconds
        continue
    }

    $checked = 0
    foreach ($p in $procsB) {
        $b = Get-SafeProcSnapshot -Proc $p
        if ($b -eq $null) { continue }
        if (-not $snapA.ContainsKey($b.ProcId)) { continue }
        if (In-Cooldown -TargetProcId $b.ProcId) { continue }

        $a = $snapA[$b.ProcId]
        $checked++

        $cpuDelta = [double]$b.CPU - [double]$a.CPU

        # Trigger 1: UI Hang
        $uiHang = $false
        if ($b.MainWindowHandle -ne 0 -and $b.Responding -ne $null) {
            $uiHang = (-not $b.Responding)
        }

        # Trigger 2: Suspended/Frozen (PsSuspend) — CPU flat + threads waiting %
        $suspendFreeze = $false
        $threadSummary = $null

        if (-not $uiHang -and $cpuDelta -lt $CpuDeltaThreshold) {
            $threadSummary = Get-ThreadSummary -TargetProcId $b.ProcId
            if ($threadSummary -and $threadSummary.WaitingPercent -ge $WaitingThreadPercent) {
                $suspendFreeze = $true
            }
        }

        if ($uiHang -or $suspendFreeze) {
            Write-Log ("TRIGGER Name={0} ProcId={1} CPUΔ={2} UIHang={3} SuspFreeze={4} MWH={5} Resp={6}" -f `
                $b.Name, $b.ProcId, ([math]::Round($cpuDelta,4)), $uiHang, $suspendFreeze, $b.MainWindowHandle, $b.Responding)

            if ($threadSummary) {
                Write-Log ("THREADS Total={0} Waiting%={1}" -f $threadSummary.TotalThreads, $threadSummary.WaitingPercent)
            }

            try {
                $LastCapture[$b.ProcId] = Get-Date
                $dump = Capture-Dump -TargetProcId $b.ProcId -ProcName $b.Name
                $cdb  = Analyze-Dump -DumpPath $dump
                Write-Log ("CAPTURE COMPLETE Dump={0} CdbLog={1}" -f $dump, $cdb)
            } catch {
                Write-Log ("ERROR Capture/Analyze Name={0} ProcId={1}: {2}" -f $b.Name, $b.ProcId, $_.Exception.Message)
            }
        }
    }

    Write-Log ("SnapshotB compare complete. Checked={0}" -f $checked)

    $passEnd = Get-Date
    Write-Log ("PASS END {0} (duration {1}s)" -f $passEnd.ToString("HH:mm:ss"), [math]::Round(($passEnd-$passStart).TotalSeconds,1))

    Start-Sleep -Seconds $MonitorIntervalSeconds
}