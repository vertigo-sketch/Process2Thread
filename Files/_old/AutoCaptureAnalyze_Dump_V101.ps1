<#
AutoCaptureAnalyze_Dump.ps1
Version: 11

Change History:
- V11 (2026-03-25)
  * Fixed crash caused by Win32_Thread missing WaitReason
  * Rewrote suspended-freeze detection to use ThreadState only (PS 5.1 safe)
  * Full script rewrite per instruction
- V10
  * Batch sampling redesign (snapshot A -> sleep -> snapshot B)
- V09-
  * Earlier iterations (superseded)

Purpose:
- Monitor all processes
- Detect either:
    1) UI hangs (non-responding windows)
    2) PsSuspend / frozen background processes
- Automatically capture dump and analyze with cdb
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds   = 5,
    [double]$CpuDeltaThreshold     = 0.01,
    [int]$WaitingThreadPercent     = 80,   # % of threads in ThreadState=5
    [int]$CooldownSeconds          = 600,  # Per-PID dump cooldown
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
$ProcDumpPath = "C:\Tools\procdump.exe"
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

Write-Log "=== AutoCapture V11 START ==="
Write-Log "ScriptRoot=$ScriptRoot"
Write-Log "ObservationWindowSeconds=$ObservationWindowSeconds"

# ==============================
# Thread analysis (SAFE)
# ==============================
function Get-ThreadSummary {
    param([int]$Pid)

    try {
        $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$Pid"
    } catch {
        return $null
    }

    if (-not $threads) { return $null }

    $total   = $threads.Count
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
    param($Pid, $Name)

    $stamp    = Get-Date -Format yyyyMMdd_HHmmss
    $dumpPath = Join-Path $DumpRoot "$Name`_$Pid`_$stamp.dmp"

    $switch = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    Write-Log "Dumping $Name PID=$Pid"

    $proc = Start-Process `
        -FilePath $ProcDumpPath `
        -ArgumentList "-accepteula $switch $Pid `"$dumpPath`"" `
        -WindowStyle Hidden `
        -PassThru

    $proc.WaitForExit(60000) | Out-Null

    if (-not (Test-Path $dumpPath)) {
        throw "Dump not created for PID=$Pid"
    }

    return $dumpPath
}

function Analyze-Dump {
    param($DumpPath)

    $log = [IO.Path]::ChangeExtension($DumpPath, ".cdb.log")

    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'

    Write-Log "Analyzing $DumpPath"

    $proc = Start-Process `
        -FilePath $CdbPath `
        -ArgumentList "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" `
        -WindowStyle Hidden `
        -PassThru

    $proc.WaitForExit(180000) | Out-Null
}

# ==============================
# Cooldown tracking
# ==============================
$LastCapture = @{}

function In-Cooldown($Pid) {
    if ($LastCapture[$Pid]) {
        ((Get-Date) - $LastCapture[$Pid]).TotalSeconds -lt $CooldownSeconds
    } else {
        $false
    }
}

# ==============================
# Main loop (BATCHED)
# ==============================
while ($true) {
    Write-Log "PASS START"

    $snapA = @{}
    foreach ($p in Get-Process) {
        $snapA[$p.Id] = @{
            Name       = $p.Name
            CPU        = [double]$p.CPU
            Handle     = $p.MainWindowHandle
            Responding = $p.Responding
        }
    }

    Start-Sleep $ObservationWindowSeconds

    foreach ($p in Get-Process) {
        if (-not $snapA.ContainsKey($p.Id)) { continue }
        if (In-Cooldown $p.Id) { continue }

        $a = $snapA[$p.Id]
        $cpuDelta = [double]$p.CPU - [double]$a.CPU

        # Trigger 1: UI Hang
        $uiHang = ($p.MainWindowHandle -ne 0 -and $p.Responding -eq $false)

        # Trigger 2: Suspended / Frozen (PsSuspend)
        $suspendFreeze = $false
        $threadSummary = $null

        if (-not $uiHang -and $cpuDelta -lt $CpuDeltaThreshold) {
            $threadSummary = Get-ThreadSummary -Pid $p.Id
            if ($threadSummary -and $threadSummary.WaitingPercent -ge $WaitingThreadPercent) {
                $suspendFreeze = $true
            }
        }

        if ($uiHang -or $suspendFreeze) {
            Write-Log "TRIGGER Name=$($p.Name) PID=$($p.Id) CPUΔ=$cpuDelta UIHang=$uiHang SuspFreeze=$suspendFreeze"
            if ($threadSummary) {
                Write-Log "THREADS Total=$($threadSummary.TotalThreads) Waiting%=$($threadSummary.WaitingPercent)"
            }

            try {
                $LastCapture[$p.Id] = Get-Date
                $dump = Capture-Dump -Pid $p.Id -Name $p.Name
                Analyze-Dump -DumpPath $dump
                Write-Log "CAPTURE COMPLETE $dump"
            } catch {
                Write-Log "ERROR PID=$($p.Id): $($_.Exception.Message)"
            }
        }
    }

    Write-Log "PASS END"
    Start-Sleep $MonitorIntervalSeconds
}