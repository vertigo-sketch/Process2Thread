<#
AutoCaptureAnalyze_Dump.ps1
Version: 03

Changes:
- V03: Added suspended-process trigger (thread-state–based) to detect frozen
       background/tray apps (e.g., OneDrive with PsSuspend).
- V02: Added dump profile support.
- V01: Initial implementation (UI hang based).

Requirements:
- PowerShell 5.1
- Sysinternals ProcDump
- Sysinternals PsSuspend (for testing)
- Windows Debugging Tools (cdb.exe)
#>

# =========================
# CONFIGURATION
# =========================

$passStart = Get-Date
Write-Log "PASS START: $passStart"
# ... existing scanning logic ...
Write-Log ("PASS END: {0} (duration: {1}s)" -f (Get-Date), [math]::Round(((Get-Date) - $passStart).TotalSeconds, 1))


$MonitorIntervalSeconds = 5
$ObservationWindowSeconds = 15

$CpuDeltaThreshold = 0.01
$SuspendedThreadThresholdPercent = 80

$DumpRoot = "$PSScriptRoot\Dumps"
$LogRoot  = "$PSScriptRoot\Logs"
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

$ProcDumpPath = "C:\Tools\procdump.exe"
$CdbPath      = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

# =========================
# UTILITIES
# =========================

function Get-CpuSnapshot {
    param($Process)
    return [double]$Process.CPU
}

function Get-ThreadStateSummary {
    param([int]$Pid)

    $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$Pid" -ErrorAction SilentlyContinue
    if (-not $threads) { return $null }

    $total = $threads.Count
    if ($total -eq 0) { return $null }

    $suspended = $threads | Where-Object {
        $_.ThreadState -eq 5 -and $_.WaitReason -in 5, 6, 12, 13
    }

    return [PSCustomObject]@{
        TotalThreads     = $total
        SuspendedThreads = $suspended.Count
        SuspendedPercent = [math]::Round(($suspended.Count / $total) * 100, 2)
    }
}

function Write-Log {
    param($Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Message" | Tee-Object -FilePath "$LogRoot\AutoCapture.log" -Append
}

# =========================
# HANG / SUSPEND DETECTION
# =========================

function Test-UiHang {
    param($Process)
    if ($Process.MainWindowHandle -eq 0) { return $false }
    return (-not $Process.Responding)
}

function Test-SuspendedFreeze {
    param(
        $Process,
        [double]$CpuBefore,
        [double]$CpuAfter,
        $ThreadSummary
    )

    if (-not $ThreadSummary) { return $false }

    $cpuDelta = $CpuAfter - $CpuBefore

    return (
        $cpuDelta -lt $CpuDeltaThreshold -and
        $ThreadSummary.SuspendedPercent -ge $SuspendedThreadThresholdPercent
    )
}

# =========================
# DUMP + ANALYSIS
# =========================

function Capture-Dump {
    param($Process)

    $dumpPath = Join-Path $DumpRoot "$($Process.Name)_$($Process.Id)_$(Get-Date -Format yyyyMMdd_HHmmss).dmp"

    Write-Log "Capturing dump: $dumpPath"
    & $ProcDumpPath -accepteula -ma $Process.Id $dumpPath | Out-Null

    return $dumpPath
}

function Analyze-Dump {
    param($DumpPath)

    $logPath = [System.IO.Path]::ChangeExtension($DumpPath, ".cdb.log")

    Write-Log "Analyzing dump with cdb"

    & $CdbPath `
        -z $DumpPath `
        -c "!analyze -hang; ~* kb; q" `
        -logo $logPath | Out-Null
}

# =========================
# MAIN MONITOR LOOP
# =========================

Write-Log "AutoCapture started. Monitoring for hung or suspended processes..."

while ($true) {

    Get-Process | ForEach-Object {

        $p = $_

        try {

            $cpuStart = Get-CpuSnapshot -Process $p
            Start-Sleep -Seconds $ObservationWindowSeconds
            $cpuEnd = (Get-Process -Id $p.Id -ErrorAction Stop).CPU

            $threadSummary = Get-ThreadStateSummary -Pid $p.Id

            $uiHang = Test-UiHang -Process $p
            $suspendFreeze = Test-SuspendedFreeze `
                                -Process $p `
                                -CpuBefore $cpuStart `
                                -CpuAfter $cpuEnd `
                                -ThreadSummary $threadSummary

            if ($uiHang -or $suspendFreeze) {

                Write-Log "Trigger detected for $($p.Name) PID=$($p.Id)"
                Write-Log ("UIHang={0} SuspendedFreeze={1} CPUΔ={2} SuspendedThreads={3}%" -f `
                            $uiHang,
                            $suspendFreeze,
                            [math]::Round($cpuEnd - $cpuStart, 4),
                            $threadSummary.SuspendedPercent)

                $dump = Capture-Dump -Process $p
                Analyze-Dump -DumpPath $dump
            }

        } catch {
            # Process exited or access denied — ignore
        }
    }

    Start-Sleep -Seconds $MonitorIntervalSeconds
}
