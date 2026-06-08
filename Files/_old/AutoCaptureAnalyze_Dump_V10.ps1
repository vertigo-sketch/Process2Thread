<#
AutoCaptureAnalyze_Dump.ps1
Version: 04

Changes:
- V04: Rewrote monitoring loop to batch-sample all processes (snapshot -> sleep once -> compare),
       fixing O(N * window) scan times. Added suspend/frozen trigger that works for tray/background
       apps (e.g., OneDrive) by combining low CPU delta + high suspended-thread percentage.
       Added per-PID cooldown to avoid repeated captures.
- V03: Added suspended-process trigger (thread-state based).
- V02: Added dump profile support.
- V01: Initial implementation (UI hang based).

Notes:
- Designed for PowerShell 5.1 compatibility.
- Best run in a normal PowerShell console, but works in ISE with this batch model.
#>

[CmdletBinding()]
param(
    # How often a full monitor pass occurs (after the observation window completes)
    [int]$MonitorIntervalSeconds = 5,

    # Time between snapshot A and snapshot B (how long we observe change)
    [int]$ObservationWindowSeconds = 15,

    # If CPU delta is below this threshold (seconds of CPU time) we treat as "no progress"
    [double]$CpuDeltaThreshold = 0.01,

    # Percent of threads that must look "suspended/waiting" to call it a suspend-freeze
    [int]$SuspendedThreadThresholdPercent = 80,

    # Prevent repeated dumps for the same PID within this timespan
    [int]$CaptureCooldownSeconds = 600,

    # Dump profile mapping to ProcDump switches
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile = 'Mini',

    # Tool paths
    [string]$ProcDumpPath = "C:\Tools\procdump.exe",
    [string]$CdbPath      = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",

    # Optional: exclude noisy/system processes by name
    [string[]]$DenyProcessNames = @('Idle','System','Registry','Memory Compression')
)

# -------------------------
# Resolve stable script root (works in ISE)
# -------------------------
$ScriptRoot = $null
if ($PSScriptRoot) {
    $ScriptRoot = $PSScriptRoot
} elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $ScriptRoot = (Get-Location).Path
}

$DumpRoot = Join-Path $ScriptRoot "Dumps"
$LogRoot  = Join-Path $ScriptRoot "Logs"
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

$LogPath = Join-Path $LogRoot "AutoCapture.log"

# -------------------------
# Logging
# -------------------------
function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message)

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts $Message"
    $line | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

Write-Log "=== AutoCapture V04 starting ==="
Write-Log "ScriptRoot=$ScriptRoot"
Write-Log "LogPath=$LogPath"
Write-Log "DumpRoot=$DumpRoot"
Write-Log "ProcDumpPath=$ProcDumpPath"
Write-Log "CdbPath=$CdbPath"
Write-Log "ObservationWindowSeconds=$ObservationWindowSeconds MonitorIntervalSeconds=$MonitorIntervalSeconds"
Write-Log "CpuDeltaThreshold=$CpuDeltaThreshold SuspendedThreadThresholdPercent=$SuspendedThreadThresholdPercent"
Write-Log "CaptureCooldownSeconds=$CaptureCooldownSeconds DumpProfile=$DumpProfile"
Write-Log "DenyProcessNames=$($DenyProcessNames -join ',')"

# -------------------------
# Validate prerequisites
# -------------------------
if (-not (Test-Path $ProcDumpPath)) {
    throw "Missing ProcDump binary at: $ProcDumpPath"
}
if (-not (Test-Path $CdbPath)) {
    throw "Missing cdb.exe at: $CdbPath"
}

# -------------------------
# Helpers
# -------------------------
function Get-ProcDumpArgs {
    param([int]$TargetPid, [string]$OutDumpPath, [string]$Profile)

    # ProcDump common switches:
    # -accepteula: accept EULA
    # -mm: minidump
    # -mh: include handle data
    # -ma: full dump
    $profileSwitches = @()
    switch ($Profile) {
        'Mini'            { $profileSwitches = @('-mm') }
        'MiniWithHandles' { $profileSwitches = @('-mm','-mh') }
        'Full'            { $profileSwitches = @('-ma') }
    }

    return @('-accepteula') + $profileSwitches + @($TargetPid, $OutDumpPath)
}

function Get-ThreadStateSummary {
    param([int]$TargetPid)

    # Win32_Thread fields:
    # ThreadState: 5 generally "Waiting"
    # WaitReason varies; suspended/transition reasons can appear depending on OS/tooling.
    # We use a conservative heuristic: many threads in "Waiting" with certain wait reasons.
    $threads = $null
    try {
        $threads = Get-CimInstance Win32_Thread -Filter "ProcessHandle=$TargetPid" -ErrorAction Stop
    } catch {
        return $null
    }

    if (-not $threads -or $threads.Count -eq 0) { return $null }

    $total = $threads.Count

    # Heuristic set: these are commonly observed wait reasons in suspended/frozen states,
    # but can vary; we rely on percent threshold + CPU flatline.
    $suspLike = $threads | Where-Object {
        $_.ThreadState -eq 5 -and $_.WaitReason -in 5, 6, 12, 13
    }

    [PSCustomObject]@{
        TotalThreads     = $total
        SuspendedThreads = $suspLike.Count
        SuspendedPercent = [math]::Round(($suspLike.Count / $total) * 100, 2)
    }
}

function Capture-Dump {
    param(
        [int]$TargetPid,
        [string]$ProcName
    )

    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $dumpPath = Join-Path $DumpRoot ("{0}_{1}_{2}.dmp" -f $ProcName, $TargetPid, $stamp)

    $args = Get-ProcDumpArgs -TargetPid $TargetPid -OutDumpPath $dumpPath -Profile $DumpProfile
    Write-Log "Capturing dump: $dumpPath (ProcDump args: $($args -join ' '))"

    $p = Start-Process -FilePath $ProcDumpPath -ArgumentList $args -PassThru -WindowStyle Hidden
    $ok = $p.WaitForExit(60000)  # 60s
    if (-not $ok) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        Write-Log "WARN: ProcDump timed out for PID=$TargetPid; killed ProcDump PID=$($p.Id)"
        throw "ProcDump timed out creating $dumpPath"
    }

    if (-not (Test-Path $dumpPath)) {
        throw "Dump not created: $dumpPath"
    }

    return $dumpPath
}

function Analyze-Dump {
    param([string]$DumpPath)

    $cdbLog = [System.IO.Path]::ChangeExtension($DumpPath, ".cdb.log")

    # Keep analysis deterministic and force exit with 'q'
    # Add symbol setup to reduce "empty log" cases caused by early exits.
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'
    $args = @(
        '-z', $DumpPath,
        '-c', $cmd,
        '-logo', $cdbLog
    )

    Write-Log "Analyzing dump: $DumpPath -> $cdbLog"
    Write-Log "cdb args: $($args -join ' ')"

    $p = Start-Process -FilePath $CdbPath -ArgumentList $args -PassThru -WindowStyle Hidden
    $ok = $p.WaitForExit(180000) # 180s
    if (-not $ok) {
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        Write-Log "WARN: cdb timed out; killed cdb PID=$($p.Id) for dump $DumpPath"
        return $cdbLog
    }

    return $cdbLog
}

function Is-DeniedName {
    param([string]$Name, [string[]]$DenyList)
    if (-not $DenyList -or $DenyList.Count -eq 0) { return $false }
    return $DenyList -contains $Name
}

# PID cooldown tracking
$LastCaptureByPid = @{}  # pid -> DateTime

function In-Cooldown {
    param([int]$TargetPid)

    if ($LastCaptureByPid.ContainsKey($TargetPid)) {
        $elapsed = (Get-Date) - $LastCaptureByPid[$TargetPid]
        return ($elapsed.TotalSeconds -lt $CaptureCooldownSeconds)
    }
    return $false
}

function Mark-Captured {
    param([int]$TargetPid)
    $LastCaptureByPid[$TargetPid] = Get-Date
}

# -------------------------
# Main monitoring loop
# -------------------------
Write-Log "Monitoring all processes (minus deny list) for UI hangs or suspend-freeze..."

while ($true) {
    $passStart = Get-Date
    Write-Log ("PASS START: {0}" -f $passStart.ToString("yyyy-MM-dd HH:mm:ss"))

    # Snapshot A: minimal fields for speed
    $snapA = @{}
    $procsA = @()

    try {
        $procsA = Get-Process -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Get-Process failed: $($_.Exception.Message)"
        Start-Sleep -Seconds $MonitorIntervalSeconds
        continue
    }

    foreach ($p in $procsA) {
        if (Is-DeniedName -Name $p.Name -DenyList $DenyProcessNames) { continue }
        if ($p.Id -le 0) { continue }

        $snapA[$p.Id] = [PSCustomObject]@{
            Name            = $p.Name
            CPU             = [double]$p.CPU
            MainWindowHandle= [int64]$p.MainWindowHandle
            Responding      = $null
        }

        # Responding property exists for many GUI processes; may throw in some contexts
        try { $snapA[$p.Id].Responding = [bool]$p.Responding } catch { $snapA[$p.Id].Responding = $null }
    }

    Start-Sleep -Seconds $ObservationWindowSeconds

    # Snapshot B
    $procsB = @()
    try {
        $procsB = Get-Process -ErrorAction Stop
    } catch {
        Write-Log "ERROR: Get-Process (snapshot B) failed: $($_.Exception.Message)"
        Start-Sleep -Seconds $MonitorIntervalSeconds
        continue
    }

    foreach ($p2 in $procsB) {
        if (-not $snapA.ContainsKey($p2.Id)) { continue }          # only compare processes that existed in A
        if (Is-DeniedName -Name $p2.Name -DenyList $DenyProcessNames) { continue }
        if (In-Cooldown -TargetPid $p2.Id) { continue }

        $a = $snapA[$p2.Id]
        $cpuB = [double]$p2.CPU
        $cpuDelta = $cpuB - [double]$a.CPU

        $mainHandleB = [int64]$p2.MainWindowHandle
        $respondingB = $null
        try { $respondingB = [bool]$p2.Responding } catch { $respondingB = $null }

        # Trigger 1: UI hang (best-effort)
        $uiHang = $false
        if ($mainHandleB -ne 0 -and $respondingB -ne $null) {
            $uiHang = (-not $respondingB)
        }

        # Candidate for Trigger 2: suspend-freeze heuristic
        $suspendFreeze = $false
        $threadSummary = $null

        if (-not $uiHang -and $cpuDelta -lt $CpuDeltaThreshold) {
            $threadSummary = Get-ThreadStateSummary -TargetPid $p2.Id
            if ($threadSummary -and $threadSummary.SuspendedPercent -ge $SuspendedThreadThresholdPercent) {
                $suspendFreeze = $true
            }
        }

        if ($uiHang -or $suspendFreeze) {
            $triggerType = $(if ($uiHang) { "UIHang" } else { "SuspendedFreeze" })

            Write-Log ("TRIGGER: {0} Name={1} PID={2} CPUΔ={3} MainHwnd={4} Responding={5}" -f `
                $triggerType, $a.Name, $p2.Id, ([math]::Round($cpuDelta,4)), $mainHandleB, $respondingB)

            if ($threadSummary) {
                Write-Log ("THREADS: Total={0} SuspLike={1} Susp%={2}" -f `
                    $threadSummary.TotalThreads, $threadSummary.SuspendedThreads, $threadSummary.SuspendedPercent)
            }

            try {
                Mark-Captured -TargetPid $p2.Id
                $dumpPath = Capture-Dump -TargetPid $p2.Id -ProcName $a.Name
                $cdbLog = Analyze-Dump -DumpPath $dumpPath
                Write-Log "DONE: Dump=$dumpPath AnalysisLog=$cdbLog"
            } catch {
                Write-Log ("ERROR: Capture/Analyze failed for Name={0} PID={1}: {2}" -f $a.Name, $p2.Id, $_.Exception.Message)
            }
        }
    }

    $passEnd = Get-Date
    $dur = [math]::Round(($passEnd - $passStart).TotalSeconds, 1)
    Write-Log ("PASS END: {0} (duration {1}s)" -f $passEnd.ToString("yyyy-MM-dd HH:mm:ss"), $dur)

    Start-Sleep -Seconds $MonitorIntervalSeconds
}
