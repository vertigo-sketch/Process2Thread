<#
AutoCaptureAnalyze_Dump.ps1
Version: 15

Change History:
- V15 (2026-03-25)
  * Suppressed noisy "normally suspended" Windows shell/UWP processes (e.g., LockApp)
  * Added DefaultDeny list (can be disabled) + SystemApps path exclusion for TrueSuspend candidates
  * Kept: batch sampling, defensive property access, TrueSuspend detection via .NET Thread WaitReason=Suspended
  * Still avoids $PID/$Pid collisions (uses ProcId/TargetProcId)

- V14
  * TrueSuspend trigger based on .NET ProcessThread.WaitReason == Suspended (reduced false positives)

Purpose:
- Monitor all processes
- Trigger dump + cdb analysis on:
    1) UI hang (windowed process with Responding=false)
    2) True suspension (PsSuspend/SuspendThread): high % threads with WaitReason=Suspended and CPU flatline
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds   = 5,

    # CPU time delta (seconds) across the observation window
    [double]$CpuDeltaThreshold     = 0.01,

    # TrueSuspend trigger: percent of threads whose WaitReason == Suspended
    [int]$SuspendedThreadPercent   = 80,

    # Cooldown per process ID (seconds)
    [int]$CooldownSeconds          = 600,

    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile           = 'Mini',

    # Optional: additional deny list (names). Default deny list is enabled unless -DisableDefaultDenyList is used.
    [string[]]$DenyProcessNames    = @(),

    # Disable built-in deny list (not recommended)
    [switch]$DisableDefaultDenyList
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
# Tool paths (edit if needed)
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

# Always log fatal errors instead of silently dying
trap {
    Write-Log ("FATAL: {0}" -f $_.Exception.Message)
    Write-Log ("FATAL: {0}" -f $_.ScriptStackTrace)
    break
}

# ==============================
# Default deny list (noise reducers)
# ==============================
$DefaultDeny = @(
    # Lock screen / shell UWP hosts frequently suspended by design
    'LockApp',
    'ShellExperienceHost',
    'StartMenuExperienceHost',
    'SearchHost',
    'TextInputHost',
    'RuntimeBroker',
    'ApplicationFrameHost',

    # Optional common background hosts that can be noisy (tune as desired)
    'backgroundTaskHost',
    'dllhost'
)

function Is-DeniedName {
    param([string]$Name)

    if (-not $Name) { return $true }

    if (-not $DisableDefaultDenyList) {
        if ($DefaultDeny -contains $Name) { return $true }
    }

    if ($DenyProcessNames -and $DenyProcessNames.Count -gt 0) {
        if ($DenyProcessNames -contains $Name) { return $true }
    }

    return $false
}

# ==============================
# Safe process snapshot
# ==============================
function Get-SafeProcSnapshot {
    param([System.Diagnostics.Process]$Proc)

    $procId = $null
    $procName = $null
    try { $procId = [int]$Proc.Id } catch { return $null }
    try { $procName = [string]$Proc.Name } catch { $procName = "Unknown" }

    if (Is-DeniedName -Name $procName) { return $null }

    $cpu = 0.0
    $mwh = 0
    $resp = $null

    try { $cpu = [double]$Proc.CPU } catch { $cpu = 0.0 }
    try { $mwh = [int64]$Proc.MainWindowHandle } catch { $mwh = 0 }

    # Only query Responding if it has a window handle
    if ($mwh -ne 0) {
        try { $resp = [bool]$Proc.Responding } catch { $resp = $null }
    }

    [PSCustomObject]@{
        ProcId           = $procId
        Name             = $procName
        CPU              = $cpu
        MainWindowHandle = $mwh
        Responding       = $resp
    }
}

# ==============================
# SystemApps path exclusion (only used for TrueSuspend candidates)
# ==============================
function Get-ExecutablePathSafe {
    param([int]$TargetProcId)

    # Win32_Process can fail on some protected processes; keep it best-effort.
    try {
        $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$TargetProcId" -ErrorAction Stop
        return [string]$wp.ExecutablePath
    } catch {
        return $null
    }
}

function Is-SystemAppPath {
    param([string]$ExePath)

    if (-not $ExePath) { return $false }

    $p = $ExePath.ToLowerInvariant()

    # Common Windows packaged app locations
    if ($p -like "*\windows\systemapps\*") { return $true }
    if ($p -like "*\program files\windowsapps\*") { return $true }

    return $false
}

# ==============================
# TrueSuspend thread summary (PsSuspend/SuspendThread)
# ==============================
function Get-SuspendedThreadSummary {
    param([int]$TargetProcId)

    $procObj = $null
    try { $procObj = Get-Process -Id $TargetProcId -ErrorAction Stop } catch { return $null }

    $threads = $null
    try { $threads = $procObj.Threads } catch { return $null }
    if (-not $threads -or $threads.Count -le 0) { return $null }

    $total = $threads.Count
    $suspCount = 0

    foreach ($t in $threads) {
        try {
            if ($t.ThreadState.ToString() -eq 'Wait') {
                if ($t.WaitReason.ToString() -eq 'Suspended') {
                    $suspCount++
                }
            }
        } catch {
            # ignore thread-level failures
        }
    }

    [PSCustomObject]@{
        TotalThreads     = $total
        SuspendedThreads = $suspCount
        SuspendedPercent = [math]::Round(($suspCount / $total) * 100, 2)
    }
}

# ==============================
# Dump + Analyze
# ==============================
function Capture-Dump {
    param([int]$TargetProcId, [string]$ProcName)

    $stamp    = Get-Date -Format yyyyMMdd_HHmmss
    $dumpPath = Join-Path $DumpRoot ("{0}_{1}_{2}.dmp" -f $ProcName, $TargetProcId, $stamp)

    $switch = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    Write-Log "Dumping Name=$ProcName ProcId=$TargetProcId Profile=$DumpProfile Path=$dumpPath"

    $pDump = Start-Process -FilePath $ProcDumpPath `
        -ArgumentList "-accepteula $switch $TargetProcId `"$dumpPath`"" `
        -WindowStyle Hidden -PassThru

    $ok = $pDump.WaitForExit(60000)
    if (-not $ok) {
        try { Stop-Process -Id $pDump.Id -Force -ErrorAction SilentlyContinue } catch {}
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

    $pCdb = Start-Process -FilePath $CdbPath `
        -ArgumentList "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" `
        -WindowStyle Hidden -PassThru

    $ok = $pCdb.WaitForExit(180000)
    if (-not $ok) {
        try { Stop-Process -Id $pCdb.Id -Force -ErrorAction SilentlyContinue } catch {}
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
# Start
# ==============================
Write-Log "=== AutoCapture V15 START ==="
Write-Log "ScriptRoot=$ScriptRoot"
Write-Log "ObservationWindowSeconds=$ObservationWindowSeconds MonitorIntervalSeconds=$MonitorIntervalSeconds"
Write-Log "CpuDeltaThreshold=$CpuDeltaThreshold SuspendedThreadPercent=$SuspendedThreadPercent CooldownSeconds=$CooldownSeconds DumpProfile=$DumpProfile"
Write-Log ("DefaultDenyEnabled={0} DefaultDeny={1}" -f (-not $DisableDefaultDenyList), ($DefaultDeny -join ','))
Write-Log ("UserDeny={0}" -f ($DenyProcessNames -join ','))

# ==============================
# Main loop (batched)
# ==============================
while ($true) {
    $passStart = Get-Date
    Write-Log ("PASS START {0}" -f $passStart.ToString("HH:mm:ss"))

    # Snapshot A
    $snapA = @{}
    $procsA = @()
    try { $procsA = Get-Process -ErrorAction Stop } catch {
        Write-Log "ERROR: Get-Process(A) failed: $($_.Exception.Message)"
        Start-Sleep -Seconds $MonitorIntervalSeconds
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
        Start-Sleep -Seconds $MonitorIntervalSeconds
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

        # Trigger 2: TrueSuspend (PsSuspend) with SystemApps suppression
        $trueSuspend = $false
        $threadSummary = $null

        if (-not $uiHang -and $cpuDelta -lt $CpuDeltaThreshold) {
            $threadSummary = Get-SuspendedThreadSummary -TargetProcId $b.ProcId

            if ($threadSummary -and
                $threadSummary.SuspendedThreads -gt 0 -and
                $threadSummary.SuspendedPercent -ge $SuspendedThreadPercent) {

                # Exclude Windows SystemApps/WindowsApps because many are suspended by design
                $exe = Get-ExecutablePathSafe -TargetProcId $b.ProcId
                if (Is-SystemAppPath -ExePath $exe) {
                    Write-Log ("SKIP SystemApp TrueSuspend Name={0} ProcId={1} Path={2}" -f $b.Name, $b.ProcId, $exe)
                } else {
                    $trueSuspend = $true
                }
            }
        }

        if ($uiHang -or $trueSuspend) {
            Write-Log ("TRIGGER Name={0} ProcId={1} CPUΔ={2} UIHang={3} TrueSuspend={4} MWH={5} Resp={6}" -f `
                $b.Name, $b.ProcId, ([math]::Round($cpuDelta,4)), $uiHang, $trueSuspend, $b.MainWindowHandle, $b.Responding)

            if ($threadSummary) {
                Write-Log ("THREADS Total={0} Suspended={1} Suspended%={2}" -f `
                    $threadSummary.TotalThreads, $threadSummary.SuspendedThreads, $threadSummary.SuspendedPercent)
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